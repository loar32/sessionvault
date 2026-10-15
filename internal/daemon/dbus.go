//go:build linux

package daemon

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Шина сеанса в песочнице — через xdg-dbus-proxy от имени владельца, с фильтром. Приложению доступны уведомления,
// значок в трее (StatusNotifierItem), медиаклавиши (MPRIS), связка ключей (там ключ шифрования паролей и кук браузера;
// без данных из песочницы он бесполезен, а данные она не отдаёт) и из порталов — только показ экрана, настройки
// оформления и запрет сна. Выбора файлов через портал нет намеренно: он вернул бы пути из настоящего дома, которых в
// песочнице нет, и приложение открывает свой диалог внутри песочницы. Остальные имена на шине для приложения не существуют.

const dbusProxyPath = "/usr/bin/xdg-dbus-proxy"

type busProxy struct {
	cmd  *exec.Cmd
	path string   // сокет прокси в каталоге службы
	sync *os.File // закрытие этого конца канала останавливает прокси
}

// trayPID — pid главного процесса приложения в его пространстве PID (см. SandboxInit): имя значка в трее содержит pid,
// и у двух приложений с одинаковым pid значки бы не ужились.
func trayPID(uid int) int { return 50 + 16*((1000-uid%1000)%32) }

func proxyRules(pid int, desktopIDs []string) []string {
	const portal = "org.freedesktop.portal.Desktop"
	r := []string{"--filter",
		"--talk=org.freedesktop.Notifications",
		"--talk=org.kde.StatusNotifierWatcher",
		"--talk=org.freedesktop.secrets",
		"--own=org.mpris.MediaPlayer2.*",
		"--call=" + portal + "=org.freedesktop.portal.ScreenCast.*@/org/freedesktop/portal/desktop",
		"--call=" + portal + "=org.freedesktop.portal.Settings.*@/org/freedesktop/portal/desktop",
		"--call=" + portal + "=org.freedesktop.portal.Inhibit.*@/org/freedesktop/portal/desktop",
		"--call=" + portal + "=org.freedesktop.portal.Request.*@/org/freedesktop/portal/desktop/request/*",
		"--call=" + portal + "=org.freedesktop.portal.Session.*@/org/freedesktop/portal/desktop/session/*",
		"--broadcast=" + portal + "=org.freedesktop.portal.Request.Response@/org/freedesktop/portal/desktop/request/*",
		"--broadcast=" + portal + "=org.freedesktop.portal.Session.Closed@/org/freedesktop/portal/desktop/session/*",
		"--broadcast=" + portal + "=org.freedesktop.portal.Settings.SettingChanged@/org/freedesktop/portal/desktop",
	}
	for p := pid; p < pid+4; p++ {
		for n := 1; n <= 3; n++ {
			r = append(r, fmt.Sprintf("--own=org.kde.StatusNotifierItem-%d-%d", p, n))
		}
	}
	// Имя приложения по его ярлыку (org.telegram.desktop): под ним оно регистрирует себя на шине.
	for _, id := range desktopIDs {
		id = strings.TrimSuffix(id, ".desktop")
		if strings.Count(id, ".") >= 2 {
			r = append(r, "--own="+id, "--own="+id+".*")
		}
	}
	return r
}

// startBus запускает прокси для приложения. Нет прокси или шины владельца — приложение работает без шины (nil).
func startBus(cfg Config, a App, acc account) (*busProxy, error) {
	bus := filepath.Join("/run/user", strconv.Itoa(cfg.Owner), "bus")
	if _, err := os.Stat(dbusProxyPath); err != nil {
		return nil, nil
	}
	if _, err := os.Stat(bus); err != nil {
		return nil, nil
	}
	cred, err := ownerCred(cfg)
	if err != nil {
		return nil, err
	}
	// Сокет прокси появляется в каталоге владельца: прокси работает от его имени. Каталог закрыт для остальных.
	dir := filepath.Join(RunDir, "bus", a.Name)
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(filepath.Dir(dir), 0o711); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chown(dir, cfg.Owner, int(cred.Gid)); err != nil {
		return nil, err
	}
	sockPath := filepath.Join(dir, "bus")
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(dbusProxyPath, append([]string{"--fd=3", "unix:path=" + bus, sockPath}, proxyRules(trayPID(acc.uid), a.Desktop)...)...)
	cmd.ExtraFiles = []*os.File{w}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred, Setsid: true, Pdeathsig: syscall.SIGKILL}
	cmd.Env = []string{"HOME=" + cfg.OwnerHome, "XDG_RUNTIME_DIR=" + filepath.Dir(bus)}
	cmd.Dir = "/"
	if err := cmd.Start(); err != nil {
		_ = r.Close()
		_ = w.Close()
		return nil, err
	}
	_ = w.Close()
	p := &busProxy{cmd: cmd, sync: r}
	ready := make(chan error, 1)
	go func() {
		b := make([]byte, 1)
		_, err := r.Read(b)
		ready <- err
	}()
	select {
	case err = <-ready:
	case <-time.After(5 * time.Second):
		err = errors.New("xdg-dbus-proxy не ответил")
	}
	// Прокси создал сокет в каталоге владельца; служба переносит его в свой каталог (прослушивание держится за сам
	// сокет, не за имя) и уже там проверяет: подменить файл в каталоге root владелец не может.
	p.path = filepath.Join(RunDir, "bus", a.Name+".sock")
	_ = os.Remove(p.path)
	if err == nil {
		err = os.Rename(sockPath, p.path)
	}
	if err == nil {
		err = verifyProxySocket(p.path, cfg.Owner, cmd.Process.Pid, acc.uid)
	}
	if err != nil {
		p.stop()
		return nil, err
	}
	return p, nil
}

// verifyProxySocket проверяет, что сокет слушает именно запущенный прокси (процесс владельца мог подложить в его каталог
// свой «сервер шины»), и выдаёт учётке приложения запись в сокет.
func verifyProxySocket(path string, owner, pid, uid int) error {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || int(st.Uid) != owner {
		return errors.New("сокет прокси шины подменён")
	}
	c, err := net.Dial("unix", "/proc/self/fd/"+strconv.Itoa(fd))
	if err != nil {
		return err
	}
	cred, err := peerCred(c.(*net.UnixConn))
	_ = c.Close()
	if err != nil || int(cred.Pid) != pid {
		return errors.New("сокет шины слушает не прокси SessionVault")
	}
	return aclFD(f, "-m", "u:"+strconv.Itoa(uid)+":rw")
}

func (p *busProxy) stop() {
	if p == nil {
		return
	}
	_ = p.sync.Close()
	_ = p.cmd.Process.Kill()
	_ = p.cmd.Wait()
	if p.path != "" {
		_ = os.Remove(p.path)
	}
}
