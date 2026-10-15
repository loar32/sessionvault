//go:build linux

package daemon

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/loar32/sessionvault/internal/i18n"
	"golang.org/x/sys/unix"
)

const bwrapPath = "/usr/bin/bwrap"

// session — графический сеанс владельца, в котором открывается приложение.
type session struct {
	runtime string // /run/user/<uid владельца>
	wayland string // имя сокета Wayland в runtime
	lang    string
	desktop string
	cursor  string
	cursorN string
	server  int // pid композитора: его выход значит, что сеанс закончился
}

var (
	waylandName = regexp.MustCompile(`^wayland-[0-9]{1,3}$`)
	envValue    = regexp.MustCompile(`^[A-Za-z0-9_.:@+-]{1,64}$`)
)

// Композиторы, которым служба доверяет окна приложений: сокет Wayland в каталоге владельца может создать любой его процесс,
// а приложение, подключённое к чужому «композитору», показало бы ему всё содержимое окон.
var compositors = map[string]bool{
	"Hyprland": true, "hyprland": true, "sway": true, "river": true, "niri": true, "labwc": true, "wayfire": true,
	"kwin_wayland": true, "gnome-shell": true, "cosmic-comp": true, "weston": true, "Xwayland": false,
}

// findSession берёт сеанс из окружения процесса, который попросил запуск (его uid уже проверен), и проверяет сокет.
func findSession(owner, pid int) (session, error) {
	s := session{runtime: "/run/user/" + strconv.Itoa(owner)}
	env := processEnv(pid)
	if v := env["WAYLAND_DISPLAY"]; waylandName.MatchString(v) {
		s.wayland = v
	} else {
		matches, _ := filepath.Glob(filepath.Join(s.runtime, "wayland-[0-9]*"))
		for _, m := range matches {
			if !strings.HasSuffix(m, ".lock") {
				s.wayland = filepath.Base(m)
				break
			}
		}
	}
	if s.wayland == "" {
		return s, errors.New(i18n.T("не найден сеанс Wayland владельца"))
	}
	for k, dst := range map[string]*string{"LANG": &s.lang, "XDG_CURRENT_DESKTOP": &s.desktop, "XCURSOR_THEME": &s.cursor, "XCURSOR_SIZE": &s.cursorN} {
		if v := env[k]; envValue.MatchString(v) {
			*dst = v
		}
	}
	server, err := compositorPID(filepath.Join(s.runtime, s.wayland), owner)
	if err != nil {
		return s, err
	}
	s.server = server
	return s, nil
}

func processEnv(pid int) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "environ"))
	if err != nil || len(b) > 1<<20 {
		return out
	}
	for _, kv := range bytes.Split(b, []byte{0}) {
		if k, v, ok := strings.Cut(string(kv), "="); ok {
			out[k] = v
		}
	}
	return out
}

// compositorPID подключается к сокету и узнаёт, кто его слушает: это должен быть известный композитор владельца из /usr.
func compositorPID(sock string, owner int) (int, error) {
	fi, err := os.Lstat(sock)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		return 0, errors.New(i18n.T("сокет Wayland не найден"))
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != owner {
		return 0, errors.New(i18n.T("сокет Wayland принадлежит не владельцу"))
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		return 0, err
	}
	defer func() { _ = c.Close() }()
	raw, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) { cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	exe, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(int(cred.Pid)), "exe"))
	if err != nil || int(cred.Uid) != owner || !strings.HasPrefix(exe, "/usr/") || !compositors[filepath.Base(exe)] {
		return 0, fmt.Errorf(i18n.T("сокет Wayland слушает не композитор (%s)"), exe)
	}
	return int(cred.Pid), nil
}

// grant открывает учётке приложения ровно то, что нужно окну и звуку: проход через каталог сеанса и запись в сокет
// Wayland (PipeWire и Pulse и так открыты всем, закрыт только каталог). Читать файлы каталога она не может.
// Маска задаётся явно: chmod каталога (PipeWire делает его на своём каталоге) обнуляет маску, и выданное право перестаёт
// действовать; поэтому выдача повторяется и перед запуском второго экземпляра.
func (s session) grant(uid int) error {
	u := "u:" + strconv.Itoa(uid)
	if err := s.acl(s.runtime, unix.S_IFDIR, "-m", u+":x,m::x"); err != nil {
		return err
	}
	if err := s.acl(filepath.Join(s.runtime, s.wayland), unix.S_IFSOCK, "-m", u+":rw,m::rw"); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(s.runtime, "pulse")); err == nil {
		_ = s.acl(filepath.Join(s.runtime, "pulse"), unix.S_IFDIR, "-m", u+":x,m::x")
	}
	return nil
}

func (s session) revoke(uid int) {
	u := "u:" + strconv.Itoa(uid)
	_ = s.acl(filepath.Join(s.runtime, s.wayland), unix.S_IFSOCK, "-x", u)
	_ = s.acl(filepath.Join(s.runtime, "pulse"), unix.S_IFDIR, "-x", u)
	_ = s.acl(s.runtime, unix.S_IFDIR, "-x", u)
}

// acl меняет ACL объекта в каталоге сеанса владельца. Путь там подменяет любой его процесс, а setfacl идёт по ссылкам:
// подменённый сокет выдал бы учётке приложения права на системный файл. Поэтому объект открывается без перехода по
// ссылкам, проверяются тип и владелец, а setfacl получает уже открытый дескриптор (/proc/self/fd/3).
func (s session) acl(path string, kind uint32, args ...string) error {
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
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	owner := strings.TrimPrefix(s.runtime, "/run/user/")
	if st.Mode&unix.S_IFMT != kind || strconv.Itoa(int(st.Uid)) != owner {
		return fmt.Errorf(i18n.T("%s подменён: не тот тип или владелец"), path)
	}
	cmd := exec.Command("setfacl", append(args, "/proc/self/fd/3")...)
	cmd.ExtraFiles = []*os.File{f}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("setfacl %s %s: %v: %s", strings.Join(args, " "), path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func setfacl(args ...string) error {
	out, err := exec.Command("setfacl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("setfacl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// bwrapArgs — песочница приложения: система только для чтения, свой /tmp и /run, вместо домашнего каталога владельца —
// расшифрованный дом приложения, вместо «Загрузок» — общая папка обмена. Своё пространство PID: приложение не видит чужих
// процессов, а выход bwrap гасит всё внутри. Сеть общая.
func bwrapArgs(app App, acc account, s session, ownerHome string, argv []string) []string {
	run := "/run/user/" + strconv.Itoa(acc.uid)
	appDir := AppDir(app.Name)
	a := []string{
		"--unshare-pid", "--unshare-ipc", "--unshare-cgroup-try",
		"--die-with-parent", "--new-session",
		"--ro-bind", "/usr", "/usr",
		"--symlink", "usr/bin", "/bin", "--symlink", "usr/bin", "/sbin",
		"--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64",
		"--ro-bind", "/etc", "/etc",
		"--ro-bind-try", "/opt", "/opt",
		"--ro-bind", "/sys", "/sys",
		"--proc", "/proc",
		"--dev", "/dev", "--tmpfs", "/dev/shm",
		"--dev-bind-try", "/dev/dri", "/dev/dri",
		"--tmpfs", "/var", "--dir", "/var/tmp",
		"--ro-bind-try", "/var/cache/fontconfig", "/var/cache/fontconfig",
		"--tmpfs", "/run",
		"--ro-bind-try", "/run/systemd/resolve", "/run/systemd/resolve",
		"--perms", "0700", "--dir", run,
		"--bind", filepath.Join(s.runtime, s.wayland), filepath.Join(run, s.wayland),
		"--bind-try", filepath.Join(s.runtime, "pipewire-0"), filepath.Join(run, "pipewire-0"),
		"--bind-try", filepath.Join(s.runtime, "pulse", "native"), filepath.Join(run, "pulse", "native"),
		"--bind", filepath.Join(appDir, homeName), ownerHome,
		"--bind", filepath.Join(appDir, "tmp"), "/tmp",
		"--bind", ExchangeDir(), filepath.Join(ownerHome, "Downloads"),
		"--chdir", ownerHome,
		"--",
	}
	return append(a, argv...)
}

func sandboxEnv(app App, acc account, s session, ownerHome string) []string {
	run := "/run/user/" + strconv.Itoa(acc.uid)
	env := []string{
		"HOME=" + ownerHome,
		"USER=" + AccountName(app.Name),
		"LOGNAME=" + AccountName(app.Name),
		"PATH=/usr/local/bin:/usr/bin",
		"XDG_RUNTIME_DIR=" + run,
		"WAYLAND_DISPLAY=" + s.wayland,
		"XDG_SESSION_TYPE=wayland",
		"PULSE_SERVER=unix:" + filepath.Join(run, "pulse", "native"),
		"ELECTRON_OZONE_PLATFORM_HINT=wayland",
		"QT_QPA_PLATFORM=wayland",
		"GDK_BACKEND=wayland",
		"XDG_DOWNLOAD_DIR=" + filepath.Join(ownerHome, "Downloads"),
	}
	if s.lang != "" {
		env = append(env, "LANG="+s.lang)
	}
	if s.desktop != "" {
		env = append(env, "XDG_CURRENT_DESKTOP="+s.desktop)
	}
	if s.cursor != "" {
		env = append(env, "XCURSOR_THEME="+s.cursor)
	}
	if s.cursorN != "" {
		env = append(env, "XCURSOR_SIZE="+s.cursorN)
	}
	return env
}

var (
	safeFlag    = regexp.MustCompile(`^--(ozone-platform|ozone-platform-hint|wayland-text-input-version|force-device-scale-factor)=[A-Za-z0-9_.]{1,32}$`)
	featureFlag = regexp.MustCompile(`^--(enable|disable)-features=[A-Za-z0-9_,:]{1,512}$`)
	extPath     = regexp.MustCompile(`^/usr/share/[A-Za-z0-9_./-]{1,200}$`)
)

// browserFlags — флаги из файла флагов браузера владельца, но только безопасные: файл пишет любой процесс его учётки,
// а флаг вроде --remote-debugging-port отдал бы ему управление защищённым браузером.
func browserFlags(app App, owner int, ownerHome string) []string {
	if app.Flags == "" {
		return nil
	}
	b, err := readOwnerFile(ownerHome, filepath.Join(".config", app.Flags), owner, 16<<10)
	if err != nil {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		for _, f := range strings.Fields(line) {
			switch {
			case safeFlag.MatchString(f), featureFlag.MatchString(f), f == "--enable-wayland-ime":
				out = append(out, f)
			case strings.HasPrefix(f, "--load-extension="):
				if ext := safeExtensions(strings.TrimPrefix(f, "--load-extension=")); ext != "" {
					out = append(out, "--load-extension="+ext)
				}
			}
		}
	}
	return out
}

func safeExtensions(list string) string {
	var ok []string
	for _, p := range strings.Split(list, ",") {
		if extPath.MatchString(p) && !strings.Contains(p, "..") && rootOwned(p) == nil {
			ok = append(ok, p)
		}
	}
	return strings.Join(ok, ",")
}

// readOwnerFile читает файл из домашнего каталога владельца, не проходя по ссылкам: иначе процесс владельца подсунул бы
// службе (root) чужой файл.
func readOwnerFile(home, rel string, owner int, limit int64) ([]byte, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, filepath.Join(home, rel), &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), rel)
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.Mode().IsRegular() || int(st.Uid) != owner || fi.Size() > limit {
		return nil, errors.New(i18n.T("файл владельца не подходит"))
	}
	b := make([]byte, fi.Size())
	_, err = f.ReadAt(b, 0)
	return b, err
}
