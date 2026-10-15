//go:build linux

package daemon

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/loar32/sessionvault/internal/ipc"
)

// Ссылки из песочницы. Внутри неё вместо xdg-open стоит sessionvault: ссылку (или файл из общей папки) он передаёт в
// сокет приложения у службы, а служба открывает её у владельца его же xdg-open. Так http(s) из Telegram уходит в
// защищённый браузер, tg:// из браузера — в защищённый Telegram (через подменённые ярлыки), а не в программу, запущенную
// внутри чужой песочницы.

const (
	sandboxLink  = "/run/sessionvault-link" // сокет внутри песочницы
	sandboxShare = "/run/sessionvault-share"
	linkGap      = 500 * time.Millisecond
)

var schemeRe = regexp.MustCompile(`^[a-z][a-z0-9+.-]{0,31}$`)

// Схемы, которые открывают локальные файлы, программы или сетевые ресурсы у владельца: из песочницы они не принимаются.
var badSchemes = map[string]bool{"file": true, "javascript": true, "data": true, "vbscript": true, "about": true,
	"chrome": true, "ssh": true, "smb": true, "sftp": true, "ftp": true, "steam": true, "x-scheme-handler": true,
	"vnc": true, "rdp": true, "telnet": true, "nfs": true, "dav": true, "davs": true, "afp": true, "trash": true, "computer": true}

func validScheme(s string) bool { return schemeRe.MatchString(s) && !badSchemes[s] }

// linkScheme — схема ссылки; символы проверяются по тем же правилам, что у ipc.ValidURL.
func linkScheme(s string) (string, bool) {
	if len(s) == 0 || len(s) > ipc.MaxURL {
		return "", false
	}
	for _, r := range s {
		if r <= 0x20 || r > 0x7e || r == '"' || r == '\\' || r == '^' || r == '`' {
			return "", false
		}
	}
	scheme, rest, ok := strings.Cut(s, ":")
	scheme = strings.ToLower(scheme)
	if !ok || rest == "" || !schemeRe.MatchString(scheme) {
		return "", false
	}
	return scheme, true
}

// AcceptsLink — приложение открывает эту ссылку само: http(s) у браузера, свои схемы (tg://) у остальных.
func (a App) AcceptsLink(s string) bool {
	if a.Browser && ipc.ValidURL(s) == nil {
		return true
	}
	scheme, ok := linkScheme(s)
	return ok && validScheme(scheme) && slices.Contains(a.Schemes, scheme)
}

// outboundLink — ссылку из песочницы можно открыть у владельца: http(s), почта и схемы защищённых приложений.
func outboundLink(s string) bool {
	if ipc.ValidURL(s) == nil {
		return true
	}
	scheme, ok := linkScheme(s)
	if !ok || !validScheme(scheme) {
		return false
	}
	if scheme == "mailto" {
		return true
	}
	return slices.ContainsFunc(Protected(), func(a App) bool { return slices.Contains(a.Schemes, scheme) })
}

func linkSocket(name string) string { return filepath.Join(RunDir, "links", name+".sock") }

// listenLinks — сокет приложения для ссылок; подключиться к нему может только учётка приложения (и root).
func listenLinks(a App, acc account) (*net.UnixListener, error) {
	dir := filepath.Join(RunDir, "links")
	if err := os.MkdirAll(dir, 0o711); err != nil {
		return nil, err
	}
	path := linkSocket(a.Name)
	_ = os.Remove(path)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	l.SetUnlinkOnClose(true)
	if err := os.Chown(path, acc.uid, acc.gid); err != nil {
		_ = l.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

// serveLinks принимает ссылки от приложения a, пока сокет открыт.
func (d *Daemon) serveLinks(a App, acc account, l *net.UnixListener, sess session) {
	var last time.Time
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			return
		}
		cred, err := peerCred(c)
		if err != nil || int(cred.Uid) != acc.uid {
			_ = c.Close()
			continue
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		line, err := readLine(bufio.NewReader(c), ipc.MaxURL+16)
		reply(c, ipc.Ok)
		_ = c.Close()
		if err != nil || time.Since(last) < linkGap {
			continue
		}
		last = time.Now()
		kind, target, _ := strings.Cut(line, " ")
		switch {
		case kind == "link" && outboundLink(target):
		case kind == "file":
			if target = d.hostFile(a, target); target == "" {
				continue
			}
		default:
			d.log.Printf("%s: ссылка отклонена: %.80q", a.Name, line)
			continue
		}
		if err := openForOwner(d.cfg, sess, target); err != nil {
			d.log.Printf("%s: открытие ссылки: %v", a.Name, err)
		}
	}
}

// hostFile переводит путь файла из песочницы в путь у владельца: только «Загрузки» (общая папка) и открытые приложению
// папки. Программы и ярлыки не открываются: xdg-open запустил бы их.
func (d *Daemon) hostFile(a App, p string) string {
	if !filepath.IsAbs(p) || len(p) > 4096 {
		return ""
	}
	p = filepath.Clean(p)
	host := ""
	downloads := filepath.Join(d.cfg.OwnerHome, "Downloads")
	if rel, err := filepath.Rel(downloads, p); err == nil && filepath.IsLocal(rel) {
		host = filepath.Join(ExchangeDir(), rel)
	}
	for _, s := range a.Shares {
		if rel, err := filepath.Rel(s, p); err == nil && filepath.IsLocal(rel) {
			host = p
		}
	}
	if host == "" {
		return ""
	}
	fi, err := os.Lstat(host)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode()&0o111 != 0 || strings.HasSuffix(host, ".desktop") {
		return ""
	}
	if strings.HasPrefix(host, ExchangeDir()+"/") {
		// У владельца общая папка видна как ~/SessionVault.
		host = filepath.Join(d.cfg.OwnerHome, "SessionVault", strings.TrimPrefix(host, ExchangeDir()+"/"))
	}
	return host
}

// openForOwner открывает ссылку или файл в сеансе владельца его xdg-open: через его менеджер systemd (запущенное не
// окажется в группе службы и не закроется вместе с ней), а если он недоступен — напрямую.
func openForOwner(cfg Config, s session, target string) error {
	cred, err := ownerCred(cfg)
	if err != nil {
		return err
	}
	run := "/run/user/" + strconv.Itoa(cfg.Owner)
	env := []string{"HOME=" + cfg.OwnerHome, "PATH=/usr/local/bin:/usr/bin", "XDG_RUNTIME_DIR=" + run,
		"DBUS_SESSION_BUS_ADDRESS=unix:path=" + run + "/bus", "WAYLAND_DISPLAY=" + s.wayland}
	if s.desktop != "" {
		env = append(env, "XDG_CURRENT_DESKTOP="+s.desktop)
	}
	if s.lang != "" {
		env = append(env, "LANG="+s.lang)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/systemd-run", "--user", "--quiet", "--collect", "--", "/usr/bin/xdg-open", target)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred, Setsid: true}
	cmd.Env, cmd.Dir = env, "/"
	if err := cmd.Run(); err == nil {
		return nil
	}
	cmd = exec.Command("/usr/bin/xdg-open", target)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred, Setsid: true}
	cmd.Env, cmd.Dir = env, "/"
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// SandboxOpen — xdg-open внутри песочницы: ссылка или файл уходит службе. Возвращает код выхода.
func SandboxOpen(args []string) int {
	if len(args) != 1 {
		return 1
	}
	target := args[0]
	line := "link " + target
	if strings.HasPrefix(target, "file://") {
		target = strings.TrimPrefix(target, "file://")
		if p, err := unescapePath(target); err == nil {
			target = p
		}
	}
	if filepath.IsAbs(target) {
		line = "file " + target
	}
	c, err := net.DialTimeout("unix", sandboxLink, 3*time.Second)
	if err != nil {
		return 1
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(line + "\n")); err != nil {
		return 1
	}
	if resp, _ := bufio.NewReader(c).ReadString('\n'); strings.TrimSpace(resp) != ipc.Ok {
		return 1
	}
	return 0
}

func unescapePath(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			n, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return "", err
			}
			b.WriteByte(byte(n))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	if strings.ContainsRune(b.String(), 0) {
		return "", errors.New("bad path")
	}
	return b.String(), nil
}

// shareDir — файлы для GIO в песочнице: ссылки http(s), почта и схемы приложений по умолчанию уходят в xdg-open
// SessionVault (программы на GTK открывают ссылки не через xdg-open, а через ярлык по умолчанию).
func shareDir() string { return filepath.Join(RunDir, "share") }

func writeShareDir() error {
	schemes := []string{"http", "https", "mailto"}
	for _, a := range AllApps() {
		for _, s := range a.Schemes {
			if validScheme(s) && !slices.Contains(schemes, s) {
				schemes = append(schemes, s)
			}
		}
	}
	var mime, defaults strings.Builder
	for _, s := range schemes {
		mime.WriteString("x-scheme-handler/" + s + ";")
		defaults.WriteString("x-scheme-handler/" + s + "=sessionvault-open.desktop\n")
	}
	desktop := "[Desktop Entry]\nType=Application\nName=SessionVault\nNoDisplay=true\nExec=" + BinPath + " open-link %u\nMimeType=" + mime.String() + "\n"
	list := "[Default Applications]\n" + defaults.String()
	for path, content := range map[string]string{
		"applications/sessionvault-open.desktop": desktop,
		"applications/mimeapps.list":             list,
		"config/mimeapps.list":                   list,
	} {
		p := filepath.Join(shareDir(), path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := writeFileAtomic(p, []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}
