//go:build linux

package daemon

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/i18n"
)

const unit = `[Unit]
Description=SessionVault
After=local-fs.target

[Service]
Type=simple
ExecStart=` + BinPath + ` daemon
Restart=on-failure
RestartSec=2
# Сначала SIGTERM только службе: она гасит приложения и шифрует их данные, потом выходит.
KillMode=mixed
TimeoutStopSec=45

[Install]
WantedBy=multi-user.target
`

func needRoot() error {
	if os.Geteuid() != 0 {
		return errors.New(i18n.T("нужны права root: запустите через sudo"))
	}
	return nil
}

// Install ставит службу. Владелец — тот, кто вызвал sudo: под root программа не ставится, root обходит любые права.
func Install(out io.Writer) error {
	if err := needRoot(); err != nil {
		return err
	}
	uid, err := strconv.Atoi(os.Getenv("SUDO_UID"))
	if err != nil || uid == 0 {
		return errors.New(i18n.T("запустите из своей учётки через sudo (не из-под root): sudo sessionvault install"))
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return err
	}
	for _, tool := range []string{bwrapPath, "/usr/bin/setfacl", "/usr/bin/useradd", "/usr/bin/userdel", "/usr/bin/systemctl"} {
		if _, err := os.Stat(tool); err != nil {
			return fmt.Errorf(i18n.T("нет %s (пакеты bubblewrap, acl, shadow, systemd)"), tool)
		}
	}
	if _, err := os.Stat(dbusProxyPath); err != nil {
		_, _ = fmt.Fprintln(out, i18n.T("Без него у защищённых приложений нет уведомлений, значка в трее и связки ключей: sudo pacman -S xdg-dbus-proxy"))
	}
	if b, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil && strings.TrimSpace(string(b)) == "0" {
		return errors.New(i18n.T("в ядре выключены пространства имён пользователей: bubblewrap не запустит песочницу"))
	}
	cfg, err := LoadConfig()
	if err == nil && cfg.Owner != uid {
		return fmt.Errorf(i18n.T("SessionVault уже установлен для учётки %s"), cfg.OwnerName)
	}
	cfg.Owner, cfg.OwnerName, cfg.OwnerHome = uid, u.Username, u.HomeDir
	for _, d := range []string{BaseDir, AppsDir()} {
		if err := os.MkdirAll(d, 0o711); err != nil {
			return err
		}
		if err := os.Chmod(d, 0o711); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(ExchangeDir(), 0o700); err != nil {
		return err
	}
	if err := setfacl("-m", "u:"+strconv.Itoa(uid)+":rwx,d:u:"+strconv.Itoa(uid)+":rwx", ExchangeDir()); err != nil {
		return err
	}
	if err := SaveConfig(cfg); err != nil {
		return err
	}
	if err := installBinary(); err != nil {
		return err
	}
	if err := os.WriteFile(UnitPath, []byte(unit), 0o644); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "sessionvault"}, {"restart", "sessionvault"}} {
		if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	if _, err := asOwner(cfg, menuDesktop(), "put", filepath.Join(appsDir(cfg), "sessionvault.desktop")); err != nil {
		_, _ = fmt.Fprintln(out, "sessionvault.desktop:", err)
	}
	if _, err := asOwner(cfg, nil, "link", filepath.Join(cfg.OwnerHome, "SessionVault"), ExchangeDir()); err != nil {
		_, _ = fmt.Fprintln(out, "~/SessionVault:", err)
	}
	_, _ = fmt.Fprintf(out, i18n.T("SessionVault установлен для %s. Защитите приложение: sudo sessionvault protect <%s>, своё — sudo sessionvault add <программа>\n"), u.Username, AppNames())
	return nil
}

func installBinary() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe == BinPath {
		return nil
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(BinPath), 0o755); err != nil {
		return err
	}
	return writeFileAtomic(BinPath, b, 0o755)
}

// Uninstall снимает защиту со всех приложений (нужны их пароли) и убирает службу. Общая папка с файлами остаётся.
func Uninstall(password func(App) ([]byte, error), out io.Writer) error {
	if err := needRoot(); err != nil {
		return err
	}
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	for _, a := range Protected() {
		pw, err := password(a)
		if err != nil {
			return err
		}
		err = Unprotect(a.Name, pw, out)
		crypto.Wipe(pw)
		if err != nil {
			return fmt.Errorf("%s: %w", a.Name, err)
		}
	}
	_ = exec.Command("systemctl", "disable", "--now", "sessionvault").Run()
	_ = os.Remove(UnitPath)
	_ = exec.Command("systemctl", "daemon-reload").Run()
	_, _ = asOwner(cfg, nil, "del", filepath.Join(appsDir(cfg), "sessionvault.desktop"))
	_, _ = asOwner(cfg, nil, "unlink", filepath.Join(cfg.OwnerHome, "SessionVault"))
	keep := false
	if entries, err := os.ReadDir(ExchangeDir()); err == nil && len(entries) > 0 {
		keep = true
	}
	entries, _ := os.ReadDir(BaseDir)
	for _, e := range entries {
		if keep && e.Name() == "exchange" {
			continue
		}
		_ = os.RemoveAll(filepath.Join(BaseDir, e.Name()))
	}
	if !keep {
		_ = os.Remove(BaseDir)
	}
	_ = os.RemoveAll(RunDir)
	_ = os.Remove(BinPath)
	if keep {
		_, _ = fmt.Fprintf(out, i18n.T("Общая папка %s не пуста и оставлена.\n"), ExchangeDir())
	}
	_, _ = fmt.Fprintln(out, i18n.T("SessionVault удалён."))
	return nil
}
