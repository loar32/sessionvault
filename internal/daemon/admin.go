//go:build linux

package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/i18n"
	"github.com/loar32/sessionvault/internal/vault"
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
	_, _ = fmt.Fprintf(out, i18n.T("SessionVault установлен для %s. Защитите приложение: sudo sessionvault protect <%s>\n"), u.Username, AppNames())
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

// ownerRunning — приложение запущено владельцем в обход SessionVault: переносить его данные на ходу нельзя.
func ownerRunning(cfg Config, a App) bool {
	for _, pid := range pidsOf(cfg.Owner) {
		exe, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
		if err == nil && slices.Contains(a.Images, exe) {
			return true
		}
	}
	return false
}

// Protect переносит данные приложения в хранилище: копия упаковывается с правами владельца, шифруется, потом прежняя папка
// удаляется и на её месте появляется приманка.
func Protect(name string, password []byte, out io.Writer) error {
	if err := needRoot(); err != nil {
		return err
	}
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	a, ok := FindApp(name)
	if !ok {
		return fmt.Errorf(i18n.T("неизвестное приложение %q; доступны: %s"), name, AppNames())
	}
	v := appVault(a)
	if v.Exists() {
		return fmt.Errorf(i18n.T("%s уже защищён"), a.Title)
	}
	if _, err := a.FindExe(); err != nil {
		return err
	}
	if ownerRunning(cfg, a) {
		return fmt.Errorf(i18n.T("закройте %s и повторите"), a.Title)
	}
	dir := AppDir(a.Name)
	_ = os.RemoveAll(dir) // остаток прерванной защиты: хранилища в нём нет
	if err := os.MkdirAll(dir, 0o711); err != nil {
		return err
	}
	acc, err := ensureAccount(a.Name)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		_ = os.RemoveAll(dir)
		_ = deleteAccount(a.Name)
		return err
	}
	origin := filepath.Join(cfg.OwnerHome, a.Origin)
	data, err := asOwner(cfg, nil, "pack", origin, a.Name)
	if err != nil {
		return fail(err)
	}
	home := filepath.Join(dir, homeName)
	if err := os.MkdirAll(home, 0o700); err != nil {
		return fail(err)
	}
	if len(data) > 0 {
		if err := vault.UnpackDir(data, filepath.Join(home, a.Origin)); err != nil {
			return fail(err)
		}
	}
	crypto.Wipe(data)
	// Метка не даёт архиву оказаться пустым у приложения, которое ещё ничего не сохранило.
	if err := os.WriteFile(filepath.Join(home, ".sessionvault"), []byte("SessionVault\n"), 0o600); err != nil {
		return fail(err)
	}
	dek, err := v.Create(password)
	if err != nil {
		return fail(err)
	}
	defer crypto.Wipe(dek)
	if err := v.Encrypt(dek); err != nil {
		return fail(err)
	}
	if _, err := asOwner(cfg, nil, "remove", origin); err != nil {
		_, _ = fmt.Fprintf(out, i18n.T("Прежняя папка %s не удалена (%v): удалите её сами, данные уже в хранилище.\n"), origin, err)
	}
	if err := placeDecoy(cfg, a); err != nil {
		_, _ = fmt.Fprintf(out, i18n.T("Приманка не создана: %v\n"), err)
	}
	u := strconv.Itoa(acc.uid)
	if err := setfacl("-R", "-m", "u:"+u+":rwX,d:u:"+u+":rwX", ExchangeDir()); err != nil {
		_, _ = fmt.Fprintln(out, err)
	}
	if err := installDesktop(cfg, a); err != nil {
		_, _ = fmt.Fprintf(out, i18n.T("Ярлык не подменён: %v\n"), err)
	}
	_, _ = Call("reload", nil, 10*time.Second)
	_, _ = fmt.Fprintf(out, i18n.T("%s защищён. Запускайте его как обычно (лаунчер, ссылки, веб-приложения): он откроется в песочнице под учёткой %s.\n"), a.Title, AccountName(a.Name))
	return nil
}

func placeDecoy(cfg Config, a App) error {
	origin := filepath.Join(cfg.OwnerHome, a.Origin)
	b, err := asOwner(cfg, nil, "decoy", origin, a.Decoy)
	if err != nil {
		return err
	}
	var files []DecoyFile
	if err := json.Unmarshal(b, &files); err != nil {
		return err
	}
	m := loadDecoys()
	m[a.Name] = decoyEntry{Path: origin, Files: files}
	return saveDecoys(m)
}

// Unprotect возвращает данные на прежнее место (с правами владельца) и убирает всё, что создала защита.
func Unprotect(name string, password []byte, out io.Writer) error {
	if err := needRoot(); err != nil {
		return err
	}
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	a, ok := FindApp(name)
	if !ok {
		return fmt.Errorf(i18n.T("неизвестное приложение %q; доступны: %s"), name, AppNames())
	}
	v := appVault(a)
	if !v.Exists() {
		return fmt.Errorf(i18n.T("%s не защищён"), a.Title)
	}
	if r, err := Call("running", nil, 5*time.Second); err == nil && slices.Contains(strings.Split(r, ","), a.Name) {
		return fmt.Errorf(i18n.T("закройте %s и повторите"), a.Title)
	}
	unlock, err := v.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	dek, err := v.Unlock(password)
	if err != nil {
		return err
	}
	defer crypto.Wipe(dek)
	if !v.NeedsRecovery() {
		if err := v.Decrypt(dek); err != nil {
			return err
		}
	}
	data := filepath.Join(AppDir(a.Name), homeName, a.Origin)
	var tar []byte
	if _, err := os.Lstat(data); err == nil {
		if tar, _, err = vault.PackDir(data, a.Exclude); err != nil {
			return errors.Join(err, v.Encrypt(dek))
		}
	}
	origin := filepath.Join(cfg.OwnerHome, a.Origin)
	decoys := loadDecoys()
	if e, ok := decoys[a.Name]; ok {
		manifest, _ := json.Marshal(e.Files)
		if _, err := asOwner(cfg, manifest, "undecoy", origin); err != nil {
			return errors.Join(err, v.Encrypt(dek))
		}
	}
	if tar != nil {
		msg, err := asOwner(cfg, tar, "unpack", origin)
		if err != nil {
			_ = placeDecoy(cfg, a)
			return errors.Join(err, v.Encrypt(dek))
		}
		crypto.Wipe(tar)
		_, _ = out.Write(msg)
	}
	delete(decoys, a.Name)
	if err := saveDecoys(decoys); err != nil {
		_, _ = fmt.Fprintln(out, err)
	}
	removeDesktop(cfg, a)
	if acc, err := lookupAccount(a.Name); err == nil {
		_ = setfacl("-R", "-x", "u:"+strconv.Itoa(acc.uid), ExchangeDir())
	}
	if err := deleteAccount(a.Name); err != nil {
		_, _ = fmt.Fprintln(out, err)
	}
	unlock()
	if err := os.RemoveAll(AppDir(a.Name)); err != nil {
		return err
	}
	_, _ = Call("reload", nil, 10*time.Second)
	_, _ = fmt.Fprintf(out, i18n.T("%s больше не защищён: данные возвращены в %s.\n"), a.Title, origin)
	return nil
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
