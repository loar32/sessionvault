//go:build linux

package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/i18n"
	"github.com/loar32/sessionvault/internal/vault"
)

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

// Protect защищает встроенное приложение.
func Protect(name string, password []byte, shares []string, out io.Writer) error {
	if err := needRoot(); err != nil {
		return err
	}
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	a, ok := builtin(name)
	if !ok {
		return fmt.Errorf(i18n.T("неизвестное приложение %q; доступны: %s"), name, AppNames())
	}
	if appVault(a).Exists() {
		return fmt.Errorf(i18n.T("%s уже защищён"), a.Title)
	}
	if _, err := a.FindExe(); err != nil {
		return err
	}
	if a.Shares, err = CheckShares(cfg, shares); err != nil {
		return err
	}
	_ = os.RemoveAll(AppDir(a.Name)) // остаток прерванной защиты: хранилища в нём нет
	if err := os.MkdirAll(AppDir(a.Name), 0o711); err != nil {
		return err
	}
	if err := protectApp(cfg, a, password, out); err != nil {
		_ = os.RemoveAll(AppDir(a.Name))
		_ = deleteAccount(a.Name)
		return err
	}
	return nil
}

// protectApp переносит данные приложения в хранилище: копия упаковывается с правами владельца и шифруется, потом прежние
// папки удаляются и на их месте появляются приманки. Каталог приложения уже создан (у добавленного в нём описание и копия
// программы); при ошибке его убирает вызывающий.
func protectApp(cfg Config, a App, password []byte, out io.Writer) error {
	v := appVault(a)
	if ownerRunning(cfg, a) {
		return fmt.Errorf(i18n.T("закройте %s и повторите"), a.Title)
	}
	acc, err := ensureAccount(a.Name)
	if err != nil {
		return err
	}
	home := filepath.Join(AppDir(a.Name), homeName)
	_ = os.RemoveAll(home)
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	moved := map[string]bool{}
	for _, d := range a.Dirs {
		ok, err := packFromOwner(cfg, filepath.Join(cfg.OwnerHome, d), a.Name, filepath.Join(home, d))
		if err != nil {
			return err
		}
		moved[d] = ok
	}
	layouts := map[string]string{}
	for _, d := range a.Dirs {
		layouts[d] = decoyLayout(a, filepath.Join(home, d))
	}
	// Метка не даёт архиву оказаться пустым у приложения, которое ещё ничего не сохранило.
	if err := os.WriteFile(filepath.Join(home, ".sessionvault"), []byte("SessionVault\n"), 0o600); err != nil {
		return err
	}
	dek, err := v.Create(password)
	if err != nil {
		return err
	}
	defer crypto.Wipe(dek)
	if err := v.Encrypt(dek); err != nil {
		return err
	}
	if err := SaveApp(a); err != nil {
		return err
	}
	for _, d := range a.Dirs {
		origin := filepath.Join(cfg.OwnerHome, d)
		if moved[d] {
			if _, err := asOwner(cfg, nil, "remove", origin); err != nil {
				_, _ = fmt.Fprintf(out, i18n.T("Прежняя папка %s не удалена (%v): удалите её сами, данные уже в хранилище.\n"), origin, err)
				continue
			}
		}
		if err := placeDecoy(cfg, a.Name, origin, layouts[d]); err != nil {
			_, _ = fmt.Fprintf(out, i18n.T("Приманка не создана: %v\n"), err)
		}
	}
	return finishProtect(cfg, a, acc, out)
}

// finishProtect — общий конец защиты, добавления и переноса: доступ к общей папке и открытым папкам, ярлыки, описание,
// метки приманок в службе.
func finishProtect(cfg Config, a App, acc account, out io.Writer) error {
	u := strconv.Itoa(acc.uid)
	if err := setfacl("-R", "-m", "u:"+u+":rwX,d:u:"+u+":rwX", ExchangeDir()); err != nil {
		_, _ = fmt.Fprintln(out, err)
	}
	for _, s := range a.Shares {
		if _, err := asOwner(cfg, nil, "acl", s, "grant", u, strconv.Itoa(cfg.Owner)); err != nil {
			_, _ = fmt.Fprintf(out, "%s: %v\n", s, err)
		}
	}
	if err := installDesktop(cfg, &a); err != nil {
		_, _ = fmt.Fprintf(out, i18n.T("Ярлык не подменён: %v\n"), err)
	}
	if err := SaveApp(a); err != nil {
		return err
	}
	_, _ = Call("reload", nil, 10*time.Second)
	_, _ = fmt.Fprintf(out, i18n.T("%s защищён. Запускайте его как обычно (лаунчер, ссылки, веб-приложения): он откроется в песочнице под учёткой %s.\n"), a.Title, AccountName(a.Name))
	return nil
}

// decoyLayout — раскладка приманки на месте папки данных: у встроенных своя, у добавленных — по содержимому (Electron
// узнаётся по своим файлам).
func decoyLayout(a App, data string) string {
	if !a.Custom {
		return a.Decoy
	}
	for _, f := range []string{"Local State", "Local Storage", "Preferences"} {
		if _, err := os.Lstat(filepath.Join(data, f)); err == nil {
			return "discord"
		}
	}
	return "generic"
}

func placeDecoy(cfg Config, app, origin, layout string) error {
	b, err := asOwner(cfg, nil, "decoy", origin, layout)
	if err != nil {
		return err
	}
	var files []DecoyFile
	if err := json.Unmarshal(b, &files); err != nil {
		return err
	}
	m := loadDecoys()
	m[app] = append(m[app], decoyEntry{Path: origin, Layout: layout, Files: files})
	return saveDecoys(m)
}

// CheckShares — папки владельца, которые можно открыть приложению: существующие, внутри его дома, не сам дом.
func CheckShares(cfg Config, shares []string) ([]string, error) {
	var out []string
	for _, s := range shares {
		p, err := ownerPath(cfg, s)
		if err != nil {
			return nil, err
		}
		if p == cfg.OwnerHome {
			return nil, errors.New(i18n.T("весь домашний каталог открыть нельзя: укажите папку внутри него"))
		}
		if fi, err := os.Stat(p); err != nil || !fi.IsDir() {
			return nil, fmt.Errorf(i18n.T("%s не папка"), p)
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// ownerPath переводит путь пользователя (~/x, относительный от дома или абсолютный) в абсолютный путь внутри его дома.
func ownerPath(cfg Config, s string) (string, error) {
	switch {
	case s == "~":
		s = cfg.OwnerHome
	case strings.HasPrefix(s, "~/"):
		s = filepath.Join(cfg.OwnerHome, s[2:])
	case !filepath.IsAbs(s):
		s = filepath.Join(cfg.OwnerHome, s)
	}
	s = filepath.Clean(s)
	rel, err := filepath.Rel(cfg.OwnerHome, s)
	if err != nil || (rel != "." && !filepath.IsLocal(rel)) {
		return "", fmt.Errorf(i18n.T("%s вне домашнего каталога %s"), s, cfg.OwnerHome)
	}
	return s, nil
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
	decoys := loadDecoys()
	home := filepath.Join(AppDir(a.Name), homeName)
	for _, d := range a.Dirs {
		origin := filepath.Join(cfg.OwnerHome, d)
		for _, e := range decoys[a.Name] {
			if e.Path != origin {
				continue
			}
			manifest, _ := json.Marshal(e.Files)
			if _, err := asOwner(cfg, manifest, "undecoy", origin); err != nil {
				return errors.Join(err, v.Encrypt(dek))
			}
		}
		data := filepath.Join(home, d)
		if _, err := os.Lstat(data); err != nil {
			continue
		}
		msg, err := unpackToOwner(cfg, data, a.Exclude, origin)
		if err != nil {
			for _, e := range decoys[a.Name] {
				if e.Path == origin {
					_ = placeDecoy(cfg, a.Name, origin, e.Layout)
				}
			}
			return errors.Join(err, v.Encrypt(dek))
		}
		_, _ = out.Write(msg)
	}
	delete(decoys, a.Name)
	if err := saveDecoys(decoys); err != nil {
		_, _ = fmt.Fprintln(out, err)
	}
	removeDesktop(cfg, a)
	if acc, err := lookupAccount(a.Name); err == nil {
		u := strconv.Itoa(acc.uid)
		_ = setfacl("-R", "-x", "u:"+u+",d:u:"+u, ExchangeDir())
		for _, s := range a.Shares {
			_, _ = asOwner(cfg, nil, "acl", s, "revoke", u, strconv.Itoa(cfg.Owner))
		}
	}
	if err := deleteAccount(a.Name); err != nil {
		_, _ = fmt.Fprintln(out, err)
	}
	unlock()
	if err := os.RemoveAll(AppDir(a.Name)); err != nil {
		return err
	}
	_, _ = Call("reload", nil, 10*time.Second)
	var where []string
	for _, d := range a.Dirs {
		where = append(where, filepath.Join(cfg.OwnerHome, d))
	}
	_, _ = fmt.Fprintf(out, i18n.T("%s больше не защищён: данные возвращены в %s.\n"), a.Title, strings.Join(where, ", "))
	return nil
}

func appVault(a App) vault.Vault {
	return vault.Vault{Dir: AppDir(a.Name), DataName: homeName, Exclude: a.HomeExclude()}
}
