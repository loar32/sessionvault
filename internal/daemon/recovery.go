//go:build linux

package daemon

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"unicode"

	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/i18n"
	"github.com/loar32/sessionvault/internal/recovery"
	"github.com/loar32/sessionvault/internal/vault"
)

// Ключ восстановления и перенос на другой ПК — как в Windows-версии: те же слоты в vault.json, те же 24 слова.

func adminVaults() (map[string]vault.Vault, error) {
	if err := needRoot(); err != nil {
		return nil, err
	}
	out := map[string]vault.Vault{}
	for _, a := range Protected() {
		out[a.Name] = appVault(a)
	}
	if len(out) == 0 {
		return nil, errors.New(i18n.T("защищённых приложений нет"))
	}
	return out, nil
}

// lockAll занимает running.lock всех хранилищ: пока приложение запущено, служба сама пишет его vault.json, и запись слота
// отсюда могла бы затереться.
func lockAll(vs map[string]vault.Vault, names []string) (func(), error) {
	var rel []func()
	release := func() {
		for _, r := range rel {
			r()
		}
	}
	for _, n := range names {
		r, err := vs[n].Lock()
		if err != nil {
			release()
			return nil, fmt.Errorf(i18n.T("%s: приложение запущено или не завершено: закройте его и повторите"), n)
		}
		rel = append(rel, r)
	}
	return release, nil
}

func vaultNames(vs map[string]vault.Vault) []string {
	out := make([]string, 0, len(vs))
	for n := range vs {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// RecoveryCreate выпускает новый ключ восстановления для всех хранилищ; прежний перестаёт работать. Сначала открываются
// все хранилища, и только потом пишутся слоты; сбой на середине возвращает прежние vault.json всем изменённым.
func RecoveryCreate(ask func(name string) ([]byte, error)) (string, error) {
	vs, err := adminVaults()
	if err != nil {
		return "", err
	}
	deks := map[string][]byte{}
	defer func() {
		for _, d := range deks {
			crypto.Wipe(d)
		}
	}()
	names := vaultNames(vs)
	for _, name := range names {
		pw, err := ask(name)
		if err != nil {
			return "", err
		}
		dek, err := vs[name].Unlock(pw)
		crypto.Wipe(pw)
		if err != nil {
			return "", fmt.Errorf("%s: %w", name, err)
		}
		deks[name] = dek
	}
	release, err := lockAll(vs, names)
	if err != nil {
		return "", err
	}
	defer release()
	key, err := crypto.NewKey()
	if err != nil {
		return "", err
	}
	defer crypto.Wipe(key)
	words, err := recovery.Words(key)
	if err != nil {
		return "", err
	}
	saved := map[string][]byte{}
	for _, name := range names {
		b, err := vs[name].MetaBytes()
		if err != nil {
			return "", fmt.Errorf("%s: %w", name, err)
		}
		saved[name] = b
	}
	var changed []string
	for _, name := range names {
		if err := vs[name].SetRecovery(deks[name], key); err != nil {
			err = fmt.Errorf("%s: %w", name, err)
			for _, done := range changed {
				if e := vs[done].RestoreMeta(saved[done]); e != nil {
					err = errors.Join(err, fmt.Errorf(i18n.T("%s: прежний vault.json не возвращён: %w"), done, e))
				}
			}
			return "", err
		}
		changed = append(changed, name)
	}
	return words, nil
}

// RecoveryVerify проверяет слова с бумаги, ничего не меняя.
func RecoveryVerify(words string) (ok, bad []string, err error) {
	vs, err := adminVaults()
	if err != nil {
		return nil, nil, err
	}
	key, err := recovery.Parse(words)
	if err != nil {
		return nil, nil, err
	}
	defer crypto.Wipe(key)
	for _, name := range vaultNames(vs) {
		dek, err := vs[name].UnlockRecovery(key)
		if err != nil {
			bad = append(bad, name)
			continue
		}
		crypto.Wipe(dek)
		ok = append(ok, name)
	}
	return ok, bad, nil
}

// RecoveryRevoke убирает ключ восстановления у одного приложения.
func RecoveryRevoke(app string) error {
	vs, err := adminVaults()
	if err != nil {
		return err
	}
	v, ok := vs[app]
	if !ok {
		return fmt.Errorf(i18n.T("хранилища %s нет"), app)
	}
	release, err := lockAll(vs, []string{app})
	if err != nil {
		return err
	}
	defer release()
	return v.RemoveRecovery()
}

// RecoveryReset задаёт новый мастер-пароль всем хранилищам, которые открывает ключ восстановления.
func RecoveryReset(words string, password []byte) (reset, skipped []string, err error) {
	vs, err := adminVaults()
	if err != nil {
		return nil, nil, err
	}
	key, err := recovery.Parse(words)
	if err != nil {
		return nil, nil, err
	}
	defer crypto.Wipe(key)
	names := vaultNames(vs)
	release, err := lockAll(vs, names)
	if err != nil {
		return nil, nil, err
	}
	defer release()
	for _, name := range names {
		dek, err := vs[name].UnlockRecovery(key)
		if err != nil {
			skipped = append(skipped, name)
			continue
		}
		err = vs[name].SetPassword(dek, password)
		crypto.Wipe(dek)
		if err != nil {
			return reset, skipped, fmt.Errorf("%s: %w", name, err)
		}
		reset = append(reset, name)
	}
	if len(reset) == 0 {
		return nil, nil, errors.New(i18n.T("ключ восстановления не подошёл ни к одному хранилищу"))
	}
	return reset, skipped, nil
}

// RecoveryCovered — какие хранилища открывает ключ восстановления, а какие нет.
func RecoveryCovered() (with, without []string, err error) {
	vs, err := adminVaults()
	if err != nil {
		return nil, nil, err
	}
	for _, name := range vaultNames(vs) {
		if vs[name].HasRecovery() {
			with = append(with, name)
		} else {
			without = append(without, name)
		}
	}
	return with, without, nil
}

// Файл переноса Linux: строка-метка, строка JSON (приложение, vault.json, описание добавленного приложения), затем
// data.enc как есть. Всё уже зашифровано; data.enc идёт потоком, без чтения в память.
const exportMagic = "SVX-LINUX-1"

type exportHeader struct {
	App    string `json:"app"`
	Meta   []byte `json:"meta"`
	Custom *App   `json:"custom,omitempty"`
}

// Export пишет хранилище приложения в файл для переноса. Файл не перезаписывается и отдаётся владельцу: его можно
// скопировать на флешку без root.
func Export(name, path string) error {
	if err := needRoot(); err != nil {
		return err
	}
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	a, ok := FindApp(name)
	if !ok || !appVault(a).Exists() {
		return fmt.Errorf(i18n.T("хранилища %s нет"), name)
	}
	v := appVault(a)
	release, err := v.Lock()
	if err != nil {
		return fmt.Errorf(i18n.T("закройте %s и повторите"), a.Title)
	}
	defer release()
	meta, err := v.ExportMeta()
	if err != nil {
		return err
	}
	hdr := exportHeader{App: a.Name, Meta: meta}
	if a.Custom {
		c := a
		c.Rewritten, c.Shares = nil, nil
		hdr.Custom = &c
	}
	line, err := json.Marshal(hdr)
	if err != nil {
		return err
	}
	data, err := os.Open(v.DataPath())
	if err != nil {
		return err
	}
	defer func() { _ = data.Close() }()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	_, err = fmt.Fprintf(w, "%s\n%s\n", exportMagic, line)
	if err == nil {
		_, err = io.Copy(w, data)
	}
	if err == nil {
		err = w.Flush()
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = f.Chown(cfg.Owner, ownerGID(cfg))
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

// ImportOptions — перенос добавленного приложения: где программа на этом ПК и подтверждение описания из файла
// (аргументы запуска приходят со стороны, поэтому их подтверждает человек).
type ImportOptions struct {
	Exe     string
	Confirm func(info string) bool
	Ask     func(a App) ([]byte, error)
}

// Import восстанавливает приложение из файла Export. Данные приложения, которые уже есть на этом ПК, не трогаются.
func Import(path string, o ImportOptions, out io.Writer) (string, error) {
	if err := needRoot(); err != nil {
		return "", err
	}
	cfg, err := LoadConfig()
	if err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReaderSize(f, 1<<20)
	magic, _ := r.ReadString('\n')
	if strings.TrimSpace(magic) != exportMagic {
		if strings.HasPrefix(magic, "{") {
			return "", errors.New(i18n.T("это файл экспорта Windows-версии: данные Windows-приложений на Linux не переносятся"))
		}
		return "", errors.New(i18n.T("файл не похож на экспорт SessionVault"))
	}
	line, err := r.ReadSlice('\n')
	if err != nil {
		return "", errors.New(i18n.T("файл не похож на экспорт SessionVault"))
	}
	var hdr exportHeader
	if err := json.Unmarshal(bytes.TrimSpace(line), &hdr); err != nil {
		return "", errors.New(i18n.T("файл не похож на экспорт SessionVault"))
	}
	a, ok := builtin(hdr.App)
	switch {
	case ok:
		if _, err := a.FindExe(); err != nil {
			return "", fmt.Errorf(i18n.T("сначала установите %s: %v"), a.Title, err)
		}
	case hdr.Custom != nil && hdr.Custom.Name == hdr.App:
		if a, err = importedApp(cfg, *hdr.Custom, o); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf(i18n.T("неизвестное приложение %q"), hdr.App)
	}
	v := appVault(a)
	if v.Exists() {
		return "", fmt.Errorf(i18n.T("%s уже защищён на этом ПК"), a.Title)
	}
	dir := AppDir(a.Name)
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o711); err != nil {
		return "", err
	}
	fail := func(err error) (string, error) {
		_ = os.RemoveAll(dir)
		_ = deleteAccount(a.Name)
		return "", err
	}
	acc, err := ensureAccount(a.Name)
	if err != nil {
		return fail(err)
	}
	if a.Kind != "" {
		if err := copyProgram(cfg, acc, &a); err != nil {
			return fail(err)
		}
	}
	secret, err := o.Ask(a)
	if err != nil {
		return fail(err)
	}
	defer crypto.Wipe(secret)
	if err := v.ImportFrom(hdr.Meta, r, secret); err != nil {
		return fail(err)
	}
	if err := SaveApp(a); err != nil {
		return fail(err)
	}
	for _, d := range a.Dirs {
		origin := filepath.Join(cfg.OwnerHome, d)
		if _, err := os.Lstat(origin); err == nil {
			_, _ = fmt.Fprintf(out, i18n.T("В %s уже есть данные этого ПК: они остались на месте открытыми, удалите их сами.\n"), origin)
			continue
		}
		if err := placeDecoy(cfg, a.Name, origin, importLayout(a)); err != nil {
			_, _ = fmt.Fprintf(out, i18n.T("Приманка не создана: %v\n"), err)
		}
	}
	if err := finishProtect(cfg, a, acc, out); err != nil {
		return fail(err)
	}
	return a.Name, nil
}

// importLayout — раскладка приманки, когда самих данных под рукой нет (перенос): у добавленных — общая.
func importLayout(a App) string {
	if a.Custom {
		return "generic"
	}
	return a.Decoy
}

// importedApp — описание добавленного приложения из файла переноса, но программа — этого ПК: её путь проверяется заново
// так же, как при add.
func importedApp(cfg Config, c App, o ImportOptions) (App, error) {
	target := o.Exe
	if target == "" {
		switch c.Kind {
		case "":
			target = c.Exe[0]
		case "dir":
			target = filepath.Join(c.Source, filepath.Base(c.Exe[0]))
		default:
			target = c.Source
		}
	}
	plan, err := PlanAdd(AddRequest{Target: target, Name: c.Name, Dirs: c.Dirs, Args: c.Args, ArgsSet: true})
	if err != nil {
		return App{}, fmt.Errorf(i18n.T("программа %s на этом ПК: %w (укажите её: -exe путь)"), c.Title, err)
	}
	if plan.Builtin != "" {
		return App{}, fmt.Errorf(i18n.T("%s на этом ПК — встроенное приложение %s"), target, plan.Builtin)
	}
	a := plan.App
	// Заголовок файла не подписан, а название и схемы попадают в ярлык владельца: перевод строки добавил бы туда свой Exec.
	if c.Title != "" && !strings.ContainsFunc(c.Title, unicode.IsControl) {
		a.Title = c.Title
	}
	a.Schemes = slices.DeleteFunc(slices.Clone(c.Schemes), func(s string) bool { return !validScheme(s) })
	a.Browser, a.Chromium = c.Browser, c.Chromium
	for _, m := range c.Match {
		if !slices.Contains(a.Match, m) {
			a.Match = append(a.Match, m)
		}
	}
	info := fmt.Sprintf(i18n.T("Приложение из файла: %s (%s)\nПрограмма на этом ПК: %s\nАргументы запуска из файла: %s\nПапки данных: %s\n"),
		a.Title, a.Name, target, strings.Join(a.Args, " "), strings.Join(a.Dirs, ", "))
	if !o.Confirm(info) {
		return App{}, errors.New(i18n.T("отменено"))
	}
	return a, nil
}
