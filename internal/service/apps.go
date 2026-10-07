package service

import (
	"errors"
	"fmt"
	"github.com/loar32/sessionvault/internal/i18n"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/loar32/sessionvault/internal/audit"
	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/decoy"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"github.com/loar32/sessionvault/internal/vault"
)

// findDiscordDir — каталог последней версии Discord (app-<версия> с Discord.exe) в профиле основной учётки.
func findDiscordDir(user string) (string, error) {
	root := filepath.Join(usersDir(), user, `AppData\Local\Discord`)
	if err := decoy.NoReparse(root); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", errors.New(`программа Discord не найдена: она ставится в профиль пользователя (AppData\Local\Discord)`)
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "app-") {
			if _, err := os.Stat(filepath.Join(root, e.Name(), "Discord.exe")); err == nil {
				dirs = append(dirs, e.Name())
			}
		}
	}
	if len(dirs) == 0 {
		return "", errors.New(`в AppData\Local\Discord нет app-<версия>\Discord.exe: запустите Discord один раз`)
	}
	sort.Slice(dirs, func(i, j int) bool { return versionLess(dirs[j], dirs[i]) })
	return filepath.Join(root, dirs[0]), nil
}

func versionLess(a, b string) bool {
	pa, pb := strings.Split(strings.TrimPrefix(a, "app-"), "."), strings.Split(strings.TrimPrefix(b, "app-"), ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x < y
		}
	}
	return len(pa) < len(pb)
}

// copyDir копирует дерево каталогов. Ссылки и junction пропускаются: источник лежит в профиле пользователя, а копирует служба с правами SYSTEM.
func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0:
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		case d.Type().IsRegular():
			return copyFile(path, target)
		}
		return nil
	})
}

// installCopy копирует каталог приложения в каталог программы (читаемый для vault, но не изменяемый пользователем)
// и выставляет p.Exe и p.Source. exeRel — путь exe внутри каталога.
func installCopy(p *profiles.Profile, srcDir, exeRel string) error {
	dst := filepath.Join(InstallDir(), "apps", p.Name)
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	if err := decoy.NoReparse(srcDir); err != nil {
		return err
	}
	release, err := isolation.PinParent(srcDir)
	if err != nil {
		return err
	}
	defer release()
	if err := copyDir(srcDir, dst); err != nil {
		_ = os.RemoveAll(dst)
		return err
	}
	p.Exe, p.Source = filepath.Join(dst, exeRel), srcDir
	if err := verifyPublisher(*p); err != nil {
		_ = os.RemoveAll(dst)
		return err
	}
	return nil
}

// resolveApp достраивает профиль встроенного приложения, которому нужна копия каталога (сейчас Discord).
func resolveApp(p *profiles.Profile, user string) error {
	if p.Name != "discord" || p.Exe != "" {
		return nil
	}
	dir, err := findDiscordDir(user)
	if err != nil {
		return err
	}
	return installCopy(p, dir, "Discord.exe")
}

// placeExe выставляет p.Exe: приложение в каталоге Windows или Program Files запускается на месте, иначе (его может заменить
// обычная учётка) копируется в каталог программы — одним файлом или, с copyDir, целиком вместе с каталогом.
func placeExe(p *profiles.Profile, exe string, copyDir bool) error {
	p.Exe = exe
	appDir := filepath.Join(InstallDir(), "apps", p.Name)
	switch {
	case copyDir:
		return installCopy(p, filepath.Dir(exe), filepath.Base(exe))
	case !inProtectedRoot(exe):
		dst := filepath.Join(appDir, filepath.Base(exe))
		if err := os.MkdirAll(appDir, 0o755); err != nil {
			return err
		}
		if err := copyFile(exe, dst); err != nil {
			return err
		}
		p.Exe, p.Source = dst, filepath.Dir(exe)
		if err := verifyPublisher(*p); err != nil {
			_ = os.RemoveAll(appDir)
			return err
		}
	}
	return nil
}

// RefreshApp копирует каталог приложения заново (после обновления самого приложения): обновляется только копия под vault.
// Приложение должно быть закрыто.
func RefreshApp(name string) error {
	if !isolation.IsElevated() {
		return errors.New(i18n.T("нужен запуск от администратора"))
	}
	if err := isolation.EnablePrivileges("SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege"); err != nil {
		return err
	}
	p, err := profiles.Load(isolation.ProfilesDir(), name)
	if err != nil {
		return err
	}
	if p.Source == "" {
		return fmt.Errorf(i18n.T("%s не копируется под учётку приложения: обновлять нечего"), name)
	}
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	v := vault.Vault{Dir: isolation.DataPath(name), DataName: workDataName}
	release, err := v.Lock()
	if err != nil {
		return errors.New(i18n.T("приложение запущено: закройте его и повторите"))
	}
	defer release()
	src, rel := p.Source, strings.TrimPrefix(p.Exe, filepath.Join(InstallDir(), "apps", name)+`\`)
	if name == "discord" {
		if src, err = findDiscordDir(cfg.MainUser); err != nil {
			return err
		}
	}
	if err := installCopy(&p, src, rel); err != nil {
		return err
	}
	return profiles.Save(isolation.ProfilesDir(), p)
}

var ErrNotConfirmed = errors.New("отменено: подтверждение не получено, приложение не добавлено")

// AddOptions — параметры собственного приложения для AddApp.
type AddOptions struct {
	Name    string
	Exe     string
	Origin  string // каталог данных приложения в профиле основной учётки; может ещё не существовать
	DataDir string // имя папки данных внутри рабочей папки (по умолчанию имя каталога Origin)
	Args    []string
	CopyDir bool // копировать весь каталог exe, а не один файл
}

// inProtectedRoot — файл лежит там, где обычная учётка не может его подменить (Windows, Program Files). Всё остальное (профиль
// пользователя, другой диск, C:\Tools) копируется под vault: иначе вредоносный код основной учётки заменил бы exe, который потом
// запускается с расшифрованными данными.
func inProtectedRoot(path string) bool {
	for _, r := range protectedRoots() {
		if under(path, r) {
			return true
		}
	}
	return false
}

func under(path, root string) bool {
	return strings.HasPrefix(strings.ToLower(path), strings.ToLower(root)+`\`)
}

// AddApp защищает собственное приложение: создаёт профиль и хранилище, переносит данные из Origin под vault.
// Приложение должно уметь задавать папку данных аргументом: хотя бы один из Args должен содержать {data_path}.
// confirm показывает администратору, что именно будет запускаться, и спрашивает разрешение; askPassword — мастер-пароль.
func AddApp(o AddOptions, confirm func(info string) bool, askPassword func() ([]byte, error)) error {
	if !isolation.IsElevated() {
		return errors.New(i18n.T("нужен запуск от администратора"))
	}
	if err := isolation.EnablePrivileges("SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege"); err != nil {
		return err
	}
	cfg, err := LoadConfig()
	if err != nil {
		return fmt.Errorf(i18n.T("конфигурация не прочитана: сначала install: %w"), err)
	}
	if !profiles.ValidName(o.Name) {
		return errors.New(i18n.T("имя: от 1 до 32 символов, строчные латинские буквы, цифры и дефис"))
	}
	if _, ok := profiles.Template(o.Name); ok {
		return fmt.Errorf(i18n.T("имя %q занято встроенным приложением: используйте sessionvault protect %s"), o.Name, o.Name)
	}
	if !filepath.IsAbs(o.Exe) || !strings.EqualFold(filepath.Ext(o.Exe), ".exe") {
		return errors.New(i18n.T("укажите полный путь к .exe"))
	}
	if _, err := os.Stat(o.Exe); err != nil {
		return fmt.Errorf(i18n.T("%s не найден"), o.Exe)
	}
	userDir := filepath.Join(usersDir(), cfg.MainUser)
	origin := filepath.Clean(o.Origin)
	if !filepath.IsAbs(origin) || !under(origin, userDir) {
		return fmt.Errorf(i18n.T("каталог данных должен лежать в профиле основной учётки (%s)"), userDir)
	}
	rel, err := filepath.Rel(userDir, origin)
	if err != nil || !filepath.IsLocal(rel) {
		return errors.New(i18n.T("недопустимый каталог данных"))
	}
	dataDir := o.DataDir
	if dataDir == "" {
		dataDir = filepath.Base(origin)
	}
	if !filepath.IsLocal(dataDir) || strings.ContainsAny(dataDir, `\/`) {
		return errors.New(i18n.T("имя папки данных не должно содержать путь"))
	}
	hasData := false
	for _, a := range o.Args {
		hasData = hasData || strings.Contains(a, "{data_path}")
	}
	if !hasData {
		return errors.New(`в аргументах запуска нужен {data_path}: приложение должно писать данные в рабочую папку, а не в профиль vault (например -arg "--user-data-dir={data_path}\data")`)
	}
	if _, err := os.Stat(isolation.VaultDir()); err != nil {
		return errors.New(i18n.T("защищённой папки нет: сначала install"))
	}
	v := vault.Vault{Dir: isolation.DataPath(o.Name), DataName: workDataName}
	if v.Exists() {
		return fmt.Errorf(i18n.T("приложение %s уже защищено"), o.Name)
	}
	if _, err := os.Stat(isolation.WorkPath(o.Name)); err == nil {
		return fmt.Errorf(i18n.T("в %s есть данные без хранилища: разберитесь с ними вручную"), v.Dir)
	}
	if _, err := os.Stat(filepath.Join(isolation.ProfilesDir(), o.Name+".json")); err == nil {
		return fmt.Errorf(i18n.T("профиль %s уже есть"), o.Name)
	}
	if err := decoy.NoReparse(origin); err != nil {
		return err
	}

	p := profiles.Profile{Name: o.Name, Title: o.Name, DataDir: dataDir, LaunchArgs: o.Args, Origin: rel, Custom: true, Decoy: "generic"}
	signer, serr := audit.Signer(o.Exe)
	signerText := i18n.T("НЕ ПОДПИСАНО")
	if serr == nil {
		p.Publisher, signerText = signer, signer
	}
	info := fmt.Sprintf(i18n.T("Приложение: %s\nИздатель (подпись): %s\nДанные: %s -> защищённая рабочая папка\nАргументы: %s\n"),
		o.Exe, signerText, origin, strings.Join(o.Args, " "))
	for _, env := range []string{"OneDrive", "OneDriveConsumer", "OneDriveCommercial"} {
		if root := os.Getenv(env); root != "" && under(origin, root) {
			info += i18n.T("ВНИМАНИЕ: каталог данных внутри OneDrive: он синхронизируется в облако в открытом виде, пока приложение работает.\n")
			break
		}
	}
	if o.CopyDir || !inProtectedRoot(o.Exe) {
		info += i18n.Tf("Приложение лежит там, где его может заменить обычная учётка: его копия будет помещена в каталог SessionVault (после обновления приложения: sessionvault refresh %s).\n", o.Name)
	}
	info += i18n.T("Оно будет запускаться под собственной учёткой sv-<имя> с доступом к своим расшифрованным данным.\n")
	if !confirm(info) {
		return ErrNotConfirmed
	}
	pw, err := askPassword()
	if err != nil {
		return err
	}
	defer crypto.Wipe(pw)

	appDir := filepath.Join(InstallDir(), "apps", o.Name)
	if err := placeExe(&p, o.Exe, o.CopyDir); err != nil {
		return err
	}

	_, statErr := os.Stat(origin)
	hadData := statErr == nil
	work := filepath.Join(isolation.WorkPath(o.Name), dataDir)
	done, moved := false, false
	defer func() {
		if done {
			return
		}
		if moved {
			_ = os.Rename(work, origin)
		}
		_ = os.RemoveAll(v.Dir)
		_ = os.Remove(filepath.Join(isolation.ProfilesDir(), o.Name+".json"))
		_ = os.RemoveAll(appDir)
		_ = UpdateConfig(func(c *Config) { delete(c.Origins, o.Name) })
	}()
	// Исходное место нужно удалению программы, чтобы вернуть данные; пишем до переноса.
	err = UpdateConfig(func(c *Config) {
		if c.Origins == nil {
			c.Origins = map[string]string{}
		}
		c.Origins[o.Name] = origin
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(work), 0o755); err != nil {
		return err
	}
	if hadData {
		release, err := isolation.PinParent(origin)
		if err != nil {
			return err
		}
		defer release()
		if err := os.Rename(origin, work); err != nil {
			return fmt.Errorf(i18n.T("не удалось перенести данные (закройте приложение и повторите): %w"), err)
		}
		moved = true
	} else {
		if err := os.MkdirAll(work, 0o755); err != nil {
			return err
		}
		// Пустой архив считался бы потерей данных: приложению нужен хотя бы один файл.
		if err := os.WriteFile(filepath.Join(work, "First Run"), nil, 0o644); err != nil {
			return err
		}
	}
	if err := profiles.Save(isolation.ProfilesDir(), p); err != nil {
		return err
	}
	if err := isolation.ProtectDir(v.Dir); err != nil {
		return err
	}
	dek, err := v.Create(pw)
	if err != nil {
		return err
	}
	defer crypto.Wipe(dek)
	if err := v.Encrypt(dek); err != nil {
		return err
	}
	check, err := v.Unlock(pw)
	if err != nil {
		return fmt.Errorf(i18n.T("хранилище не открывается после создания: %w"), err)
	}
	crypto.Wipe(check)
	done = true
	return nil
}

// staleCopies — приложения, у которых есть копия под vault (Discord и добавленные через add), и среди них те, чьё
// исходное приложение обновилось. Только чтение: профили и пути исходников.
func staleCopies(mainUser string) (total int, stale []string) {
	entries, err := os.ReadDir(isolation.ProfilesDir())
	if err != nil {
		return 0, nil
	}
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok {
			continue
		}
		p, err := profiles.Load(isolation.ProfilesDir(), name)
		if err != nil || p.Source == "" {
			continue
		}
		total++
		if name == "discord" {
			if dir, err := findDiscordDir(mainUser); err == nil && !strings.EqualFold(dir, p.Source) {
				stale = append(stale, name)
			}
			continue
		}
		src, err1 := os.Stat(filepath.Join(p.Source, filepath.Base(p.Exe)))
		cp, err2 := os.Stat(p.Exe)
		if err1 == nil && err2 == nil && src.ModTime().After(cp.ModTime()) {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	return total, stale
}

// customProfile строит профиль собственного приложения из файла экспорта. Файл приходит со стороны, поэтому из него берётся
// только описание (имя папки данных, аргументы, путь данных): запуск и права задаёт этот ПК, а аргументы и издателя
// администратор подтверждает глазами.
func customProfile(b bundle, c CustomImport) (profiles.Profile, error) {
	var p profiles.Profile
	if c.Exe == "" {
		return p, errors.New(i18n.T("приложение добавлено командой add: укажите, где оно лежит на этом ПК: sessionvault import -exe <путь к .exe> [-copy-dir] <файл>"))
	}
	if !profiles.ValidName(b.App) {
		return p, errors.New(i18n.T("в файле недопустимое имя приложения"))
	}
	if !filepath.IsAbs(c.Exe) || !strings.EqualFold(filepath.Ext(c.Exe), ".exe") {
		return p, errors.New(i18n.T("укажите полный путь к .exe"))
	}
	if _, err := os.Stat(c.Exe); err != nil {
		return p, fmt.Errorf(i18n.T("%s не найден"), c.Exe)
	}
	p = *b.Profile
	p.Name, p.Custom, p.Decoy = b.App, true, "generic"
	p.Exe, p.Source, p.Sig, p.ExecFiles, p.ExecSigner, p.Exclude = "", "", "", nil, "", nil
	if p.DataDir == "" || !filepath.IsLocal(p.DataDir) || strings.ContainsAny(p.DataDir, `\/`) {
		return p, errors.New(i18n.T("в файле недопустимая папка данных"))
	}
	if p.Origin == "" || !filepath.IsLocal(p.Origin) {
		return p, errors.New(i18n.T("в файле недопустимый путь данных"))
	}
	hasData := false
	for _, a := range p.LaunchArgs {
		hasData = hasData || strings.Contains(a, "{data_path}")
	}
	if !hasData {
		return p, errors.New(i18n.T("в аргументах запуска из файла нет {data_path}"))
	}
	signer, err := audit.Signer(c.Exe)
	signerText := i18n.T("НЕ ПОДПИСАНО")
	switch {
	case err == nil:
		signerText = signer
		if p.Publisher != "" && !strings.EqualFold(p.Publisher, signer) {
			return p, fmt.Errorf(i18n.T("%s подписан %q, а в файле издатель %q"), c.Exe, signer, p.Publisher)
		}
		p.Publisher = signer
	case p.Publisher != "":
		return p, fmt.Errorf(i18n.T("%s не подписан, а в файле издатель %q"), c.Exe, p.Publisher)
	}
	info := fmt.Sprintf(i18n.T("Приложение %s из файла экспорта.\nИсполняемый файл на этом ПК: %s\nИздатель (подпись): %s\nДанные: профиль основной учётки\\%s\nАргументы запуска из файла: %s\n"),
		b.App, c.Exe, signerText, p.Origin, strings.Join(p.LaunchArgs, " "))
	if c.Confirm == nil || !c.Confirm(info) {
		return p, ErrNotConfirmed
	}
	return p, nil
}
