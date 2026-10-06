package service

import (
	"errors"
	"fmt"
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
		return "", errors.New(`Discord не найден: он ставится в профиль пользователя (AppData\Local\Discord)`)
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

// RefreshApp копирует каталог приложения заново (после обновления самого приложения): обновляется только копия под vault.
// Приложение должно быть закрыто.
func RefreshApp(name string) error {
	if !isolation.IsElevated() {
		return errors.New("нужен запуск от администратора")
	}
	if err := isolation.EnablePrivileges("SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege"); err != nil {
		return err
	}
	p, err := profiles.Load(isolation.ProfilesDir(), name)
	if err != nil {
		return err
	}
	if p.Source == "" {
		return fmt.Errorf("%s не копируется под vault: обновлять нечего", name)
	}
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	v := vault.Vault{Dir: isolation.DataPath(name), DataName: workDataName}
	release, err := v.Lock()
	if err != nil {
		return errors.New("приложение запущено: закройте его и повторите")
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
		return errors.New("нужен запуск от администратора")
	}
	if err := isolation.EnablePrivileges("SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege"); err != nil {
		return err
	}
	cfg, err := LoadConfig()
	if err != nil {
		return fmt.Errorf("конфигурация не прочитана: сначала install: %w", err)
	}
	if !profiles.ValidName(o.Name) {
		return errors.New("имя: от 1 до 32 символов, строчные латинские буквы, цифры и дефис")
	}
	if _, ok := profiles.Template(o.Name); ok {
		return fmt.Errorf("имя %q занято встроенным приложением: используйте sessionvault protect %s", o.Name, o.Name)
	}
	if !filepath.IsAbs(o.Exe) || !strings.EqualFold(filepath.Ext(o.Exe), ".exe") {
		return errors.New("укажите полный путь к .exe")
	}
	if _, err := os.Stat(o.Exe); err != nil {
		return fmt.Errorf("%s не найден", o.Exe)
	}
	userDir := filepath.Join(usersDir(), cfg.MainUser)
	origin := filepath.Clean(o.Origin)
	if !filepath.IsAbs(origin) || !under(origin, userDir) {
		return fmt.Errorf("каталог данных должен лежать в профиле основной учётки (%s)", userDir)
	}
	rel, err := filepath.Rel(userDir, origin)
	if err != nil || !filepath.IsLocal(rel) {
		return errors.New("недопустимый каталог данных")
	}
	dataDir := o.DataDir
	if dataDir == "" {
		dataDir = filepath.Base(origin)
	}
	if !filepath.IsLocal(dataDir) || strings.ContainsAny(dataDir, `\/`) {
		return errors.New("имя папки данных не должно содержать путь")
	}
	hasData := false
	for _, a := range o.Args {
		hasData = hasData || strings.Contains(a, "{data_path}")
	}
	if !hasData {
		return errors.New(`в аргументах запуска нужен {data_path}: приложение должно писать данные в рабочую папку, а не в профиль vault (например -arg "--user-data-dir={data_path}\data")`)
	}
	if _, err := os.Stat(isolation.VaultDir()); err != nil {
		return errors.New("защищённой папки нет: сначала install")
	}
	v := vault.Vault{Dir: isolation.DataPath(o.Name), DataName: workDataName}
	if v.Exists() {
		return fmt.Errorf("приложение %s уже защищено", o.Name)
	}
	if _, err := os.Stat(isolation.WorkPath(o.Name)); err == nil {
		return fmt.Errorf("в %s есть данные без хранилища: разберитесь с ними вручную", v.Dir)
	}
	if _, err := os.Stat(filepath.Join(isolation.ProfilesDir(), o.Name+".json")); err == nil {
		return fmt.Errorf("профиль %s уже есть", o.Name)
	}
	if err := decoy.NoReparse(origin); err != nil {
		return err
	}

	p := profiles.Profile{Name: o.Name, Title: o.Name, DataDir: dataDir, LaunchArgs: o.Args, Origin: rel, Custom: true}
	signer, serr := audit.Signer(o.Exe)
	signerText := "НЕ ПОДПИСАНО"
	if serr == nil {
		p.Publisher, signerText = signer, signer
	}
	info := fmt.Sprintf("Приложение: %s\nИздатель (подпись): %s\nДанные: %s -> защищённая рабочая папка\nАргументы: %s\n",
		o.Exe, signerText, origin, strings.Join(o.Args, " "))
	for _, env := range []string{"OneDrive", "OneDriveConsumer", "OneDriveCommercial"} {
		if root := os.Getenv(env); root != "" && under(origin, root) {
			info += "ВНИМАНИЕ: каталог данных внутри OneDrive: он синхронизируется в облако в открытом виде, пока приложение работает.\n"
			break
		}
	}
	if o.CopyDir || !inProtectedRoot(o.Exe) {
		info += "Приложение лежит там, где его может заменить обычная учётка: его копия будет помещена в каталог SessionVault (после обновления приложения: sessionvault refresh " + o.Name + ").\n"
	}
	info += "Оно будет запускаться под учёткой vault с доступом к своим расшифрованным данным.\n"
	if !confirm(info) {
		return ErrNotConfirmed
	}
	pw, err := askPassword()
	if err != nil {
		return err
	}
	defer crypto.Wipe(pw)

	p.Exe = o.Exe
	appDir := filepath.Join(InstallDir(), "apps", o.Name)
	switch {
	case o.CopyDir:
		if err := installCopy(&p, filepath.Dir(o.Exe), filepath.Base(o.Exe)); err != nil {
			return err
		}
	case !inProtectedRoot(o.Exe):
		dst := filepath.Join(appDir, filepath.Base(o.Exe))
		if err := os.MkdirAll(appDir, 0o755); err != nil {
			return err
		}
		if err := copyFile(o.Exe, dst); err != nil {
			return err
		}
		p.Exe, p.Source = dst, filepath.Dir(o.Exe)
		if err := verifyPublisher(p); err != nil {
			_ = os.RemoveAll(appDir)
			return err
		}
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
		if err := os.Rename(origin, work); err != nil {
			return fmt.Errorf("не удалось перенести данные (закройте приложение и повторите): %w", err)
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
		return fmt.Errorf("хранилище не открывается после создания: %w", err)
	}
	crypto.Wipe(check)
	done = true
	return nil
}
