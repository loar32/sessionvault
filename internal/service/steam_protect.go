package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/decoy"
	"github.com/loar32/sessionvault/internal/i18n"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"github.com/loar32/sessionvault/internal/vault"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Кэши встроенного браузера Steam пересоздаются сами: шифровать их незачем.
var steamLocalExclude = []string{
	`htmlcache\Default\Cache`, `htmlcache\Default\Code Cache`, `htmlcache\Default\GPUCache`,
	`htmlcache\Default\DawnGraphiteCache`, `htmlcache\Default\DawnWebGPUCache`, `htmlcache\Default\Service Worker\CacheStorage`,
	`htmlcache\GrShaderCache`, `htmlcache\ShaderCache`, `htmlcache\GraphiteDawnCache`, `htmlcache\BrowserMetrics`,
	`htmlcache\Crashpad`, `htmlcache\component_crx_cache`, `htmlcache\Safe Browsing`, `htmlcache\segmentation_platform`,
}

// steamDir — каталог клиента основной учётки: путь из её реестра, иначе обычное место.
func steamDir(user *windows.SID) string {
	if k, err := registry.OpenKey(registry.USERS, user.String()+`\Software\Valve\Steam`, registry.QUERY_VALUE); err == nil {
		defer func() { _ = k.Close() }()
		if s, _, err := k.GetStringValue("SteamPath"); err == nil && s != "" {
			return filepath.Clean(filepath.FromSlash(s))
		}
	}
	return filepath.Join(isolation.KnownDir(windows.FOLDERID_ProgramFilesX86, `C:\Program Files (x86)`), "Steam")
}

// steamProfile — профиль Steam с местами сессии этой установки клиента.
func steamProfile(mainUser string, user *windows.SID) profiles.Profile {
	dir := steamDir(user)
	p := profiles.Steam
	p.Exe = filepath.Join(dir, "steam.exe")
	p.Places = []profiles.Place{
		{Path: filepath.Join(dir, "config"), Decoy: "steamconfig"},
		{Path: filepath.Join(usersDir(), mainUser, `AppData\Local\Steam`), Decoy: "steamlocal", Exclude: steamLocalExclude},
		{Path: dir, Files: []string{"ssfn*"}},
	}
	return p
}

// ProtectSteam переносит файлы сессии Steam в зашифрованное хранилище и оставляет на их местах приманку. Steam должен быть
// закрыт; сам клиент и игры остаются в учётке пользователя. askPassword спрашивает мастер-пароль нового хранилища.
func ProtectSteam(askPassword func() ([]byte, error)) (err error) {
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
	user, _, _, err := windows.LookupSID("", cfg.MainUser)
	if err != nil {
		return fmt.Errorf(i18n.T("учётка %q не найдена: %w"), cfg.MainUser, err)
	}
	p := steamProfile(cfg.MainUser, user)
	if _, err := os.Stat(p.Exe); err != nil {
		return fmt.Errorf(i18n.T("%s не найден (%s): сначала установите приложение"), p.Title, p.Exe)
	}
	if err := verifyPublisher(p); err != nil {
		return err
	}
	if _, err := os.Stat(isolation.VaultDir()); err != nil {
		return errors.New(i18n.T("защищённой папки нет: сначала install"))
	}
	v := vault.Vault{Dir: isolation.DataPath(p.Name), DataName: workDataName}
	if v.Exists() {
		return fmt.Errorf(i18n.T("%s уже защищён"), p.Title)
	}
	if _, err := os.Stat(isolation.WorkPath(p.Name)); err == nil {
		return fmt.Errorf(i18n.T("в %s есть данные без хранилища: разберитесь с ними вручную"), v.Dir)
	}
	if anyProcess(steamProcesses) {
		return errors.New(i18n.T("закройте Steam (в том числе из трея) и повторите"))
	}
	for _, pl := range p.Places {
		if err := decoy.NoReparse(pl.Path); err != nil {
			return err
		}
	}
	pw, err := askPassword()
	if err != nil {
		return err
	}
	defer crypto.Wipe(pw)

	done := false
	defer func() {
		if !done {
			_ = os.RemoveAll(v.Dir)
			_ = os.Remove(filepath.Join(isolation.ProfilesDir(), p.Name+".json"))
		}
	}()
	if err := profiles.Save(isolation.ProfilesDir(), p); err != nil {
		return err
	}
	if err := os.MkdirAll(isolation.WorkPath(p.Name), 0o755); err != nil {
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
	for i, pl := range p.Places {
		files, err := readPlace(pl)
		if err != nil {
			return err
		}
		if err := stageWrite(p.Name, i, files); err != nil {
			return err
		}
	}
	if err := v.Encrypt(dek); err != nil {
		return err
	}
	check, err := v.Unlock(pw)
	if err != nil {
		return fmt.Errorf(i18n.T("хранилище не открывается после создания: %w"), err)
	}
	crypto.Wipe(check)
	done = true
	// Данные в хранилище проверены: места освобождаются, приманку кладёт служба.
	var errs []error
	for _, pl := range p.Places {
		if err := removePlace(pl); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// restorePlacesAdmin возвращает данные Steam на места при снятии защиты и удалении программы: приманка убирается, файлы
// переходят пользователю. Выполняется от администратора после проверки путей на ссылки.
func restorePlacesAdmin(user *windows.SID, p profiles.Profile, v vault.Vault, password []byte) error {
	for _, pl := range p.Places {
		if err := decoy.NoReparse(pl.Path); err != nil {
			return err
		}
	}
	dek, err := v.Unlock(password)
	if err != nil {
		return err
	}
	defer crypto.Wipe(dek)
	// Открытая копия после сбоя свежее архива; файлы, оставшиеся на местах, свежее неё.
	if v.NeedsRecovery() {
		for i, pl := range p.Places {
			if pl.Decoy != "" && decoy.Owned(placeKey(p.Name, i), pl.Path) {
				continue
			}
			if placeHasData(pl) {
				files, err := readPlace(pl)
				if err != nil {
					return err
				}
				if err := stageWrite(p.Name, i, files); err != nil {
					return err
				}
			}
		}
	} else if err := v.Decrypt(dek); err != nil {
		return err
	}
	if err := isolation.ProtectDir(isolation.WorkPath(p.Name)); err != nil {
		return err
	}
	for i, pl := range p.Places {
		key := placeKey(p.Name, i)
		if pl.Decoy != "" {
			if err := decoy.Remove(key, pl.Path); err != nil && !errors.Is(err, decoy.ErrForeign) {
				return err
			}
		}
		if placeHasData(pl) {
			// Свои данные пользователя уже на месте (Steam запускали без защиты): оставляем их.
			continue
		}
		files, err := stageRead(p.Name, i)
		if err != nil {
			return err
		}
		if err := writePlace(pl, files); err != nil {
			return err
		}
		// Каталог клиента целиком не трогаем: владельцем становится пользователь только у возвращённого.
		owned := []string{pl.Path}
		if len(pl.Files) > 0 {
			owned = matches(pl)
		}
		for _, p := range owned {
			if err := isolation.GiveToUser(p, user); err != nil {
				return err
			}
		}
	}
	return os.RemoveAll(v.Dir)
}
