package service

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/loar32/sessionvault/internal/audit"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

// Администратор обходит права файлов, поэтому защищать учётку-администратора бессмысленно.
var ErrMainUserAdmin = errors.New("основная учётка состоит в администраторах, защита не будет работать")

const runKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

func InstallDir() string {
	return filepath.Join(isolation.KnownDir(windows.FOLDERID_ProgramFiles, `C:\Program Files`), "SessionVault")
}

func installedExe() string { return filepath.Join(InstallDir(), "sessionvault.exe") }

func usersDir() string {
	return isolation.KnownDir(windows.FOLDERID_UserProfiles, `C:\Users`)
}

// Шаги установки обратимы: при ошибке откатываем уже сделанное, не оставляя полуустановленную систему.
type steps struct{ undo []func() }

func (s *steps) rollback() {
	for i := len(s.undo) - 1; i >= 0; i-- {
		s.undo[i]()
	}
}

// Где у пользователя лежит Telegram; пусто, если не нашли.
func findTelegram(user string) string {
	for _, p := range []string{
		filepath.Join(usersDir(), user, `AppData\Roaming\Telegram Desktop\Telegram.exe`),
		filepath.Join(isolation.KnownDir(windows.FOLDERID_ProgramFiles, `C:\Program Files`), `Telegram Desktop\Telegram.exe`),
		filepath.Join(isolation.KnownDir(windows.FOLDERID_ProgramFilesX86, `C:\Program Files (x86)`), `Telegram Desktop\Telegram.exe`),
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// Приложение запускает vault, а в профиль пользователя у него доступа нет: exe оттуда копируем в каталог программы.
func ensureReadableByVault(name, exe string) (string, error) {
	if !strings.HasPrefix(strings.ToLower(exe), strings.ToLower(usersDir())+`\`) {
		return exe, nil
	}
	dst := filepath.Join(InstallDir(), "apps", name, filepath.Base(exe))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	return dst, copyFile(exe, dst)
}

// Приложение запускается рядом с расшифрованными данными, поэтому подмену exe (копия берётся из профиля пользователя) ловим здесь.
// Если файла нет (Telegram ещё не установлен), проверять нечего: путь в профиле поправят вручную.
func verifyPublisher(p profiles.Profile) error {
	// Только для автотестов в ВМ: подставной Telegram там не подписан. Переменную задаёт сам администратор, запускающий установку.
	if p.Publisher == "" || os.Getenv("SESSIONVAULT_SKIP_SIGNATURE") == "1" {
		return nil
	}
	if _, err := os.Stat(p.Exe); err != nil {
		return nil
	}
	name, err := audit.Signer(p.Exe)
	if err != nil {
		return fmt.Errorf("%s: подпись не проверена: %w", p.Exe, err)
	}
	if !strings.EqualFold(name, p.Publisher) {
		return fmt.Errorf("%s подписан %q, ожидался %q", p.Exe, name, p.Publisher)
	}
	return nil
}

func Install(mainUser, telegramExe string) (err error) {
	if !isolation.IsElevated() {
		return errors.New("нужен запуск от администратора")
	}
	if err := isolation.EnablePrivileges("SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege"); err != nil {
		return err
	}
	if _, _, _, err := windows.LookupSID("", mainUser); err != nil {
		return fmt.Errorf("учётка %q не найдена: %w", mainUser, err)
	}
	admin, err := isolation.IsAdminUser(mainUser)
	if err != nil {
		return err
	}
	if admin {
		return fmt.Errorf("%w: %s", ErrMainUserAdmin, mainUser)
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	if s, err := m.OpenService(Name); err == nil {
		_ = s.Close()
		return errors.New("служба уже установлена")
	}

	var st steps
	defer func() {
		if err != nil {
			st.rollback()
		}
	}()

	_, statErr := os.Stat(isolation.BaseDir())
	existed := statErr == nil
	// Защита каталога данных ставится до записи секретов: всё созданное дальше наследует закрытый доступ.
	if err = os.MkdirAll(isolation.ProfilesDir(), 0o755); err != nil {
		return err
	}
	// Откатываем только созданное в этот запуск: при повторной установке в каталоге могут лежать чужие зашифрованные данные.
	if existed {
		fmt.Fprintln(os.Stderr, "каталог данных уже существует: прежние хранилища сохраняются")
	} else {
		st.undo = append(st.undo, func() { _ = os.RemoveAll(isolation.BaseDir()) })
	}
	if err = isolation.ProtectDir(isolation.BaseDir()); err != nil {
		return err
	}
	if !isolation.PasswordSaved() {
		var pw string
		if pw, err = isolation.GeneratePassword(); err != nil {
			return err
		}
		if err = isolation.CreateUser(isolation.VaultUser, pw); err != nil {
			return err
		}
		st.undo = append(st.undo, func() { _ = isolation.DeleteUser(isolation.VaultUser) })
		if err = isolation.SavePassword(pw); err != nil {
			return err
		}
	} else if !isolation.UserExists(isolation.VaultUser) {
		return errors.New("пароль vault сохранён, но учётки нет: удали vault.pwd и повтори")
	}
	if err = isolation.HideFromLogon(isolation.VaultUser); err != nil {
		return err
	}
	if err = isolation.DenyRemoteLogon(isolation.VaultUser); err != nil {
		return err
	}
	if err = isolation.SetupVaultDir(); err != nil {
		return err
	}
	// При повторной установке сохраняем исходные места данных: без них uninstall не вернёт сессии.
	cfg := Config{MainUser: mainUser, IdleMinutes: defaultIdleMinutes}
	if old, e := LoadConfig(); e == nil {
		cfg.Origins, cfg.AuditByUs, cfg.DecoyAllow, cfg.Hardening, cfg.ASR = old.Origins, old.AuditByUs, old.DecoyAllow, old.Hardening, old.ASR
	}
	if err = SaveConfig(cfg); err != nil {
		return err
	}

	if err = copySelf(); err != nil {
		return err
	}
	st.undo = append(st.undo, func() { _ = os.RemoveAll(InstallDir()) })

	if telegramExe == "" {
		if telegramExe = findTelegram(mainUser); telegramExe == "" {
			telegramExe = profiles.Telegram.Exe
			fmt.Fprintln(os.Stderr, "Telegram не найден: путь к нему можно поправить в", filepath.Join(isolation.ProfilesDir(), "telegram.json"))
		}
	}
	tg := profiles.Telegram
	if tg.Exe, err = ensureReadableByVault(tg.Name, telegramExe); err != nil {
		return err
	}
	if err = verifyPublisher(tg); err != nil {
		return err
	}
	if err = profiles.Save(isolation.ProfilesDir(), tg); err != nil {
		return err
	}

	if err = addAutostart(); err != nil {
		return err
	}
	st.undo = append(st.undo, func() { _ = removeAutostart() })

	s, err := m.CreateService(Name, installedExe(), mgr.Config{
		StartType:   mgr.StartAutomatic,
		DisplayName: "SessionVault",
		Description: "Защита сессий приложений от стилеров",
	}, "service")
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	st.undo = append(st.undo, func() { _ = s.Delete() })
	// После аварии служба поднимается сама; открытые данные при этом дошифровываются при следующем запуске приложения.
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10 * time.Second}}, 86400)
	return s.Start()
}

// Трей стартует при входе любого пользователя; чужим учётным записям pipe закрыт, там он покажет «служба недоступна».
func addAutostart() error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	return k.SetStringValue("SessionVaultTray", `"`+installedExe()+`" tray`)
}

func removeAutostart() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE)
	if err != nil {
		return nil
	}
	defer func() { _ = k.Close() }()
	return k.DeleteValue("SessionVaultTray")
}

func copySelf() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if strings.EqualFold(self, installedExe()) {
		return nil
	}
	return copyFile(self, installedExe())
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
