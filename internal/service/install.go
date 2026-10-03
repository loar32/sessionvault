package service

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func InstallDir() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "SessionVault")
}

func installedExe() string { return filepath.Join(InstallDir(), "sessionvault.exe") }

// Шаги установки обратимы: при ошибке откатываем уже сделанное, не оставляя полуустановленную систему.
type steps struct{ undo []func() }

func (s *steps) rollback() {
	for i := len(s.undo) - 1; i >= 0; i-- {
		s.undo[i]()
	}
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
		return fmt.Errorf("%s состоит в администраторах: администратор обходит права файлов, защита не будет работать", mainUser)
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

	// Защита каталога данных ставится до записи секретов: всё созданное дальше наследует закрытый доступ.
	if err = os.MkdirAll(isolation.ProfilesDir(), 0o755); err != nil {
		return err
	}
	st.undo = append(st.undo, func() { _ = os.RemoveAll(isolation.BaseDir()) })
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
	if err = isolation.SetupVaultDir(); err != nil {
		return err
	}
	if err = SaveConfig(Config{MainUser: mainUser, IdleMinutes: defaultIdleMinutes}); err != nil {
		return err
	}
	tg := profiles.Telegram
	tg.Exe = telegramExe
	if err = profiles.Save(isolation.ProfilesDir(), tg); err != nil {
		return err
	}

	if err = copySelf(); err != nil {
		return err
	}
	st.undo = append(st.undo, func() { _ = os.RemoveAll(InstallDir()) })

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

func copySelf() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(InstallDir(), 0o755); err != nil {
		return err
	}
	in, err := os.Open(self)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(installedExe(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
