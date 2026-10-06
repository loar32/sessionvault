package service

import (
	"errors"
	"os"

	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/lockdown"
	"golang.org/x/sys/windows"
)

// Запрет запуска интерпретаторов для vault ставится перед каждым запуском приложения: обновление Windows заменяет файлы
// и сбрасывает права. Сбой не мешает запуску: приложение остаётся под сетевыми правилами и запретом запуска из рабочей папки.
func (s *Service) denyInterpreters() {
	sid, err := isolation.AppsGroupSID()
	if err != nil {
		return
	}
	if err := isolation.EnablePrivileges("SeRestorePrivilege", "SeBackupPrivilege"); err != nil {
		s.log.Printf("запрет интерпретаторов: %v", err)
		return
	}
	if err := lockdown.DenyInterpreters(sid); err != nil {
		s.log.Printf("запрет интерпретаторов: %v", err)
	}
}

// Lockdown включает (off=false) или снимает сетевой заслон: правила брандмауэра и запрет интерпретаторов для vault.
func Lockdown(off bool) error {
	if !isolation.IsElevated() {
		return errors.New("нужен запуск от администратора")
	}
	if err := isolation.EnablePrivileges("SeRestorePrivilege", "SeBackupPrivilege"); err != nil {
		return err
	}
	if off {
		var errs []error
		if sid, err := isolation.AppsGroupSID(); err == nil {
			errs = append(errs, lockdown.AllowInterpreters(sid))
		}
		if sid, _, _, err := windows.LookupSID("", isolation.LegacyVaultUser); err == nil {
			errs = append(errs, lockdown.AllowInterpreters(sid))
		}
		return errors.Join(append(errs, lockdown.RemoveFirewall())...)
	}
	sid, err := isolation.EnsureAppsGroup()
	if err != nil {
		return err
	}
	if _, err := os.Stat(installedExe()); err != nil {
		return errors.New("SessionVault не установлен: сначала install")
	}
	return errors.Join(lockdown.ApplyFirewall(sid, installedExe(), isolation.BaseDir()), lockdown.DenyInterpreters(sid))
}

// migrateLegacyVault заменяет общую учётку vault прежних версий: снимает с неё запреты на интерпретаторы и удаляет учётку и пароль.
// Хранилища не затрагиваются: на диске только шифр, а рабочие папки получают права учёток приложений при запуске.
func migrateLegacyVault() {
	sid, _, _, err := windows.LookupSID("", isolation.LegacyVaultUser)
	if err != nil {
		isolation.RemoveLegacyPassword()
		return
	}
	_ = lockdown.AllowInterpreters(sid)
	if isolation.DeleteAppAccount(isolation.LegacyVaultUser) == nil {
		isolation.RemoveLegacyPassword()
	}
}

// migrate выполняется при старте службы после замены программы без переустановки (прежняя версия оставила учётку vault и не
// создала группу приложений): создаёт группу и права общей папки, переносит правила на группу, удаляет vault.
// Установка делает то же сама, поэтому здесь работа есть только при обновлении на месте.
func (s *Service) migrate() {
	_, groupErr := isolation.AppsGroupSID()
	legacy := isolation.UserExists(isolation.LegacyVaultUser)
	if groupErr == nil && !legacy {
		isolation.RemoveLegacyPassword()
		return
	}
	if groupErr != nil {
		if err := isolation.SetupExchange(s.cfg.MainUser); err != nil {
			s.log.Println("переход на учётки приложений: общая папка:", err)
		}
		if err := Lockdown(false); err != nil {
			s.log.Println("переход на учётки приложений: сетевой заслон:", err)
		}
	}
	migrateLegacyVault()
	s.log.Println("переход с общей учётки vault на учётки приложений выполнен")
}
