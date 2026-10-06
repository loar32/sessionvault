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
	sid, _, _, err := windows.LookupSID("", isolation.VaultUser)
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
	sid, _, _, err := windows.LookupSID("", isolation.VaultUser)
	if err != nil {
		return errors.New("учётки vault нет: сначала install")
	}
	if off {
		return errors.Join(lockdown.RemoveFirewall(), lockdown.AllowInterpreters(sid))
	}
	if _, err := os.Stat(installedExe()); err != nil {
		return errors.New("SessionVault не установлен: сначала install")
	}
	return errors.Join(lockdown.ApplyFirewall(sid, installedExe(), isolation.BaseDir()), lockdown.DenyInterpreters(sid))
}
