package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"github.com/loar32/sessionvault/internal/vault"
	"golang.org/x/sys/windows"
)

// Unprotect снимает защиту с одного приложения: данные расшифровываются и возвращаются на прежнее место, профиль, учётка
// sv-<имя> и копия приложения удаляются. Остальные приложения и служба не затрагиваются.
func Unprotect(name string, password []byte) error {
	if !isolation.IsElevated() {
		return errors.New("нужен запуск от администратора")
	}
	if !profiles.ValidName(name) {
		return fmt.Errorf("недопустимое имя приложения %q", name)
	}
	if err := isolation.EnablePrivileges("SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege"); err != nil {
		return err
	}
	cfg, err := LoadConfig()
	if err != nil {
		return fmt.Errorf("конфигурация не прочитана: %w", err)
	}
	user, _, _, err := windows.LookupSID("", cfg.MainUser)
	if err != nil {
		return fmt.Errorf("учётка %q не найдена: %w", cfg.MainUser, err)
	}
	p, err := profiles.Load(isolation.ProfilesDir(), name)
	if err != nil {
		return fmt.Errorf("приложение %s не защищено: %w", name, err)
	}
	v := vault.Vault{Dir: isolation.DataPath(name), DataName: workDataName, Exclude: p.Exclude}
	if !v.Exists() {
		return fmt.Errorf("хранилища %s нет", name)
	}
	// Запущенное приложение держит running.lock; пока оно открыто, данные возвращать нельзя.
	release, err := v.Lock()
	if err != nil {
		return fmt.Errorf("%s запущено или не завершено: закройте его и повторите", name)
	}
	release()
	if err := restoreProfile(cfg, user, name, v, password); err != nil {
		return err
	}
	// Данные возвращены: дальше откатываться нечему, остальное убирается по возможности.
	_ = os.Remove(filepath.Join(isolation.ProfilesDir(), name+".json"))
	_ = UpdateConfig(func(c *Config) { delete(c.Origins, name) })
	_ = isolation.DeleteAppAccount(isolation.AccountName(name))
	_ = os.RemoveAll(filepath.Join(InstallDir(), "apps", name))
	if p.Exe != "" {
		werRemoveOne(p.Exe)
	}
	SyncService()
	return nil
}

func werRemoveOne(exe string) {
	if name, err := windows.UTF16PtrFromString(filepath.Base(exe)); err == nil {
		_, _, _ = pWerRemove.Call(uintptr(unsafe.Pointer(name)), 1)
	}
}
