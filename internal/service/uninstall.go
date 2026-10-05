package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/loar32/sessionvault/internal/asr"
	"github.com/loar32/sessionvault/internal/audit"
	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/decoy"
	"github.com/loar32/sessionvault/internal/hardening"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"github.com/loar32/sessionvault/internal/vault"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Uninstall возвращает данные приложений на прежние места в расшифрованном виде и только потом убирает всё остальное.
// Любая ошибка до конца возврата данных прерывает удаление: данные пользователя не должны остаться заблокированными.
func Uninstall(password []byte) (err error) {
	if !isolation.IsElevated() {
		return errors.New("нужен запуск от администратора")
	}
	if err := isolation.EnablePrivileges("SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege", "SeSecurityPrivilege"); err != nil {
		return err
	}
	cfg, err := LoadConfig()
	if os.IsNotExist(err) {
		return nil // уже удалено: установщик может вызвать нас повторно
	}
	if err != nil {
		return fmt.Errorf("конфигурация не прочитана: %w", err)
	}
	user, _, _, err := windows.LookupSID("", cfg.MainUser)
	if err != nil {
		return fmt.Errorf("учётка %q не найдена: %w", cfg.MainUser, err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()

	wasRunning, err := stopService(m)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil && wasRunning {
			_ = startService(m)
		}
	}()

	entries, err := os.ReadDir(isolation.VaultDir())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		v := vault.Vault{Dir: isolation.DataPath(e.Name()), DataName: filepath.Base(isolation.WorkPath(e.Name()))}
		if !v.Exists() {
			// Данные без метаданных (сбой посреди import-tdata): это может быть единственная копия сессии.
			if _, err := os.Stat(isolation.WorkPath(e.Name())); err == nil {
				return fmt.Errorf("профиль %s: данные без хранилища, удаление остановлено (папка %s)", e.Name(), v.Dir)
			}
			continue
		}
		if err = restoreProfile(cfg, user, e.Name(), v, password); err != nil {
			return fmt.Errorf("профиль %s: %w", e.Name(), err)
		}
	}

	// Данные возвращены: дальше откатываться нечему, ошибки не прерывают удаление.
	if cfg.AuditByUs {
		_ = audit.DisableFileSystem()
	}
	_ = audit.RestoreMemoryAudit(cfg.MemAuditPrev)
	_ = hardening.Revert(cfg.Hardening)
	_ = asr.Revert(cfg.ASR)
	if s, e := m.OpenService(Name); e == nil {
		_ = s.Delete()
		_ = s.Close()
	}
	_ = removeAutostart()
	// Флаг автопоказа окна проверки: после повторной установки окно снова должно показаться. Удаляется один файл, не папка:
	// путь идёт через профиль пользователя, а службе с правами SYSTEM нельзя рекурсивно чистить то, что он может подменить ссылкой.
	_ = os.Remove(filepath.Join(usersDir(), cfg.MainUser, `AppData\Local\SessionVault\check-shown`))
	removeBaseKeepingExchange()
	_ = isolation.AllowRemoteLogon(isolation.VaultUser)
	_ = isolation.DeleteUserProfile(isolation.VaultUser)
	_ = isolation.DeleteUser(isolation.VaultUser)
	_ = os.RemoveAll(filepath.Join(usersDir(), isolation.VaultUser)) // если штатное удаление профиля не справилось
	// Сам exe и деинсталлятор не трогаем: ими занимается установщик (Inno удалит файлы и каталог после нас).
	_ = os.RemoveAll(filepath.Join(InstallDir(), "apps"))
	return nil
}

func restoreProfile(cfg Config, user *windows.SID, name string, v vault.Vault, password []byte) error {
	p, err := profiles.Load(isolation.ProfilesDir(), name)
	if err != nil {
		return err
	}
	origin := cfg.Origins[name]
	if origin == "" {
		return errors.New("неизвестно, куда вернуть данные (не записан исходный путь)")
	}
	// Администратор переносит и удаляет файлы по пути из профиля пользователя: ссылка на нём увела бы это в чужую папку.
	if err := decoy.NoReparse(origin); err != nil {
		return err
	}
	dek, err := v.Unlock(password)
	if err != nil {
		return err
	}
	defer crypto.Wipe(dek)
	// Приманка занимает место, куда вернутся настоящие данные; чужую папку тут не трогаем: ниже её отложат в сторону.
	if err := decoy.Remove(name, origin); err != nil && !errors.Is(err, decoy.ErrForeign) {
		return err
	}
	// Открытая копия после сбоя свежее архива: её и возвращаем.
	if !v.NeedsRecovery() {
		if err := v.Decrypt(dek); err != nil {
			return err
		}
	}
	src := filepath.Join(isolation.WorkPath(name), p.DataDir)
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("в хранилище нет %s: %w", p.DataDir, err)
	}
	if _, err := os.Stat(origin); err == nil {
		// На месте уже что-то есть (например, Telegram создал новую папку): не затираем, а откладываем в сторону.
		aside := fmt.Sprintf("%s.sessionvault-%s", origin, time.Now().Format("20060102-150405"))
		if err := os.Rename(origin, aside); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(origin), 0o755); err != nil {
		return err
	}
	if err := os.Rename(src, origin); err != nil {
		return err
	}
	if err := isolation.GiveToUser(origin, user); err != nil {
		return err
	}
	return os.RemoveAll(v.Dir)
}

func stopService(m *mgr.Mgr) (wasRunning bool, err error) {
	s, err := m.OpenService(Name)
	if err != nil {
		return false, nil
	}
	defer func() { _ = s.Close() }()
	st, err := s.Query()
	if err != nil || st.State == svc.Stopped {
		return false, err
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return true, err
	}
	for range 60 {
		if st, err = s.Query(); err == nil && st.State == svc.Stopped {
			return true, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return true, errors.New("служба не остановилась за 30 секунд")
}

func startService(m *mgr.Mgr) error {
	s, err := m.OpenService(Name)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	return s.Start()
}

// В общей папке лежат файлы пользователя: при удалении программы они остаются, пока пользователь сам их не уберёт.
func removeBaseKeepingExchange() {
	base := isolation.BaseDir()
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(isolation.ExchangeDir()) {
			_ = os.RemoveAll(filepath.Join(base, e.Name()))
		}
	}
	_ = os.Remove(isolation.ExchangeDir()) // пустую папку убираем
	_ = os.Remove(base)
}
