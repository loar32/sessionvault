package service

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/ipc"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"github.com/loar32/sessionvault/internal/vault"
)

// Ключ FIDO2 — первый способ разблокировки (если включён): Windows просит вставить ключ, PIN и касание.
// Отмена окна, сбой или отсутствие ключа ведут дальше: к Windows Hello, затем к окну пароля.
func (s *Service) tryFido(name string, v vault.Vault, session uint32) ([]byte, bool) {
	credID, salt, ok := v.FidoInfo()
	if !ok {
		return nil, false
	}
	secret, err := s.helloSecret(session, "fido-unlock", hex.EncodeToString(credID), salt)
	if err != nil {
		s.log.Printf("%s: ключ FIDO2: %v", name, err)
		return nil, false
	}
	defer crypto.Wipe(secret)
	dek, err := v.UnlockFido(secret)
	if err != nil {
		s.log.Printf("%s: ключ FIDO2 не открыл хранилище: %v", name, err)
		return nil, false
	}
	s.log.Printf("%s: хранилище разблокировано ключом FIDO2", name)
	return dek, true
}

// Включение входа по ключу для профиля: мастер-пароль подтверждает владельца, затем ключ создаёт учётные данные
// и отдаёт секрет для случайной соли. Один и тот же ключ можно привязать ко всем профилям: у каждого свои учётные данные и соль.
func (s *Service) enableFido(c *ipc.Conn, name string) string {
	if _, err := profiles.Load(isolation.ProfilesDir(), name); err != nil {
		s.logRunFailure("fido %s: %v", name, err)
		return ipc.Failed
	}
	session, err := c.ClientSession()
	if err != nil || session == 0 {
		return ipc.Failed
	}
	v := vault.Vault{Dir: isolation.DataPath(name), DataName: workDataName}
	if !v.Exists() {
		return ipc.Failed
	}
	s.mu.Lock()
	if !s.admit(name, time.Now()) {
		s.mu.Unlock()
		return ipc.Busy
	}
	s.running[name] = true
	s.stopIdle()
	s.mu.Unlock()
	defer s.finish(name)

	dek, err := s.askPassword(name, v, session, false)
	if err != nil {
		s.log.Printf("fido %s: %v", name, err)
		if errors.Is(err, errBusy) {
			return ipc.Busy
		}
		return ipc.Failed
	}
	salt, err := crypto.NewKey()
	if err != nil {
		return ipc.Failed
	}
	fields, err := s.helperReply(session, "fido-enroll", "-", salt)
	if err != nil {
		s.log.Printf("fido %s: %v", name, err)
		return ipc.Failed
	}
	defer func() {
		for _, f := range fields {
			crypto.Wipe(f)
		}
	}()
	if len(fields) != 2 {
		s.log.Printf("fido %s: помощник вернул неверный ответ", name)
		return ipc.Failed
	}
	if err := v.EnableFido(dek, fields[1], salt, fields[0]); err != nil {
		s.log.Printf("fido %s: %v", name, err)
		return ipc.Failed
	}
	s.log.Printf("%s: вход по ключу FIDO2 включён", name)
	return ipc.Ok
}

// DisableFido убирает вход по ключу FIDO2 у профиля (или у всех, если имя пустое); пароль продолжает работать.
// Учётные данные на самом ключе не удаляются: их стирает только владелец ключа.
func DisableFido(profile string) error {
	if !isolation.IsElevated() {
		return errors.New("нужен запуск от администратора")
	}
	var names []string
	if profile != "" {
		names = []string{profile}
	} else {
		entries, err := os.ReadDir(isolation.VaultDir())
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.IsDir() && profiles.ValidName(e.Name()) {
				names = append(names, e.Name())
			}
		}
	}
	for _, n := range names {
		if !profiles.ValidName(n) {
			return fmt.Errorf("недопустимое имя профиля %q", n)
		}
		v := vault.Vault{Dir: isolation.DataPath(n), DataName: workDataName}
		if !v.Exists() {
			continue
		}
		if err := v.DisableFido(); err != nil {
			return fmt.Errorf("%s: %w", n, err)
		}
	}
	return nil
}
