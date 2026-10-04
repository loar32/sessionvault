package service

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/ipc"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"github.com/loar32/sessionvault/internal/vault"
	"golang.org/x/sys/windows"
)

const (
	// Один ключ Hello на пользователя; у каждого профиля свой challenge, поэтому и секреты у профилей разные.
	helloKeyName     = "SessionVault"
	helloStartWait   = 30 * time.Second // помощник должен подключиться
	helloGestureWait = 90 * time.Second // пользователь делает жест (палец, лицо, PIN)
	maxHelloLine     = 1024
)

// Секрет от Windows Hello получает помощник под токеном пользователя (ключ Hello принадлежит ему, а не SYSTEM) и отдаёт службе
// по случайному pipe. Pipe открыт только SYSTEM и пользователю сессии, подключиться должен именно запущенный нами процесс.
// mode: hello-unlock (ключ уже есть) или hello-enroll (создать, если ещё нет).
func (s *Service) helloSecret(session uint32, mode, keyName string, challenge []byte) ([]byte, error) {
	sid, err := isolation.SessionUserSID(session)
	if err != nil {
		return nil, err
	}
	tail, err := crypto.NewSalt()
	if err != nil {
		return nil, err
	}
	pipe := ipc.UnlockPipe + hex.EncodeToString(tail)
	l, err := ipc.Listen(pipe, "D:P(A;;GA;;;SY)(A;;GRGW;;;"+sid+")")
	if err != nil {
		return nil, err
	}
	defer l.Close()
	pid, proc, err := isolation.StartAsSessionUser(session, fmt.Sprintf(`"%s" %s %s`, s.exe, mode, pipe))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = windows.TerminateProcess(proc, 0)
		_ = windows.CloseHandle(proc)
	}()
	c, err := l.Accept(helloStartWait)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if cp, err := c.ClientPID(); err != nil || cp != pid {
		return nil, errors.New("к pipe Hello подключился чужой процесс")
	}
	if err := c.WriteLine(keyName + " " + hex.EncodeToString(challenge)); err != nil {
		return nil, err
	}
	reply, err := c.ReadBytes(helloGestureWait, maxHelloLine)
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(reply)
	if !strings.HasPrefix(string(reply), "ok ") {
		return nil, errors.New(strings.TrimSpace(string(reply)))
	}
	secret := make([]byte, hex.DecodedLen(len(reply)-3))
	n, err := hex.Decode(secret, reply[3:])
	if err != nil || n == 0 {
		crypto.Wipe(secret)
		return nil, errors.New("помощник Hello вернул неверный ответ")
	}
	return secret[:n], nil
}

// Hello — первый способ разблокировки; отмена, сбой или отсутствие Hello возвращают к окну пароля.
func (s *Service) tryHello(name string, v vault.Vault, session uint32) ([]byte, bool) {
	keyName, challenge, ok := v.HelloInfo()
	if !ok {
		return nil, false
	}
	secret, err := s.helloSecret(session, "hello-unlock", keyName, challenge)
	if err != nil {
		s.log.Printf("%s: Windows Hello: %v", name, err)
		return nil, false
	}
	defer crypto.Wipe(secret)
	dek, err := v.UnlockHello(secret)
	if err != nil {
		s.log.Printf("%s: Windows Hello не открыл хранилище: %v", name, err)
		return nil, false
	}
	s.log.Printf("%s: хранилище разблокировано через Windows Hello", name)
	return dek, true
}

// Включение Hello для профиля: мастер-пароль (окно пароля) подтверждает владельца, затем Hello создаёт ключ и подписывает challenge.
func (s *Service) enableHello(c *ipc.Conn, name string) string {
	if _, err := profiles.Load(isolation.ProfilesDir(), name); err != nil {
		s.logRunFailure("hello %s: %v", name, err)
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
		s.log.Printf("hello %s: %v", name, err)
		if errors.Is(err, errBusy) {
			return ipc.Busy
		}
		return ipc.Failed
	}
	challenge, err := crypto.NewKey()
	if err != nil {
		return ipc.Failed
	}
	secret, err := s.helloSecret(session, "hello-enroll", helloKeyName, challenge)
	if err != nil {
		s.log.Printf("hello %s: %v", name, err)
		return ipc.Failed
	}
	defer crypto.Wipe(secret)
	if err := v.EnableHello(dek, helloKeyName, challenge, secret); err != nil {
		s.log.Printf("hello %s: %v", name, err)
		return ipc.Failed
	}
	s.log.Printf("%s: вход через Windows Hello включён", name)
	return ipc.Ok
}

// DisableHello убирает вход через Windows Hello у профиля (или у всех, если имя пустое); пароль продолжает работать.
// Ключ Hello в профиле пользователя не удаляется: это может сделать только его владелец, а ключ общий для профилей.
func DisableHello(profile string) error {
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
		if err := v.DisableHello(); err != nil {
			return fmt.Errorf("%s: %w", n, err)
		}
	}
	return nil
}
