package profiles

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RequireSignature включается программой (служба и команды): профиль без верной подписи не читается. В тестах пакета
// выключено, чтобы они могли писать профили вручную.
var RequireSignature bool

var ErrUnsigned = errors.New("профиль не подписан или изменён после подписи: проверьте его и подтвердите командой sessionvault trust <имя>")

// Ключ подписи лежит рядом с каталогом профилей, в закрытой папке данных (читают только SYSTEM и администраторы).
// Подпись показывает, что профиль записала сама программа или администратор командой, а не что-то постороннее.
func keyPath(dir string) string { return filepath.Join(filepath.Dir(dir), "profiles.key") }

func loadKey(dir string, create bool) ([]byte, error) {
	b, err := os.ReadFile(keyPath(dir))
	if err == nil && len(b) == 32 {
		return b, nil
	}
	if !create {
		return nil, ErrUnsigned
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath(dir), key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// HasKey — ключ подписи уже создан (иначе профили прежних версий ещё не подписаны).
func HasKey(dir string) bool {
	b, err := os.ReadFile(keyPath(dir))
	return err == nil && len(b) == 32
}

func (p Profile) signature(key []byte) string {
	p.Sig = ""
	b, _ := json.Marshal(p)
	m := hmac.New(sha256.New, key)
	m.Write(b)
	return hex.EncodeToString(m.Sum(nil))
}

func (p Profile) verify(dir string) error {
	key, err := loadKey(dir, false)
	if err != nil {
		return err
	}
	got, err := hex.DecodeString(p.Sig)
	want, _ := hex.DecodeString(p.signature(key))
	if err != nil || !hmac.Equal(got, want) {
		return ErrUnsigned
	}
	return nil
}

// Resign подписывает все профили каталога, не проверяя прежней подписи: так обновляются профили версий до подписи.
// Вызывается установкой и службой при первом запуске после обновления, то есть по явному действию администратора.
func Resign(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !ValidName(name) {
			continue
		}
		if err := Trust(dir, name); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// Trust подписывает профиль как есть: администратор проверил его содержимое и подтвердил.
func Trust(dir, name string) error {
	p, err := load(dir, name)
	if err != nil {
		return err
	}
	return Save(dir, p)
}
