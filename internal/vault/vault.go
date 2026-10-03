package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/loar32/sessionvault/internal/crypto"
	"golang.org/x/sys/windows"
)

const (
	metaFile = "vault.json"
	dataFile = "data.enc"
	openFile = "open"
)

var ErrWrongPassword = errors.New("неверный пароль")

// Vault — одно приложение: Dir\vault.json, Dir\data.enc и открытая папка Dir\<DataName> на время работы.
type Vault struct {
	Dir      string
	DataName string
}

type meta struct {
	Version    int
	Salt       []byte
	Params     crypto.Params
	WrappedDEK []byte
}

func (v Vault) path(name string) string { return filepath.Join(v.Dir, name) }

func (v Vault) dataDir() string { return v.path(v.DataName) }

func (v Vault) Exists() bool {
	_, err := os.Stat(v.path(metaFile))
	return err == nil
}

// После сбоя открытая копия остаётся вместе с маркером.
func (v Vault) NeedsRecovery() bool {
	_, err := os.Stat(v.path(openFile))
	return err == nil
}

// Создаёт ключи; данные при этом не шифрует. Вызывающий обнуляет возвращённый ключ.
func (v Vault) Create(password []byte) ([]byte, error) {
	salt, err := crypto.NewSalt()
	if err != nil {
		return nil, err
	}
	dek, err := crypto.NewKey()
	if err != nil {
		return nil, err
	}
	p := crypto.DefaultParams()
	kek := crypto.DeriveKey(password, salt, p)
	defer crypto.Wipe(kek)
	wrapped, err := crypto.Seal(kek, dek)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(meta{Version: 1, Salt: salt, Params: p, WrappedDEK: wrapped})
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(v.path(metaFile), b); err != nil {
		crypto.Wipe(dek)
		return nil, err
	}
	return dek, nil
}

func (v Vault) Unlock(password []byte) ([]byte, error) {
	b, err := os.ReadFile(v.path(metaFile))
	if err != nil {
		return nil, err
	}
	var m meta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m.Version != 1 {
		return nil, fmt.Errorf("версия хранилища %d не поддерживается", m.Version)
	}
	kek := crypto.DeriveKey(password, m.Salt, m.Params)
	defer crypto.Wipe(kek)
	dek, err := crypto.Open(kek, m.WrappedDEK)
	if err != nil {
		return nil, ErrWrongPassword
	}
	return dek, nil
}

// Открытая папка → data.enc. Порядок важен при сбое: пока data.enc не заменён, маркер и открытая копия целы;
// после замены data.enc полный, а недоудалённая папка без маркера при следующем Decrypt затирается.
func (v Vault) Encrypt(dek []byte) error {
	tar, err := packDir(v.dataDir())
	if err != nil {
		return err
	}
	defer crypto.Wipe(tar)
	blob, err := crypto.Seal(dek, tar)
	if err != nil {
		return err
	}
	if err := writeAtomic(v.path(dataFile), blob); err != nil {
		return err
	}
	if err := os.Remove(v.path(openFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return removeAll(v.dataDir())
}

// data.enc → открытая папка. Маркер ставится после распаковки: частичная распаковка не считается открытыми данными.
func (v Vault) Decrypt(dek []byte) error {
	blob, err := os.ReadFile(v.path(dataFile))
	if err != nil {
		return err
	}
	tar, err := crypto.Open(dek, blob)
	if err != nil {
		return err
	}
	defer crypto.Wipe(tar)
	if err := removeAll(v.dataDir()); err != nil {
		return err
	}
	if err := unpackDir(tar, v.dataDir()); err != nil {
		return err
	}
	return os.WriteFile(v.path(openFile), nil, 0o600)
}

// Сразу после выхода процесса файлы ещё могут быть заняты (антивирус, индексатор).
func retry(f func() error) error {
	var err error
	for range 20 {
		if err = f(); err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return err
}

func removeAll(path string) error {
	return retry(func() error { return os.RemoveAll(path) })
}

func writeAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return retry(func() error { return os.Rename(tmp, path) })
}

// Эксклюзивно открытый файл держит запущенный экземпляр; при падении процесса система снимает блокировку сама.
func (v Vault) Lock() (release func(), err error) {
	name, err := windows.UTF16PtrFromString(v.path("running.lock"))
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, errors.New("уже запущено (или не завершено): running.lock занят")
	}
	return func() { _ = windows.CloseHandle(h) }, nil
}
