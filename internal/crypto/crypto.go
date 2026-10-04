package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/crypto/argon2"
	"golang.org/x/sys/windows"
)

const (
	KeySize  = 32
	SaltSize = 16
)

type Params struct {
	Memory  uint32 // КиБ
	Time    uint32
	Threads uint8
}

func DefaultParams() Params {
	return Params{Memory: 128 * 1024, Time: 3, Threads: uint8(min(runtime.NumCPU(), 255))}
}

func DeriveKey(password, salt []byte, p Params) []byte {
	return argon2.IDKey(password, salt, p.Time, p.Memory, p.Threads, KeySize)
}

func random(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func NewKey() ([]byte, error)  { return random(KeySize) }
func NewSalt() ([]byte, error) { return random(SaltSize) }

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Результат: nonce ‖ шифротекст. Nonce новый на каждый вызов: повтор с тем же ключом ломает GCM.
func Seal(key, plaintext []byte) ([]byte, error) { return SealAAD(key, plaintext, nil) }

// aad не шифруется, но входит в проверку подлинности: изменённый или подставленный из другого места блок не откроется.
func SealAAD(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce, err := random(gcm.NonceSize())
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func Open(key, blob []byte) ([]byte, error) { return OpenAAD(key, blob, nil) }

func OpenAAD(key, blob, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, errors.New("данные слишком короткие")
	}
	return gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], aad)
}

func Wipe(b []byte) { clear(b) }

// VirtualLock не даёт системе выгрузить ключ в файл подкачки.
func Lock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return windows.VirtualLock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}

func Unlock(b []byte) {
	if len(b) > 0 {
		_ = windows.VirtualUnlock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	}
}
