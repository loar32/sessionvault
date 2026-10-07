package isolation

import (
	"encoding/base64"
	"errors"
	"github.com/loar32/sessionvault/internal/i18n"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	dpapiPrefix        = "dpapi:"
	cryptUIForbidden   = 0x1
	cryptLocalMachine  = 0x4
	dpapiEntropyString = "SessionVault accounts v1"
)

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func copyBlob(b *windows.DataBlob) []byte {
	out := make([]byte, b.Size)
	copy(out, unsafe.Slice(b.Data, b.Size))
	_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(b.Data)))
	return out
}

// sealPassword шифрует пароль учётки ключом DPAPI этого компьютера: скопированный отдельно файл (диск без BitLocker, резервная
// копия) на другой машине не расшифруется. От администратора этого компьютера защиты нет: он читает пароль так же, как служба.
func sealPassword(pw string) (string, error) {
	var out windows.DataBlob
	err := windows.CryptProtectData(blob([]byte(pw)), nil, blob([]byte(dpapiEntropyString)), 0, nil, cryptUIForbidden|cryptLocalMachine, &out)
	if err != nil {
		return "", err
	}
	return dpapiPrefix + base64.StdEncoding.EncodeToString(copyBlob(&out)), nil
}

// openPassword расшифровывает пароль; запись без префикса (прежних версий) читается как есть и при следующей записи будет зашифрована.
func openPassword(s string) (string, error) {
	enc, ok := strings.CutPrefix(s, dpapiPrefix)
	if !ok {
		return s, nil
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(raw) == 0 {
		return "", errors.New(i18n.T("запись пароля повреждена"))
	}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(raw), nil, blob([]byte(dpapiEntropyString)), 0, nil, cryptUIForbidden, &out); err != nil {
		return "", err
	}
	b := copyBlob(&out)
	defer func() {
		for i := range b {
			b[i] = 0
		}
	}()
	return string(b), nil
}
