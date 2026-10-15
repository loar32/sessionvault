package crypto

import "golang.org/x/sys/unix"

// mlock не даёт системе выгрузить ключ в раздел подкачки.
func Lock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Mlock(b)
}

func Unlock(b []byte) {
	if len(b) > 0 {
		_ = unix.Munlock(b)
	}
}
