package crypto

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

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
