// Package audit включает системный аудит чтения файлов и читает его события: обычный мониторинг папок видит только
// запись, а стилер только читает.
package audit

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procAuditQuery        = auditProc("AuditQuerySystemPolicy")
	procAuditSet          = auditProc("AuditSetSystemPolicy")
	procAuditFree         = auditProc("AuditFree")
	guidFileSystem        = windows.GUID{Data1: 0x0CCE921D, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}
	guidCategoryObjAccess = windows.GUID{Data1: 0x6997984A, Data2: 0x797A, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}
)

func auditProc(name string) *windows.LazyProc {
	return windows.NewLazySystemDLL("advapi32.dll").NewProc(name)
}

const (
	auditSuccess = 0x1
	auditFailure = 0x2
	auditNone    = 0x4
)

type policy struct {
	SubCategory windows.GUID
	Info        uint32
	Category    windows.GUID
}

func fileSystemPolicy() (uint32, error) {
	g := guidFileSystem
	var p *policy
	if r, _, e := procAuditQuery.Call(uintptr(unsafe.Pointer(&g)), 1, uintptr(unsafe.Pointer(&p))); r == 0 {
		return 0, e
	}
	defer func() { _, _, _ = procAuditFree.Call(uintptr(unsafe.Pointer(p))) }()
	return p.Info, nil
}

func setFileSystemPolicy(info uint32) error {
	p := policy{SubCategory: guidFileSystem, Info: info, Category: guidCategoryObjAccess}
	if r, _, e := procAuditSet.Call(uintptr(unsafe.Pointer(&p)), 1); r == 0 {
		return e
	}
	return nil
}

// EnableFileSystem включает запись успешных обращений к файлам; changed — политику включили мы, а не она уже была.
func EnableFileSystem() (changed bool, err error) {
	cur, err := fileSystemPolicy()
	if err != nil {
		return false, err
	}
	if cur&auditSuccess != 0 {
		return false, nil
	}
	// Неудачи оставляем как были: меняем только то, что нужно нам.
	if err := setFileSystemPolicy(cur&auditFailure | auditSuccess); err != nil {
		return false, err
	}
	return true, nil
}

// DisableFileSystem возвращает политику, которую включили мы.
func DisableFileSystem() error {
	cur, err := fileSystemPolicy()
	if err != nil {
		return err
	}
	if cur&auditFailure != 0 {
		return setFileSystemPolicy(auditFailure)
	}
	return setFileSystemPolicy(auditNone)
}

// IsEnabled — действует ли аудит успешных обращений к файлам сейчас.
func IsEnabled() bool {
	cur, err := fileSystemPolicy()
	return err == nil && cur&auditSuccess != 0
}

// WatchReads ставит аудит чтения на папку; запись в журнал делается для всех, кто читает данные или список файлов.
// Правило наследуется, поэтому оно действует и на файлы внутри.
func WatchReads(path string) error {
	sd, err := windows.SecurityDescriptorFromString("S:(AU;OICISA;0x1;;;WD)")
	if err != nil {
		return err
	}
	sacl, _, err := sd.SACL()
	if err != nil {
		return err
	}
	if sacl == nil {
		return errors.New("пустой SACL")
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.SACL_SECURITY_INFORMATION, nil, nil, nil, sacl)
}
