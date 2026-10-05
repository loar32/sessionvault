// Package audit включает системный аудит чтения файлов и читает его события: обычный мониторинг папок видит только
// запись, а стилер только читает.
package audit

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procAuditQuery         = auditProc("AuditQuerySystemPolicy")
	procAuditSet           = auditProc("AuditSetSystemPolicy")
	procAuditFree          = auditProc("AuditFree")
	guidFileSystem         = windows.GUID{Data1: 0x0CCE921D, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}
	guidHandleManipulation = windows.GUID{Data1: 0x0CCE9223, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}
	guidKernelObject       = windows.GUID{Data1: 0x0CCE921F, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}
	guidCategoryObjAccess  = windows.GUID{Data1: 0x6997984A, Data2: 0x797A, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}
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

func policyFor(g windows.GUID) (uint32, error) {
	var p *policy
	if r, _, e := procAuditQuery.Call(uintptr(unsafe.Pointer(&g)), 1, uintptr(unsafe.Pointer(&p))); r == 0 {
		return 0, e
	}
	defer func() { _, _, _ = procAuditFree.Call(uintptr(unsafe.Pointer(p))) }()
	return p.Info, nil
}

func setPolicy(g windows.GUID, info uint32) error {
	p := policy{SubCategory: g, Info: info, Category: guidCategoryObjAccess}
	if r, _, e := procAuditSet.Call(uintptr(unsafe.Pointer(&p)), 1); r == 0 {
		return e
	}
	return nil
}

func fileSystemPolicy() (uint32, error) { return policyFor(guidFileSystem) }

// enable включает запись успешных обращений; changed — политику включили мы, а не она уже была.
// Неудачи оставляем как были: меняем только то, что нужно нам.
func enable(g windows.GUID) (changed bool, err error) {
	cur, err := policyFor(g)
	if err != nil {
		return false, err
	}
	if cur&auditSuccess != 0 {
		return false, nil
	}
	if err := setPolicy(g, cur&auditFailure|auditSuccess); err != nil {
		return false, err
	}
	return true, nil
}

func disable(g windows.GUID) error {
	cur, err := policyFor(g)
	if err != nil {
		return err
	}
	if cur&auditFailure != 0 {
		return setPolicy(g, auditFailure)
	}
	return setPolicy(g, auditNone)
}

// EnableFileSystem включает запись успешных обращений к файлам; changed — политику включили мы, а не она уже была.
func EnableFileSystem() (changed bool, err error) { return enable(guidFileSystem) }

// DisableFileSystem возвращает политику, которую включили мы.
func DisableFileSystem() error { return disable(guidFileSystem) }

// Политики, нужные для журнала чтения памяти: обращения к процессам (объекты ядра) и выдача дескрипторов. Событие об
// отказанной попытке (обычная учётка не может открыть процесс vault) приходит только при включённых обеих.
var memoryPolicies = []struct {
	Key  string
	GUID windows.GUID
}{{"kernel", guidKernelObject}, {"handle", guidHandleManipulation}}

// EnableMemoryAudit включает запись успехов и отказов для этих политик. В prev лежат прежние значения (первое
// сохранённое не перезаписывается: повторный вызов не должен принять наши изменения за исходные); changed — что-то изменилось.
func EnableMemoryAudit(prev map[string]uint32) (st map[string]uint32, changed bool, err error) {
	st = map[string]uint32{}
	for k, v := range prev {
		st[k] = v
	}
	for _, p := range memoryPolicies {
		cur, err := policyFor(p.GUID)
		if err != nil {
			return st, changed, err
		}
		if cur&(auditSuccess|auditFailure) == auditSuccess|auditFailure {
			continue
		}
		if _, ok := st[p.Key]; !ok {
			st[p.Key] = cur
		}
		if err := setPolicy(p.GUID, auditSuccess|auditFailure); err != nil {
			return st, changed, err
		}
		changed = true
	}
	return st, changed, nil
}

// RestoreMemoryAudit возвращает прежние значения политик.
func RestoreMemoryAudit(prev map[string]uint32) error {
	var errs []error
	for _, p := range memoryPolicies {
		if old, ok := prev[p.Key]; ok {
			if err := setPolicy(p.GUID, old&(auditSuccess|auditFailure|auditNone)); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func MemoryAuditEnabled() bool {
	for _, p := range memoryPolicies {
		cur, err := policyFor(p.GUID)
		if err != nil || cur&(auditSuccess|auditFailure) != auditSuccess|auditFailure {
			return false
		}
	}
	return true
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
