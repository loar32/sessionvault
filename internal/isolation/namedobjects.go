package isolation

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procNtOpenDirectoryObject = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtOpenDirectoryObject")

const (
	// Просмотр, обход и создание объектов в каталоге имён сеанса: этого хватает, чтобы создавать мьютексы и события в Local\.
	directoryAccess    = 0x1 | 0x2 | 0x4 | 0x8
	objCaseInsensitive = 0x40
)

// У чужой учётки в сеансе пользователя нет права создавать именованные объекты в Local\ (даже мьютекс: ACCESS_DENIED).
// Браузеры на Chromium создают такой мьютекс при запуске и без него не стартуют («Failed to create a ProcessSingleton»).
// Право выдаётся logon-SID vault на время работы приложения, как и права на рабочий стол.
func setNamedObjectAccess(sid *windows.SID, mode windows.ACCESS_MODE) error {
	var session uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session); err != nil {
		return err
	}
	if session == 0 {
		return nil
	}
	name, err := windows.NewNTUnicodeString(fmt.Sprintf(`\Sessions\%d\BaseNamedObjects`, session))
	if err != nil {
		return err
	}
	oa := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), ObjectName: name, Attributes: objCaseInsensitive}
	var h windows.Handle
	st, _, _ := procNtOpenDirectoryObject.Call(uintptr(unsafe.Pointer(&h)),
		uintptr(windows.READ_CONTROL|windows.WRITE_DAC|directoryAccess), uintptr(unsafe.Pointer(&oa)))
	if st != 0 {
		return fmt.Errorf("NtOpenDirectoryObject: статус %#x", st)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	return editObjectACL(h, windows.SE_KERNEL_OBJECT, sid, mode, directoryAccess)
}
