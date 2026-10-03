package isolation

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	logonWithProfile         = 0x1
	createUnicodeEnvironment = 0x400
)

var procCreateProcessWithLogon = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateProcessWithLogonW")

// Запуск через вторичный вход: окна остаются в сессии вызывающего, а процесс работает от vault.
// Окружение берётся из профиля vault, а не от вызывающего.
func Launch(user, password, cmdline, workDir string) (uint32, error) {
	u, err := windows.UTF16PtrFromString(user)
	if err != nil {
		return 0, err
	}
	dom, _ := windows.UTF16PtrFromString(".")
	pw, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return 0, err
	}
	cl, err := windows.UTF16PtrFromString(cmdline)
	if err != nil {
		return 0, err
	}
	wd, err := windows.UTF16PtrFromString(workDir)
	if err != nil {
		return 0, err
	}
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var pi windows.ProcessInformation
	r, _, e := procCreateProcessWithLogon.Call(
		uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(dom)), uintptr(unsafe.Pointer(pw)),
		logonWithProfile, 0, uintptr(unsafe.Pointer(cl)), createUnicodeEnvironment, 0,
		uintptr(unsafe.Pointer(wd)), uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		return 0, e
	}
	_ = windows.CloseHandle(pi.Process)
	_ = windows.CloseHandle(pi.Thread)
	return pi.ProcessId, nil
}
