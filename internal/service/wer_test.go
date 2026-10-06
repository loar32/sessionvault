package service

import (
	"testing"
	"unsafe"

	"github.com/loar32/sessionvault/internal/isolation"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const werKey = `SOFTWARE\Microsoft\Windows\Windows Error Reporting\ExcludedApplications`

func werHas(t *testing.T, name string) bool {
	t.Helper()
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, werKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer func() { _ = k.Close() }()
	_, _, err = k.GetIntegerValue(name)
	return err == nil
}

func TestWerExclude(t *testing.T) {
	if !isolation.IsElevated() {
		t.Skip("нужны права администратора")
	}
	const exe = "svtest-wer.exe"
	name, _ := windows.UTF16PtrFromString(exe)
	defer pWerRemove.Call(uintptr(unsafe.Pointer(name)), 1)
	werExclude(`C:\x\` + exe)
	if !werHas(t, exe) {
		t.Fatal("исключение WER не записано")
	}
	if r, _, _ := pWerRemove.Call(uintptr(unsafe.Pointer(name)), 1); r != 0 {
		t.Fatalf("WerRemoveExcludedApplication: 0x%x", r)
	}
	if werHas(t, exe) {
		t.Fatal("исключение WER осталось после снятия")
	}
}
