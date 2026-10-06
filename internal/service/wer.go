package service

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"golang.org/x/sys/windows"
)

var (
	wer        = windows.NewLazySystemDLL("wer.dll")
	pWerAdd    = wer.NewProc("WerAddExcludedApplication")
	pWerRemove = wer.NewProc("WerRemoveExcludedApplication")
)

// Аварийный дамп защищённого приложения содержит его память с расшифрованными данными, а Служба отчётов об ошибках
// сохраняет его на диск. Исключаем exe приложения из отчётов (для всех пользователей; по имени файла).
// Вызывается перед запуском приложения и безвредна при повторе.
func werExclude(exe string) {
	name, err := windows.UTF16PtrFromString(filepath.Base(exe))
	if err != nil {
		return
	}
	_, _, _ = pWerAdd.Call(uintptr(unsafe.Pointer(name)), 1)
}

// werRestore убирает исключения при удалении программы.
func werRestore() {
	entries, err := os.ReadDir(isolation.ProfilesDir())
	if err != nil {
		return
	}
	for _, e := range entries {
		n, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok {
			continue
		}
		p, err := profiles.Load(isolation.ProfilesDir(), n)
		if err != nil {
			continue
		}
		if name, err := windows.UTF16PtrFromString(filepath.Base(p.Exe)); err == nil {
			_, _, _ = pWerRemove.Call(uintptr(unsafe.Pointer(name)), 1)
		}
	}
}
