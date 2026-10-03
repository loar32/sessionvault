package main

import (
	"os"

	"golang.org/x/sys/windows"
)

var procAttachConsole = windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole")

const attachParentProcess = ^uintptr(0)

// Бинарник собирается как GUI-приложение (иначе трей и окно пароля показывали бы консоль). Для командных режимов
// подключаемся к консоли запустившего процесса, если вывод не перенаправлен в файл или pipe.
func attachConsole() {
	if h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE); err == nil && h != 0 {
		return
	}
	if r, _, _ := procAttachConsole.Call(attachParentProcess); r == 0 {
		return
	}
	reopen := func(name string, flag int, target **os.File) {
		if f, err := os.OpenFile(name, flag, 0); err == nil {
			*target = f
		}
	}
	reopen("CONOUT$", os.O_WRONLY, &os.Stdout)
	reopen("CONOUT$", os.O_WRONLY, &os.Stderr)
	reopen("CONIN$", os.O_RDONLY, &os.Stdin)
}
