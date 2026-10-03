package main

import (
	"os"

	"golang.org/x/sys/windows"
)

var (
	kernel32         = windows.NewLazySystemDLL("kernel32.dll")
	procAttachConsol = kernel32.NewProc("AttachConsole")
	procAllocConsole = kernel32.NewProc("AllocConsole")
)

const attachParentProcess = ^uintptr(0)

// Консоль открыта самим процессом (запуск из установщика): перед выходом нужна пауза, иначе окно с ошибкой исчезнет.
var ownConsole bool

// Бинарник собирается как GUI-приложение (иначе трей и окно пароля показывали бы консоль). Для командных режимов
// подключаемся к консоли запустившего процесса, а если её нет (запуск из установщика) — открываем свою.
// Если вывод перенаправлен в файл или pipe, ничего не трогаем.
func attachConsole() {
	if h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE); err == nil && h != 0 {
		return
	}
	if r, _, _ := procAttachConsol.Call(attachParentProcess); r == 0 {
		if r, _, _ := procAllocConsole.Call(); r == 0 {
			return
		}
		ownConsole = true
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
