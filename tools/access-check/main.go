// access-check запускается из основной (обычной) учётки и пробует добраться до защищённых данных.
// Код выхода: 0 — всё закрыто, 1 — что-то прочиталось, 2 — проверка не состоялась.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

var leaks, skipped int

func main() {
	base := filepath.Join(os.Getenv("ProgramData"), "SessionVault")
	dir := flag.String("dir", filepath.Join(base, "vault"), "защищённая папка")
	file := flag.String("file", filepath.Join(base, "vault", "telegram", "tdata", "key_datas"), "защищённый файл")
	pwd := flag.String("pwd", filepath.Join(base, "vault.pwd"), "файл с паролем vault")
	pid := flag.Uint("pid", 0, "pid процесса vault")
	flag.Parse()

	checkList(*dir)
	checkRead(*file)
	checkRead(*pwd)
	checkWriteDACL(*dir)
	if *pid != 0 {
		checkProcess(uint32(*pid))
	}

	fmt.Printf("итог: утечек %d, не проверено %d\n", leaks, skipped)
	switch {
	case leaks > 0:
		os.Exit(1)
	case skipped > 0:
		os.Exit(2)
	}
}

func denied(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}

func report(what string, err error) {
	switch {
	case err == nil:
		leaks++
		fmt.Println("УТЕЧКА   ", what)
	case denied(err):
		fmt.Println("закрыто  ", what)
	default:
		skipped++
		fmt.Println("НЕ ПРОВЕРЕНО", what, "-", err)
	}
}

func checkList(dir string) {
	_, err := os.ReadDir(dir)
	report("список файлов "+dir, err)
}

func checkRead(path string) {
	_, err := os.ReadFile(path)
	report("чтение "+path, err)
}

func checkWriteDACL(path string) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		report("смена прав "+path, err)
		return
	}
	h, err := windows.CreateFile(p, windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err == nil {
		_ = windows.CloseHandle(h)
	}
	report("смена прав "+path, err)
}

func checkProcess(pid uint32) {
	h, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err == nil {
		_ = windows.CloseHandle(h)
	}
	report(fmt.Sprintf("чтение памяти процесса %d", pid), err)
}
