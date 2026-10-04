// access-check запускается из основной (обычной) учётки и пробует добраться до защищённых данных.
// Код выхода: 0 — всё закрыто, 1 — что-то прочиталось, 2 — проверка не состоялась.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/loar32/sessionvault/internal/ipc"
	"github.com/loar32/sessionvault/internal/isolation"
	"golang.org/x/sys/windows"
)

var leaks, skipped int

func main() {
	base := isolation.BaseDir()
	dir := flag.String("dir", filepath.Join(base, "vault"), "защищённая папка")
	file := flag.String("file", filepath.Join(base, "vault", "telegram", "work", "tdata", "key_datas"), "защищённый файл")
	enc := flag.String("enc", filepath.Join(base, "vault", "telegram", "data.enc"), "зашифрованный архив")
	meta := flag.String("meta", filepath.Join(base, "vault", "telegram", "vault.json"), "метаданные хранилища")
	pwd := flag.String("pwd", filepath.Join(base, "vault.pwd"), "файл с паролем vault")
	pid := flag.Uint("pid", 0, "pid процесса vault")
	pipe := flag.Bool("pipe", false, "пробы pipe службы")
	decoy := flag.String("decoy", "", "только прочитать приманку по этому пути (вызывает тревогу службы)")
	flag.Parse()

	if *decoy != "" {
		os.Exit(readDecoy(*decoy))
	}

	checkList(*dir)
	checkReadOpen(*file)
	checkRead(*enc)
	checkRead(*meta)
	checkRead(*pwd)
	checkWriteDACL(*dir)
	if *pid != 0 {
		checkProcess(uint32(*pid))
	}
	if *pipe {
		checkPipes()
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

// Открытая копия существует только пока приложение запущено; её отсутствие — нормальное состояние.
func checkReadOpen(path string) {
	_, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Println("нет файла", path, "(приложение закрыто)")
		return
	}
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

// Пробы pipe: служба не должна ни выполнять посторонние команды, ни отдавать данные, ни падать от мусора.
func checkPipes() {
	junk := []string{
		"", " ", "stop", "unlock", "unlock secret", "quit", "shutdown", "status x", "STATUS",
		"run", "list arg", "list; calc", "run telegram arg", "run telegram -workdir C:\\", "run ../telegram", `run ..	elegram`, "run nonexistent",
		"run telegram\x00", "run telegram; calc", "run $(calc)", "run телеграм",
		"open x", "open https://example.com", "hello", "hello ", "hello ../telegram", "hello telegram arg", "hello nonexistent", "hello telegram; calc",
		strings.Repeat("A", 1<<20), strings.Repeat("run telegram ", 5000),
	}
	for _, q := range junk {
		resp, err := ipc.Call(ipc.CommandPipe, q, 3*time.Second)
		name := fmt.Sprintf("pipe: запрос %q", short(q))
		switch {
		case err != nil || resp == ipc.Failed:
			fmt.Println("закрыто  ", name)
		default:
			leaks++
			fmt.Println("УТЕЧКА   ", name, "-> ответ", resp)
		}
	}
	if resp, err := ipc.Call(ipc.CommandPipe, "status", 3*time.Second); err != nil || (resp != ipc.Locked && resp != ipc.Unlocked) {
		leaks++
		fmt.Println("УТЕЧКА    служба не отвечает после проб:", resp, err)
	} else {
		fmt.Println("закрыто   служба жива после проб, отвечает только статусом:", resp)
	}
	// Имя pipe пароля случайное и живёт только пока открыто окно; если оно сейчас есть, подключиться нельзя.
	pipes, _ := filepath.Glob(`\\.\pipe\` + strings.TrimPrefix(ipc.UnlockPipe, `\\.\pipe\`) + "*")
	for _, p := range pipes {
		if c, err := ipc.Dial(p, time.Second); err == nil {
			leaks++
			c.Close()
			fmt.Println("УТЕЧКА    pipe пароля доступен обычной учётке:", p)
		} else {
			fmt.Println("закрыто   pipe пароля:", err)
		}
	}
}

func short(s string) string {
	if len(s) > 30 {
		return s[:30] + "…"
	}
	return s
}

// Читает папку так же, как это делает стилер: список файлов и содержимое каждого.
func readDecoy(path string) int {
	fmt.Printf("READ_AT=%d\n", time.Now().UnixMilli())
	entries, err := os.ReadDir(path)
	if err != nil {
		fmt.Println("приманка не прочитана:", err)
		return 2
	}
	n := 0
	for _, e := range entries {
		if b, err := os.ReadFile(filepath.Join(path, e.Name())); err == nil {
			n += len(b)
		}
	}
	fmt.Printf("приманка прочитана: %d файлов/папок, %d байт\n", len(entries), n)
	return 0
}
