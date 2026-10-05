package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/loar32/sessionvault/internal/checkup"
	"github.com/loar32/sessionvault/internal/ipc"
	"github.com/loar32/sessionvault/internal/service"
	"golang.org/x/sys/windows"
)

// Отчёт берётся у службы по pipe; администратору pipe закрыт, поэтому ему (и при остановленной службе) отдаётся
// последний check.json с пометкой о времени.
func check(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "вывести отчёт в JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := ipc.CallMax(ipc.CommandPipe, "check", 30*time.Second, ipc.MaxCheck)
	stale := false
	if err != nil {
		b, rerr := os.ReadFile(service.CheckPath())
		if rerr != nil {
			return fmt.Errorf("служба недоступна, сохранённого отчёта нет: %w", err)
		}
		raw, stale = string(b), true
	}
	var r checkup.Report
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return fmt.Errorf("неверный отчёт: %w", err)
	}
	if *asJSON {
		fmt.Println(raw)
		return nil
	}
	if stale {
		fmt.Printf("Служба недоступна, показан отчёт от %s\n\n", r.Time.Local().Format("02.01.2006 15:04"))
	}
	fmt.Print(checkup.Format(r, enableColor()))
	return nil
}

// Цвет только в консоли, где включилась обработка ANSI-кодов; при выводе в файл или pipe — без него.
func enableColor() bool {
	h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		return false
	}
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		return false
	}
	return windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}
