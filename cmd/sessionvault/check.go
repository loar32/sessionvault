package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/loar32/sessionvault/internal/asr"
	"github.com/loar32/sessionvault/internal/checkup"
	"github.com/loar32/sessionvault/internal/ipc"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/service"
	"github.com/loar32/sessionvault/internal/ui/checkwin"
	"golang.org/x/sys/windows"
)

// Отчёт берётся у службы по pipe; администратору pipe закрыт, поэтому ему (и при остановленной службе) отдаётся
// последний check.json с пометкой о времени.
func check(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "вывести отчёт в JSON")
	window := fs.Bool("window", false, "показать итог в окне, как пункт трея")
	fix := fs.Bool("fix", false, "включить правила ASR в Defender (от администратора)")
	yes := fs.Bool("yes", false, "с -fix: не спрашивать подтверждение")
	off := fs.Bool("off", false, "с -fix: вернуть прежние значения")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *fix {
		return fixASR(*yes, *off)
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
	if *window {
		checkwin.Show(r)
		return nil
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

// Ничего не включается молча: сначала список правил и откат, потом вопрос (-yes его пропускает).
func fixASR(yes, off bool) error {
	if !isolation.IsElevated() {
		return errors.New("нужен запуск от администратора")
	}
	if off {
		if err := service.FixASR(true); errors.Is(err, service.ErrNothingToRevert) {
			fmt.Println(err)
			return nil
		} else if err != nil {
			return err
		}
		service.SyncService()
		fmt.Println("правила ASR возвращены к прежним значениям")
		return nil
	}
	fmt.Println("Будут включены правила ASR в Defender (режим блокировки):")
	for _, r := range asr.Rules {
		fmt.Println("  - " + r.Title)
	}
	fmt.Println("Откат: sessionvault check -fix -off (или удаление программы).")
	if !yes {
		fmt.Print("Включить? [y/N]: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes", "д", "да":
		default:
			fmt.Println("отменено, ничего не изменено")
			return nil
		}
	}
	if err := service.FixASR(false); err != nil {
		return err
	}
	service.SyncService()
	fmt.Println("готово. Служба обновит отчёт через несколько секунд (sessionvault check из основной учётки или пункт трея).")
	return nil
}
