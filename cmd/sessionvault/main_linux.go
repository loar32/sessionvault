package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/daemon"
	"github.com/loar32/sessionvault/internal/i18n"
	"github.com/loar32/sessionvault/internal/ipc"
	"golang.org/x/term"
)

const version = "1.2.0"

const minPasswordChars = 10

const usageRU = `sessionvault install
sessionvault protect [-yes] [-password-stdin] <telegram|chromium|brave|chrome|discord>
sessionvault unprotect [-password-stdin] <приложение>
sessionvault uninstall
sessionvault run <приложение> [ссылка]
sessionvault lock
sessionvault close <приложение>
sessionvault status
sessionvault menu
sessionvault alerts`

const usageEN = `sessionvault install
sessionvault protect [-yes] [-password-stdin] <telegram|chromium|brave|chrome|discord>
sessionvault unprotect [-password-stdin] <app>
sessionvault uninstall
sessionvault run <app> [link]
sessionvault lock
sessionvault close <app>
sessionvault status
sessionvault menu
sessionvault alerts`

var stdinReader = bufio.NewReader(os.Stdin)

func main() {
	i18n.Init(daemon.ConfigPath())
	// Ярлык приложения: sessionvault-<имя> — тот же файл, имя вызова говорит, что запускать.
	if base := filepath.Base(os.Args[0]); strings.HasPrefix(base, "sessionvault-") {
		os.Exit(launch(strings.TrimPrefix(base, "sessionvault-"), os.Args[1:]))
	}
	if len(os.Args) < 2 {
		usage()
	}
	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	case "daemon":
		err = runDaemon()
	case "helper":
		err = daemon.RunHelper(args)
	case "install":
		err = daemon.Install(os.Stdout)
	case "uninstall":
		err = daemon.Uninstall(func(a daemon.App) ([]byte, error) {
			fmt.Fprintf(os.Stderr, i18n.T("Снятие защиты с %s.\n"), a.Title)
			return readPassword(!term.IsTerminal(int(os.Stdin.Fd())), false)
		}, os.Stdout)
	case "protect":
		err = protect(args)
	case "unprotect":
		err = unprotect(args)
	case "run":
		if len(args) < 1 {
			usage()
		}
		os.Exit(launch(args[0], args[1:]))
	case "unlock":
		if len(args) < 1 {
			usage()
		}
		os.Exit(unlockAndRun(args[0], args[1:]))
	case "close":
		if len(args) != 1 {
			usage()
		}
		_, err = daemon.Call("close "+args[0], nil, 10*time.Second)
	case "lock":
		_, err = daemon.Call("lock", nil, 5*time.Second)
	case "status":
		err = status()
	case "menu":
		err = menu()
	case "alerts":
		var b []byte
		if b, err = os.ReadFile(daemon.AlertsPath()); err == nil {
			_, _ = os.Stdout.Write(b)
		} else if errors.Is(err, os.ErrNotExist) {
			fmt.Println(i18n.T("Тревог не было."))
			err = nil
		}
	case "version", "-v", "--version":
		fmt.Println("sessionvault", version)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sessionvault:", i18n.T(err.Error()))
		os.Exit(1)
	}
}

func usage() {
	if i18n.English() {
		fmt.Fprintln(os.Stderr, usageEN)
	} else {
		fmt.Fprintln(os.Stderr, usageRU)
	}
	os.Exit(2)
}

func runDaemon() error {
	if os.Geteuid() != 0 {
		return errors.New(i18n.T("нужны права root: запустите через sudo"))
	}
	cfg, err := daemon.LoadConfig()
	if err != nil {
		return err
	}
	l := daemon.OpenLog()
	d := daemon.New(cfg, l)
	if err := d.Listen(); err != nil {
		return err
	}
	l.Printf("служба запущена, версия %s, владелец %s", version, cfg.OwnerName)
	d.StartTraps()
	go d.Serve()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	l.Println("остановка службы")
	d.Stop()
	return nil
}

func flagSet(args []string, names ...string) (rest []string, set map[string]bool) {
	set = map[string]bool{}
	for _, a := range args {
		if slices.Contains(names, a) {
			set[a] = true
		} else {
			rest = append(rest, a)
		}
	}
	return rest, set
}

func protect(args []string) error {
	rest, f := flagSet(args, "-yes", "-password-stdin")
	if len(rest) != 1 {
		usage()
	}
	a, ok := daemon.FindApp(rest[0])
	if !ok {
		return fmt.Errorf(i18n.T("неизвестное приложение %q; доступны: %s"), rest[0], daemon.AppNames())
	}
	if !f["-yes"] {
		fmt.Printf(i18n.T("%s: данные из ~/%s переедут в зашифрованное хранилище, на их месте останется приманка.\nПриложение будет запускаться в песочнице под учёткой %s и видеть вместо домашнего каталога только свои данные и папку ~/SessionVault (как «Загрузки»).\n"), a.Title, a.Origin, daemon.AccountName(a.Name))
		if a.Browser {
			fmt.Println(i18n.T("Сохранённые входы на сайтах могут потребовать повторного входа: браузер в песочнице не видит связку ключей сеанса."))
		}
		fmt.Print(i18n.T("Продолжить? [y/N] "))
		line, _ := stdinReader.ReadString('\n')
		if s := strings.ToLower(strings.TrimSpace(line)); s != "y" && s != "yes" && s != "д" && s != "да" {
			return errors.New(i18n.T("отменено"))
		}
	}
	pw, err := readPassword(f["-password-stdin"], true)
	if err != nil {
		return err
	}
	defer crypto.Wipe(pw)
	return daemon.Protect(a.Name, pw, os.Stdout)
}

func unprotect(args []string) error {
	rest, f := flagSet(args, "-password-stdin")
	if len(rest) != 1 {
		usage()
	}
	pw, err := readPassword(f["-password-stdin"], false)
	if err != nil {
		return err
	}
	defer crypto.Wipe(pw)
	return daemon.Unprotect(rest[0], pw, os.Stdout)
}

// requestFor — что попросить у службы по аргументам ярлыка: ссылка (браузер, xdg-open), веб-приложение Omarchy (--app=)
// или просто запуск. Прочие флаги ярлыка не передаются: служба запускает приложение только со своими аргументами.
func requestFor(name string, args []string) (string, []byte) {
	for _, arg := range args {
		if u, ok := strings.CutPrefix(arg, "--app="); ok && ipc.ValidURL(u) == nil {
			return "webapp " + name, []byte(u)
		}
		if ipc.ValidURL(arg) == nil {
			return "open " + name, []byte(arg)
		}
	}
	return "run " + name, nil
}

// launch — запуск из ярлыка. Хранилище заперто — открывается окно терминала с вводом пароля (окна служба не рисует).
func launch(name string, args []string) int {
	line, extra := requestFor(name, args)
	resp, err := daemon.Call(line, extra, time.Minute)
	if err != nil {
		notify("SessionVault", err.Error())
		return 1
	}
	switch resp {
	case ipc.Ok, ipc.Busy:
		return 0
	case ipc.Locked:
		if err := openPrompt(name, args); err != nil {
			notify("SessionVault", err.Error())
			return 1
		}
		return 0
	case ipc.Alarm:
		notify(i18n.T("SessionVault: тревога"), i18n.T("Недавно прочитана приманка: запуск приложений приостановлен на 10 минут (sessionvault alerts)."))
	default:
		notify("SessionVault", fmt.Sprintf(i18n.T("не удалось запустить %s (подробности: journalctl -u sessionvault)"), name))
	}
	return 1
}

// openPrompt — плавающее окно терминала (класс TUI.float в Omarchy) с запросом пароля.
func openPrompt(name string, args []string) error {
	cmdline := append([]string{daemon.BinPath, "unlock", name}, args...)
	term := "xdg-terminal-exec"
	if _, err := exec.LookPath(term); err != nil {
		return errors.New(i18n.T("нет xdg-terminal-exec: откройте терминал и выполните sessionvault run ") + name)
	}
	cmd := exec.Command(term, append([]string{"--app-id=TUI.float", "--title=SessionVault", "-e"}, cmdline...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

func unlockAndRun(name string, args []string) int {
	a, ok := daemon.FindApp(name)
	if !ok {
		fmt.Fprintf(os.Stderr, i18n.T("неизвестное приложение %q; доступны: %s")+"\n", name, daemon.AppNames())
		return 2
	}
	fmt.Printf("\n  SessionVault — %s\n\n", a.Title)
	for attempt := 1; attempt <= 3; attempt++ {
		pw, err := readPassword(!term.IsTerminal(int(os.Stdin.Fd())), false)
		if err != nil {
			fmt.Fprintln(os.Stderr, i18n.T(err.Error()))
			return pause(1)
		}
		resp, err := daemon.Call("unlock "+name, pw, time.Minute)
		crypto.Wipe(pw)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return pause(1)
		}
		switch resp {
		case ipc.Ok:
			line, extra := requestFor(name, args)
			if r, err := daemon.Call(line, extra, time.Minute); err != nil || (r != ipc.Ok && r != ipc.Busy) {
				fmt.Fprintf(os.Stderr, i18n.T("не удалось запустить %s (подробности: journalctl -u sessionvault)")+"\n", name)
				return pause(1)
			}
			return 0
		case "bad":
			fmt.Fprintln(os.Stderr, i18n.T("Неверный пароль."))
		case "wait":
			fmt.Fprintln(os.Stderr, i18n.T("Слишком много попыток: подождите 10 секунд."))
			return pause(1)
		case ipc.Alarm:
			fmt.Fprintln(os.Stderr, i18n.T("Недавно прочитана приманка: запуск приложений приостановлен на 10 минут (sessionvault alerts)."))
			return pause(1)
		default:
			fmt.Fprintln(os.Stderr, i18n.T("Служба не смогла открыть хранилище (journalctl -u sessionvault)."))
			return pause(1)
		}
	}
	return pause(1)
}

// pause держит окно с ошибкой, иначе терминал закрылся бы сразу.
func pause(code int) int {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, i18n.T("Нажмите Enter, чтобы закрыть окно."))
		_, _ = stdinReader.ReadString('\n')
	}
	return code
}

func status() error {
	st, err := daemon.Call("status", nil, 5*time.Second)
	if err != nil {
		return err
	}
	list, _ := daemon.Call("list", nil, 5*time.Second)
	running, _ := daemon.Call("running", nil, 5*time.Second)
	fmt.Printf(i18n.T("Хранилище: %s\nЗащищены: %s\nЗапущены: %s\n"), stateText(st), orDash(list), orDash(running))
	return nil
}

func stateText(s string) string {
	switch s {
	case ipc.Locked:
		return i18n.T("заблокировано")
	case ipc.Unlocked:
		return i18n.T("разблокировано")
	case ipc.Alarm:
		return i18n.T("ТРЕВОГА (sessionvault alerts)")
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// menu — меню Omarchy (omarchy-menu-select): защищённые приложения, блокировка, состояние.
func menu() error {
	list, err := daemon.Call("list", nil, 5*time.Second)
	if err != nil {
		notify("SessionVault", err.Error())
		return err
	}
	var rows []string
	for _, n := range strings.Split(list, ",") {
		if a, ok := daemon.FindApp(n); ok {
			rows = append(rows, "\U000F0341\t"+a.Title+"\t"+a.Name)
		}
	}
	rows = append(rows, "\U000F033E\t"+i18n.T("Заблокировать хранилище")+"\t:lock", "\U000F02FC\t"+i18n.T("Состояние")+"\t:status")
	if _, err := exec.LookPath("omarchy-menu-select"); err != nil {
		return status()
	}
	out, err := exec.Command("omarchy-menu-select", append([]string{"SessionVault"}, rows...)...).Output()
	if err != nil {
		return nil // меню закрыто без выбора
	}
	_, key, _ := strings.Cut(strings.TrimSpace(string(out)), "\t")
	switch key {
	case "":
		return nil
	case ":lock":
		if _, err := daemon.Call("lock", nil, 5*time.Second); err != nil {
			return err
		}
		notify("SessionVault", i18n.T("Хранилище заблокировано (запущенные приложения — после их закрытия)."))
	case ":status":
		st, _ := daemon.Call("status", nil, 5*time.Second)
		running, _ := daemon.Call("running", nil, 5*time.Second)
		notify("SessionVault", fmt.Sprintf(i18n.T("Хранилище: %s\nЗащищены: %s\nЗапущены: %s\n"), stateText(st), orDash(list), orDash(running)))
	default:
		os.Exit(launch(key, nil))
	}
	return nil
}

func notify(title, body string) {
	if _, err := exec.LookPath("omarchy-notification-send"); err == nil {
		_ = exec.Command("omarchy-notification-send", "--app-name", "SessionVault", title, body).Run()
		return
	}
	if err := exec.Command("notify-send", "-a", "SessionVault", title, body).Run(); err != nil {
		fmt.Fprintln(os.Stderr, title+": "+body)
	}
}

func checkNewPassword(pw []byte) error {
	if utf8.RuneCount(pw) < minPasswordChars {
		return fmt.Errorf(i18n.T("мастер-пароль короче %d символов"), minPasswordChars)
	}
	return nil
}

func readPassword(stdin, confirm bool) ([]byte, error) {
	if stdin {
		line, err := stdinReader.ReadBytes('\n')
		if err != nil && len(line) == 0 {
			return nil, err
		}
		pw := bytes.TrimRight(line, "\r\n")
		if len(pw) == 0 {
			return nil, errors.New(i18n.T("пароль не может быть пустым"))
		}
		if confirm {
			if err := checkNewPassword(pw); err != nil {
				return nil, err
			}
		}
		if len(pw) > ipc.MaxPassword {
			return nil, errors.New(i18n.T("пароль слишком длинный"))
		}
		return pw, nil
	}
	fmt.Fprint(os.Stderr, i18n.T("Мастер-пароль: "))
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if len(pw) == 0 {
		return nil, errors.New(i18n.T("пароль не может быть пустым"))
	}
	if len(pw) > ipc.MaxPassword {
		return nil, errors.New(i18n.T("пароль слишком длинный"))
	}
	if confirm {
		if err := checkNewPassword(pw); err != nil {
			return nil, err
		}
		fmt.Fprint(os.Stderr, i18n.T("Повтори пароль: "))
		again, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		defer crypto.Wipe(again)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(pw, again) {
			crypto.Wipe(pw)
			return nil, errors.New(i18n.T("пароли не совпали"))
		}
	}
	return pw, nil
}
