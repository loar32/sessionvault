package main

import (
	"bufio"
	"bytes"
	"encoding/json"
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

	"github.com/loar32/sessionvault/internal/checkup"
	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/daemon"
	"github.com/loar32/sessionvault/internal/i18n"
	"github.com/loar32/sessionvault/internal/ipc"
	"golang.org/x/term"
)

const version = "1.2.1"

const minPasswordChars = 10

const usageRU = `sessionvault install
sessionvault protect [-yes] [-password-stdin] [-share папка]... <telegram|chromium|brave|chrome|discord>
sessionvault add [-yes] [-password-stdin] [-name имя] [-data папка]... [-share папка]... [-arg аргумент]... <ярлык|программа|AppImage>
sessionvault refresh <приложение>
sessionvault share|unshare <приложение> <папка>
sessionvault unprotect [-password-stdin] <приложение>
sessionvault uninstall
sessionvault run <приложение> [ссылка]
sessionvault lock
sessionvault close <приложение>
sessionvault status
sessionvault check
sessionvault recovery create|verify|reset|revoke|status [-file файл] [-password-stdin]
sessionvault export <приложение> <файл>
sessionvault import [-exe программа] [-yes] [-password-stdin] <файл>
sessionvault menu
sessionvault alerts`

const usageEN = `sessionvault install
sessionvault protect [-yes] [-password-stdin] [-share folder]... <telegram|chromium|brave|chrome|discord>
sessionvault add [-yes] [-password-stdin] [-name name] [-data folder]... [-share folder]... [-arg argument]... <launcher|program|AppImage>
sessionvault refresh <app>
sessionvault share|unshare <app> <folder>
sessionvault unprotect [-password-stdin] <app>
sessionvault uninstall
sessionvault run <app> [link]
sessionvault lock
sessionvault close <app>
sessionvault status
sessionvault check
sessionvault recovery create|verify|reset|revoke|status [-file file] [-password-stdin]
sessionvault export <app> <file>
sessionvault import [-exe program] [-yes] [-password-stdin] <file>
sessionvault menu
sessionvault alerts`

var stdinReader = bufio.NewReader(os.Stdin)

func main() {
	i18n.Init(daemon.ConfigPath())
	// Внутри песочницы на месте xdg-open стоит этот же файл: ссылка уходит службе.
	switch base := filepath.Base(os.Args[0]); {
	case base == "xdg-open":
		os.Exit(daemon.SandboxOpen(os.Args[1:]))
	case strings.HasPrefix(base, "sessionvault-"):
		// Ярлык приложения: sessionvault-<имя> — тот же файл, имя вызова говорит, что запускать.
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
	case "sandbox":
		os.Exit(daemon.SandboxInit(args))
	case "open-link":
		os.Exit(daemon.SandboxOpen(args))
	case "pause-run":
		os.Exit(pauseRun(args))
	case "install":
		err = daemon.Install(os.Stdout)
	case "uninstall":
		err = daemon.Uninstall(func(a daemon.App) ([]byte, error) {
			fmt.Fprintf(os.Stderr, i18n.T("Снятие защиты с %s.\n"), a.Title)
			return readPassword(!term.IsTerminal(int(os.Stdin.Fd())), false)
		}, os.Stdout)
	case "protect":
		err = protect(args)
	case "add":
		err = add(args)
	case "refresh":
		if len(args) != 1 {
			usage()
		}
		err = daemon.Refresh(args[0], os.Stdout)
	case "share", "unshare":
		if len(args) != 2 {
			usage()
		}
		err = daemon.Share(args[0], args[1], os.Args[1] == "share", os.Stdout)
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
	case "check":
		err = check()
	case "recovery":
		err = recoveryCmd(args)
	case "export":
		if len(args) != 2 {
			usage()
		}
		if err = daemon.Export(args[0], absPath(args[1])); err == nil {
			fmt.Println(i18n.T("готово:"), absPath(args[1]))
			fmt.Println(i18n.T("Файл зашифрован; на новом ПК его открывает мастер-пароль или ключ восстановления: sudo sessionvault import файл"))
		}
	case "import":
		err = importCmd(args)
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

// opts — флаги команды: булевы (-yes) и со значением, которые можно повторять (-share a -share b).
type opts struct {
	pos   []string
	set   map[string]bool
	multi map[string][]string
}

func parseOpts(args []string, bools, values []string) opts {
	o := opts{set: map[string]bool{}, multi: map[string][]string{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case slices.Contains(bools, a):
			o.set[a] = true
		case slices.Contains(values, a):
			if i+1 >= len(args) {
				usage()
			}
			o.multi[a] = append(o.multi[a], args[i+1])
			i++
		default:
			o.pos = append(o.pos, a)
		}
	}
	return o
}

func absPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func askYes(prompt string) bool {
	fmt.Print(prompt)
	line, _ := stdinReader.ReadString('\n')
	s := strings.ToLower(strings.TrimSpace(line))
	return s == "y" || s == "yes" || s == "д" || s == "да"
}

func ask(prompt string) string {
	fmt.Print(prompt)
	line, _ := stdinReader.ReadString('\n')
	return strings.TrimSpace(line)
}

func protect(args []string) error {
	o := parseOpts(args, []string{"-yes", "-password-stdin"}, []string{"-share"})
	if len(o.pos) != 1 {
		usage()
	}
	a, ok := daemon.FindApp(o.pos[0])
	if !ok || a.Custom {
		return fmt.Errorf(i18n.T("неизвестное приложение %q; доступны: %s"), o.pos[0], daemon.AppNames())
	}
	return protectBuiltin(a, o.multi["-share"], o.set["-yes"], o.set["-password-stdin"])
}

func protectBuiltin(a daemon.App, shares []string, yes, stdin bool) error {
	if !yes {
		fmt.Printf(i18n.T("%s: данные из ~/%s переедут в зашифрованное хранилище, на их месте останется приманка.\nПриложение будет запускаться в песочнице под учёткой %s и видеть вместо домашнего каталога только свои данные и папку ~/SessionVault (как «Загрузки»).\n"), a.Title, a.Dirs[0], daemon.AccountName(a.Name))
		if !askYes(i18n.T("Продолжить? [y/N] ")) {
			return errors.New(i18n.T("отменено"))
		}
	}
	pw, err := readPassword(stdin, true)
	if err != nil {
		return err
	}
	defer crypto.Wipe(pw)
	return daemon.Protect(a.Name, pw, shares, os.Stdout)
}

func add(args []string) error {
	o := parseOpts(args, []string{"-yes", "-password-stdin"}, []string{"-name", "-data", "-share", "-arg"})
	if len(o.pos) != 1 {
		usage()
	}
	target := o.pos[0]
	if strings.Contains(target, "/") || fileExists(target) && !strings.HasSuffix(target, ".desktop") {
		target = absPath(target)
	}
	req := daemon.AddRequest{Target: target, Dirs: o.multi["-data"], Shares: o.multi["-share"], Args: o.multi["-arg"], ArgsSet: len(o.multi["-arg"]) > 0}
	if n := o.multi["-name"]; len(n) > 0 {
		req.Name = n[len(n)-1]
	}
	plan, err := daemon.PlanAdd(req)
	if err != nil {
		return err
	}
	if plan.Builtin != "" {
		a, _ := daemon.FindApp(plan.Builtin)
		fmt.Printf(i18n.T("Это встроенное приложение %s: защищаю его как встроенное.\n"), a.Title)
		return protectBuiltin(a, req.Shares, o.set["-yes"], o.set["-password-stdin"])
	}
	a := plan.App
	if !o.set["-yes"] {
		cfg, err := daemon.LoadConfig()
		if err != nil {
			return err
		}
		showPlan(plan)
		if len(req.Dirs) == 0 {
			if s := ask(i18n.T("Enter — согласиться, или впишите папки данных сами (через пробел, ~/… или от дома): ")); s != "" {
				if a.Dirs, err = daemon.NormalizeDirs(cfg, daemon.ExecArgv(s)); err != nil {
					return err
				}
			}
		}
		if len(req.Shares) == 0 {
			if s := ask(i18n.T("Открыть приложению ваши папки (например ~/Pictures)? Enter — нет, или впишите через пробел: ")); s != "" {
				if a.Shares, err = daemon.CheckShares(cfg, daemon.ExecArgv(s)); err != nil {
					return err
				}
			}
		}
		if !askYes(fmt.Sprintf(i18n.T("Защитить %s? [y/N] "), a.Title)) {
			return errors.New(i18n.T("отменено"))
		}
	}
	pw, err := readPassword(o.set["-password-stdin"], true)
	if err != nil {
		return err
	}
	defer crypto.Wipe(pw)
	return daemon.Add(a, pw, os.Stdout)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func showPlan(p daemon.AddPlan) {
	a := p.App
	fmt.Printf(i18n.T("Приложение: %s (имя %s, учётка %s)\n"), a.Title, a.Name, daemon.AccountName(a.Name))
	if p.Desktop != "" {
		fmt.Printf(i18n.T("Ярлык: %s\n"), p.Desktop)
	}
	if a.Kind != "" {
		fmt.Printf(i18n.T("Программа: %s — лежит там, где её может заменить не только root, поэтому запускаться будет её копия в каталоге SessionVault (после обновления программы: sudo sessionvault refresh %s)\n"), a.Source, a.Name)
	} else {
		fmt.Printf(i18n.T("Программа: %s\n"), a.Exe[0])
	}
	if len(a.Args) > 0 {
		fmt.Printf(i18n.T("Аргументы запуска: %s\n"), strings.Join(a.Args, " "))
	}
	if len(a.Dirs) > 0 {
		fmt.Printf(i18n.T("Папки данных (переедут в хранилище, на их месте будет приманка): ~/%s\n"), strings.Join(a.Dirs, ", ~/"))
	} else {
		fmt.Println(i18n.T("Папки данных не найдены: приложение ещё не запускалось. Его данные появятся сразу в хранилище, а папки с его именем после первого закрытия получат приманку."))
	}
	if len(a.Shares) > 0 {
		fmt.Printf(i18n.T("Открытые приложению папки: %s\n"), strings.Join(a.Shares, ", "))
	}
	fmt.Println(i18n.T("Приложение будет запускаться в песочнице под своей учёткой и видеть вместо домашнего каталога только свои данные и папку ~/SessionVault (как «Загрузки»)."))
}

func unprotect(args []string) error {
	o := parseOpts(args, []string{"-password-stdin"}, nil)
	if len(o.pos) != 1 {
		usage()
	}
	pw, err := readPassword(o.set["-password-stdin"], false)
	if err != nil {
		return err
	}
	defer crypto.Wipe(pw)
	return daemon.Unprotect(o.pos[0], pw, os.Stdout)
}

func recoveryCmd(args []string) error {
	if len(args) < 1 {
		return errors.New(i18n.T("укажи действие: sessionvault recovery create|reset|verify|revoke|status"))
	}
	o := parseOpts(args[1:], []string{"-password-stdin"}, []string{"-file"})
	stdin := o.set["-password-stdin"]
	switch args[0] {
	case "create":
		words, err := daemon.RecoveryCreate(func(name string) ([]byte, error) {
			fmt.Fprintf(os.Stderr, i18n.T("Хранилище %s. "), name)
			return readPassword(stdin, false)
		})
		if err != nil {
			return err
		}
		if f := o.multi["-file"]; len(f) > 0 {
			path := absPath(f[0])
			// O_EXCL: существующий файл (и ссылка на него) не перезаписывается; слова не остаются в истории терминала.
			fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
			if err == nil {
				_, err = fh.WriteString(words + "\n")
				err = errors.Join(err, fh.Close())
			}
			if err != nil {
				return fmt.Errorf(i18n.T("слова не записаны в файл (хранилища уже на новом ключе, повторите create): %w"), err)
			}
			fmt.Println(i18n.T("Ключ восстановления (24 слова) записан в"), path, i18n.T("- перепишите на бумагу и удалите файл."))
			return nil
		}
		fmt.Println(i18n.T("Ключ восстановления (24 слова). Запишите на бумагу по порядку и спрячьте; на экране он больше не появится."))
		fmt.Println(i18n.T("Он открывает все защищённые приложения без пароля. Прежний ключ, если был, больше не работает."))
		fmt.Println()
		fmt.Println(words)
		return nil
	case "verify":
		fmt.Fprint(os.Stderr, i18n.T("Ключ восстановления (24 слова). "))
		words, err := readPassword(stdin, false)
		if err != nil {
			return err
		}
		defer crypto.Wipe(words)
		ok, bad, err := daemon.RecoveryVerify(string(words))
		if err != nil {
			return err
		}
		if len(ok) > 0 {
			fmt.Println(i18n.T("ключ верный, открывает:"), strings.Join(ok, ", "))
		}
		if len(bad) > 0 {
			fmt.Println(i18n.T("не открывает:"), strings.Join(bad, ", "))
		}
		if len(ok) == 0 {
			return errors.New(i18n.T("ключ не подошёл ни к одному хранилищу: проверьте запись слов"))
		}
		return nil
	case "revoke":
		if len(o.pos) != 1 {
			return errors.New(i18n.T("укажи приложение: sessionvault recovery revoke telegram"))
		}
		if err := daemon.RecoveryRevoke(o.pos[0]); err != nil {
			return err
		}
		fmt.Println(i18n.T("ключ восстановления больше не открывает"), o.pos[0])
		return nil
	case "reset":
		fmt.Fprint(os.Stderr, i18n.T("Ключ восстановления (24 слова). "))
		words, err := readPassword(stdin, false)
		if err != nil {
			return err
		}
		defer crypto.Wipe(words)
		fmt.Fprint(os.Stderr, i18n.T("Новый мастер-пароль. "))
		pw, err := readPassword(stdin, true)
		if err != nil {
			return err
		}
		defer crypto.Wipe(pw)
		names, skipped, err := daemon.RecoveryReset(string(words), pw)
		if err != nil {
			return err
		}
		fmt.Println(i18n.T("новый мастер-пароль задан для:"), strings.Join(names, ", "))
		if len(skipped) > 0 {
			fmt.Println(i18n.T("не изменены (ключ их не открывает, прежний пароль остался):"), strings.Join(skipped, ", "))
		}
		return nil
	case "status":
		with, without, err := daemon.RecoveryCovered()
		if err != nil {
			return err
		}
		if len(with) > 0 {
			fmt.Println(i18n.T("ключ восстановления открывает:"), strings.Join(with, ", "))
		}
		if len(without) > 0 {
			fmt.Println(i18n.T("без ключа восстановления:"), strings.Join(without, ", "), i18n.T("(создайте: sessionvault recovery create)"))
		}
		return nil
	}
	return errors.New(i18n.T("неизвестное действие: ") + args[0])
}

func importCmd(args []string) error {
	o := parseOpts(args, []string{"-yes", "-password-stdin"}, []string{"-exe"})
	if len(o.pos) != 1 {
		usage()
	}
	var exe string
	if e := o.multi["-exe"]; len(e) > 0 {
		exe = absPath(e[0])
	}
	name, err := daemon.Import(absPath(o.pos[0]), daemon.ImportOptions{
		Exe: exe,
		Confirm: func(info string) bool {
			fmt.Print(info)
			return o.set["-yes"] || askYes(i18n.T("Принять описание из файла? [y/N] "))
		},
		Ask: func(a daemon.App) ([]byte, error) {
			fmt.Fprintf(os.Stderr, i18n.T("Хранилище %s: введите мастер-пароль или ключ восстановления. "), a.Title)
			return readPassword(o.set["-password-stdin"], false)
		},
	}, os.Stdout)
	if err != nil {
		return err
	}
	fmt.Println(i18n.T("готово:"), name, i18n.T("перенесён"))
	return nil
}

func check() error {
	resp, err := daemon.Call("check", nil, time.Minute)
	if err != nil {
		return err
	}
	var r checkup.Report
	if err := json.Unmarshal([]byte(resp), &r); err != nil {
		return errors.New(i18n.T("служба не дала отчёт (journalctl -u sessionvault)"))
	}
	fmt.Print(checkup.Format(r, term.IsTerminal(int(os.Stdout.Fd()))))
	return nil
}

// requestFor — что попросить у службы по аргументам ярлыка: ссылка (браузер, xdg-open, своя схема приложения),
// веб-приложение Omarchy (--app=) или просто запуск. Прочие флаги ярлыка не передаются: служба запускает приложение только
// со своими аргументами.
func requestFor(name string, args []string) (string, []byte) {
	a, _ := daemon.FindApp(name)
	for _, arg := range args {
		if u, ok := strings.CutPrefix(arg, "--app="); ok && ipc.ValidURL(u) == nil {
			return "webapp " + name, []byte(u)
		}
		if a.AcceptsLink(arg) {
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
		if err := openTerminal(append([]string{daemon.BinPath, "unlock", name}, args...)...); err != nil {
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

// openTerminal — плавающее окно терминала Omarchy (класс TUI.float) с командой.
func openTerminal(cmdline ...string) error {
	t := "xdg-terminal-exec"
	if _, err := exec.LookPath(t); err != nil {
		return errors.New(i18n.T("нет xdg-terminal-exec: откройте терминал и выполните ") + strings.Join(cmdline, " "))
	}
	cmd := exec.Command(t, append([]string{"--app-id=TUI.float", "--title=SessionVault", "-e"}, cmdline...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

// pauseRun выполняет команду в окне терминала и ждёт Enter, чтобы окно не закрылось раньше, чем прочитан итог.
func pauseRun(args []string) int {
	if len(args) == 0 {
		return 2
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	code := 0
	if err := cmd.Run(); err != nil {
		code = 1
	}
	fmt.Println()
	return pause(code)
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

// menu — меню Omarchy (omarchy-menu-select): защищённые приложения и действия.
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
	// У приложений под названием — имя (его меню и возвращает), у действий подписи нет: они узнаются по тексту.
	addText, checkText, recoveryText := i18n.T("Добавить приложение"), i18n.T("Проверить защиту"), i18n.T("Ключ восстановления")
	lockText, statusText := i18n.T("Заблокировать хранилище"), i18n.T("Состояние")
	rows = append(rows, "\U000F0415\t"+addText, "\U000F0483\t"+checkText, "\U000F0306\t"+recoveryText,
		"\U000F033E\t"+lockText, "\U000F02FC\t"+statusText)
	if _, err := exec.LookPath("omarchy-menu-select"); err != nil {
		return status()
	}
	label, key := pick("SessionVault", rows)
	switch {
	case label == "":
		return nil
	case label == addText:
		return menuAdd()
	case label == checkText:
		return openTerminal(daemon.BinPath, "pause-run", daemon.BinPath, "check")
	case label == recoveryText:
		return openTerminal(daemon.BinPath, "pause-run", "sudo", daemon.BinPath, "recovery", "create")
	case label == lockText:
		if _, err := daemon.Call("lock", nil, 5*time.Second); err != nil {
			return err
		}
		notify("SessionVault", i18n.T("Хранилище заблокировано (запущенные приложения — после их закрытия)."))
	case label == statusText:
		st, _ := daemon.Call("status", nil, 5*time.Second)
		running, _ := daemon.Call("running", nil, 5*time.Second)
		notify("SessionVault", fmt.Sprintf(i18n.T("Хранилище: %s\nЗащищены: %s\nЗапущены: %s\n"), stateText(st), orDash(list), orDash(running)))
	case key != "":
		os.Exit(launch(key, nil))
	}
	return nil
}

func pick(title string, rows []string) (label, key string) {
	out, err := exec.Command("omarchy-menu-select", append([]string{title}, rows...)...).Output()
	if err != nil {
		return "", "" // меню закрыто без выбора
	}
	label, key, _ = strings.Cut(strings.TrimSpace(string(out)), "\t")
	return label, key
}

// menuAdd — список программ лаунчера; выбранная добавляется в окне терминала (там sudo спросит пароль системы).
func menuAdd() error {
	home, _ := os.UserHomeDir()
	var rows []string
	for _, c := range daemon.Candidates(home) {
		rows = append(rows, "\U000F0415\t"+c.Title+"\t"+c.ID)
	}
	if len(rows) == 0 {
		notify("SessionVault", i18n.T("Все программы лаунчера уже защищены."))
		return nil
	}
	if _, key := pick(i18n.T("Добавить приложение"), rows); key != "" {
		return openTerminal(daemon.BinPath, "pause-run", "sudo", daemon.BinPath, "add", key)
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
