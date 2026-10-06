package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/loar32/sessionvault/internal/audit"
	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/ipc"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"github.com/loar32/sessionvault/internal/service"
	"github.com/loar32/sessionvault/internal/ui/alert"
	"github.com/loar32/sessionvault/internal/ui/prompt"
	"github.com/loar32/sessionvault/internal/ui/tray"
	"github.com/loar32/sessionvault/internal/vault"
	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

const usage = `sessionvault install [-user имя] [-telegram-exe путь]
sessionvault protect [-yes] [-password-stdin] <telegram|chrome|edge|brave|discord>
sessionvault add [-yes] [-copy-dir] [-data имя] -arg "...{data_path}..." имя путь-к-exe каталог-данных
sessionvault refresh <приложение>
sessionvault trust [-yes] <профиль>
sessionvault import-tdata [путь-к-tdata]
sessionvault uninstall
sessionvault restore-backup <профиль>
sessionvault harden [-off]
sessionvault lockdown [-off]
sessionvault hello disable [профиль]
sessionvault fido disable [профиль]
sessionvault recovery create|reset|status
sessionvault export <приложение> <файл>
sessionvault import <файл>
sessionvault run <профиль>
sessionvault open <ссылка>
sessionvault status
sessionvault check [-json|-window]
sessionvault check -fix [-yes|-off]
sessionvault alerts
sessionvault tray`

// Код выхода 3 — основная учётка состоит в администраторах: установщик показывает отдельное сообщение.
const exitMainUserAdmin = 3

// Окно с результатом закрывается вместе с процессом; в видимых окнах установщика (-pause) ждём Enter, но только
// когда есть что прочитать: при ошибке и после import-tdata. Иначе тихое удаление повисло бы на пустой паузе.
var pause bool

// Один читатель на весь процесс: при вводе через pipe несколько вопросов подряд иначе теряли бы буферизованные строки.
var stdinReader = bufio.NewReader(os.Stdin)

func finish(code int) {
	if pause && ownConsole && (code != 0 || os.Args[1] == "import-tdata") {
		fmt.Fprint(os.Stderr, "\nНажмите Enter, чтобы закрыть окно...")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	}
	os.Exit(code)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	profiles.RequireSignature = true
	args := os.Args[2:]
	if i := slices.Index(args, "-pause"); i >= 0 {
		args = slices.Delete(args, i, i+1)
		pause = true
	}
	switch os.Args[1] {
	case "service", "prompt", "tray", "launch", "alert", "hello-unlock", "hello-enroll", "fido-unlock", "fido-enroll":
	default:
		attachConsole()
	}
	var err error
	switch os.Args[1] {
	case "install":
		err = install(args)
	case "protect":
		err = protect(args)
		nudgeService(err)
	case "import-tdata":
		err = importTdata(args)
		nudgeService(err)
	case "uninstall":
		err = uninstall(args)
	case "restore-backup":
		err = restoreBackup(args)
	case "harden":
		err = harden(args)
	case "add":
		err = addCmd(args)
		nudgeService(err)
	case "refresh":
		err = refreshCmd(args)
	case "trust":
		err = trustCmd(args)
	case "lockdown":
		err = lockdownCmd(args)
	case "hello":
		err = helloCmd(args)
	case "recovery":
		err = recoveryCmd(args)
	case "export":
		err = exportCmd(args)
	case "import":
		err = importCmd(args)
		nudgeService(err)
	case "fido":
		err = fidoCmd(args)
	case "hello-unlock", "hello-enroll", "fido-unlock", "fido-enroll":
		err = helloHelper(os.Args[1], args)
	case "open":
		err = openLink(args)
	case "run":
		err = run(args)
	case "check":
		err = check(args)
	case "status":
		err = status()
	case "service":
		err = service.RunService()
	case "tray":
		err = tray.Run()
	case "prompt":
		err = promptWindow(args)
	case "alert":
		err = alertWindow(args)
	case "alerts":
		err = alerts()
	case "launch":
		err = launch(args)
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		if errors.Is(err, service.ErrMainUserAdmin) {
			finish(exitMainUserAdmin)
		}
		finish(1)
	}
	finish(0)
}

func install(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	user := fs.String("user", "", "основная учётка (по умолчанию — вошедшая на консоль)")
	tg := fs.String("telegram-exe", "", "путь к Telegram.exe (по умолчанию ищется сам)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *user == "" {
		u, err := isolation.ConsoleUser()
		if err != nil || u == "" {
			return errors.New("не удалось определить основную учётку: укажи -user")
		}
		*user = u
	}
	if err := service.Install(*user, *tg); err != nil {
		return err
	}
	fmt.Println("готово: служба SessionVault установлена и защищает учётку", *user)
	return nil
}

// Защита приложения: Telegram — перенос существующей tdata, браузеры — новый пустой профиль (прежний удаляется).
func protect(args []string) error {
	fs := flag.NewFlagSet("protect", flag.ContinueOnError)
	stdin := fs.Bool("password-stdin", false, "")
	yes := fs.Bool("yes", false, "удалить прежний профиль браузера без вопроса")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return errors.New("укажи приложение: sessionvault protect telegram|chrome|edge|brave|discord")
	}
	app := fs.Arg(0)
	rest := fs.Args()[1:]
	if app == "telegram" {
		if *stdin {
			rest = append([]string{"-password-stdin"}, rest...)
		}
		return importTdata(rest)
	}
	// Флаги можно писать и после имени приложения.
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errors.New("лишние аргументы: " + strings.Join(fs.Args(), " "))
	}
	confirm := func(path string, size int64) bool {
		fmt.Fprintf(os.Stderr, "Прежний профиль браузера будет УДАЛЁН: %s (%d МБ).\n", path, size>>20)
		fmt.Fprintln(os.Stderr, "Куки и пароли в нём привязаны к вашей учётной записи; новый защищённый профиль начнётся с пустого, входы придётся сделать заново.")
		if *yes {
			return true
		}
		fmt.Fprint(os.Stderr, "Закройте браузер и введите delete для подтверждения: ")
		line, _ := stdinReader.ReadString('\n')
		return strings.TrimSpace(line) == "delete"
	}
	left, err := service.ProtectBrowser(app, confirm, func() ([]byte, error) { return readPassword(*stdin, true) })
	if err != nil {
		return err
	}
	fmt.Println("готово:", app, "защищён; запускайте его из иконки SessionVault в трее")
	if left != "" {
		fmt.Fprintln(os.Stderr, "ВНИМАНИЕ: прежний профиль удалён не полностью, удалите вручную:", left)
	}
	return nil
}

func importTdata(args []string) error {
	fs := flag.NewFlagSet("import-tdata", flag.ContinueOnError)
	stdin := fs.Bool("password-stdin", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !isolation.IsElevated() {
		return errors.New("нужен запуск от администратора")
	}
	if err := isolation.EnablePrivileges("SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege"); err != nil {
		return err
	}
	cfg, err := service.LoadConfig()
	if err != nil {
		return fmt.Errorf("конфигурация не прочитана: сначала install: %w", err)
	}
	src := service.UserTdata(cfg.MainUser)
	if fs.NArg() > 1 {
		return errors.New("укажи один путь к tdata")
	} else if fs.NArg() == 1 {
		if src, err = filepath.Abs(fs.Arg(0)); err != nil {
			return err
		}
	}
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("папка tdata не найдена (%s): укажи путь явно", src)
	}
	p := profiles.Telegram
	v := vault.Vault{Dir: isolation.DataPath(p.Name), DataName: filepath.Base(isolation.WorkPath(p.Name))}
	if _, err := os.Stat(isolation.VaultDir()); err != nil {
		return errors.New("защищённой папки нет: сначала install")
	}
	if v.Exists() {
		return fmt.Errorf("хранилище %s уже создано", v.Dir)
	}
	dst := filepath.Join(isolation.WorkPath(p.Name), p.DataDir)
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("%s уже существует", dst)
	}
	pw, err := readPassword(*stdin, true)
	if err != nil {
		return err
	}
	defer crypto.Wipe(pw)

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	// Исходное место нужно удалению программы, чтобы вернуть данные пользователю; пишем до переноса.
	err = service.UpdateConfig(func(c *service.Config) {
		if c.Origins == nil {
			c.Origins = map[string]string{}
		}
		c.Origins[p.Name] = src
	})
	if err != nil {
		return err
	}
	// Перенос, а не копия: на старом месте открытых данных не остаётся.
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	// Единственная копия сессии не должна остаться без хранилища: при любой ошибке возвращаем её на место.
	ok := false
	defer func() {
		if !ok {
			_ = os.Rename(dst, src)
			_ = os.Remove(filepath.Join(v.Dir, "vault.json"))
		}
	}()
	if err := isolation.ProtectDir(v.Dir); err != nil {
		return err
	}
	dek, err := v.Create(pw)
	if err != nil {
		return err
	}
	defer crypto.Wipe(dek)
	if err := v.Encrypt(dek); err != nil {
		return err
	}
	ok = true
	fmt.Println("tdata зашифрована в", v.Dir)
	return nil
}

func uninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	stdin := fs.Bool("password-stdin", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !service.Installed() {
		fmt.Println("SessionVault уже удалён")
		return nil
	}
	fmt.Fprintln(os.Stderr, "Данные приложений будут расшифрованы и возвращены на прежние места.")
	pw, err := readPassword(*stdin, false)
	if err != nil {
		return err
	}
	defer crypto.Wipe(pw)
	if err := service.Uninstall(pw); err != nil {
		return err
	}
	fmt.Println("готово: данные возвращены, SessionVault удалён")
	return nil
}

// Возвращает предыдущий архив из data.enc.bak, если текущий оказался испорчен. Приложение должно быть закрыто.
func restoreBackup(args []string) error {
	fs := flag.NewFlagSet("restore-backup", flag.ContinueOnError)
	stdin := fs.Bool("password-stdin", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || !profiles.ValidName(fs.Arg(0)) {
		return errors.New("укажи профиль: sessionvault restore-backup telegram")
	}
	if !isolation.IsElevated() {
		return errors.New("нужен запуск от администратора")
	}
	if err := isolation.EnablePrivileges("SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege"); err != nil {
		return err
	}
	name := fs.Arg(0)
	v := vault.Vault{Dir: isolation.DataPath(name), DataName: filepath.Base(isolation.WorkPath(name))}
	if !v.Exists() {
		return fmt.Errorf("хранилища %s нет", name)
	}
	pw, err := readPassword(*stdin, false)
	if err != nil {
		return err
	}
	defer crypto.Wipe(pw)
	dek, err := v.Unlock(pw)
	if err != nil {
		return err
	}
	defer crypto.Wipe(dek)
	release, err := v.Lock()
	if err != nil {
		return err
	}
	defer release()
	if err := v.RestoreBackup(dek); err != nil {
		return err
	}
	fmt.Println("предыдущий архив возвращён")
	return nil
}

// Клиент pipe службы: запрос на запуск; пароль, если нужен, спросит само окно службы.
func run(args []string) error {
	if len(args) != 1 {
		return errors.New("укажи профиль: sessionvault run telegram")
	}
	resp, err := ipc.Call(ipc.CommandPipe, "run "+args[0], 3*time.Minute)
	if err != nil {
		return fmt.Errorf("служба недоступна: %w", err)
	}
	fmt.Println(resp)
	if resp != ipc.Ok {
		return errors.New("запуск не выполнен")
	}
	return nil
}

func status() error {
	resp, err := ipc.Call(ipc.CommandPipe, "status", 10*time.Second)
	if err != nil {
		return fmt.Errorf("служба недоступна: %w", err)
	}
	fmt.Println(resp)
	return nil
}

func promptWindow(args []string) error {
	if len(args) != 2 {
		return errors.New("укажи профиль и pipe")
	}
	return prompt.Run(args[0], args[1])
}

func alertWindow(args []string) error {
	if len(args) != 1 {
		return errors.New("нет данных тревоги")
	}
	return alert.Run(args[0])
}

func lockdownCmd(args []string) error {
	fs := flag.NewFlagSet("lockdown", flag.ContinueOnError)
	off := fs.Bool("off", false, "снять заслон")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := service.Lockdown(*off); err != nil {
		return err
	}
	if *off {
		fmt.Println("сетевой заслон снят")
	} else {
		fmt.Println("сетевой заслон включён: для учётки vault закрыты сеть системных утилит и запуск интерпретаторов; SessionVault сети не имеет")
	}
	return nil
}

func harden(args []string) error {
	fs := flag.NewFlagSet("harden", flag.ContinueOnError)
	off := fs.Bool("off", false, "вернуть прежние значения")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := service.Harden(*off); err != nil {
		return err
	}
	if *off {
		fmt.Println("прежние значения возвращены; перезагрузите компьютер")
	} else {
		fmt.Println("шифрование файла подкачки, отключение гибернации и дампов памяти включены; перезагрузите компьютер.")
		fmt.Println("Гибернация отключена, поэтому быстрый запуск Windows тоже не работает. Вернуть: sessionvault harden -off")
	}
	return nil
}

// Журнал тревог читают администраторы: у обычных учёток доступа к файлу нет.
func alerts() error {
	if audit.IsEnabled() {
		fmt.Println("аудит чтения файлов: включён")
	} else {
		fmt.Println("аудит чтения файлов: НЕ работает (приманка не сработает)")
	}
	b, err := os.ReadFile(service.AlertsPath())
	if os.IsNotExist(err) {
		fmt.Println("тревог не было")
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Print(string(b))
	return nil
}

// Запускается службой от SYSTEM в сессии пользователя: стартует приложение от vault и ждёт его выхода.
func launch(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.New("укажи профиль")
	}
	p, err := profiles.Load(isolation.ProfilesDir(), args[0])
	if err != nil {
		return err
	}
	pw, err := isolation.LoadPassword()
	if err != nil {
		return err
	}
	work := isolation.WorkPath(p.Name)
	cmd := p.CommandLine(work)
	if len(args) == 2 {
		if err := ipc.ValidURL(args[1]); err != nil {
			return err
		}
		cmd += " " + args[1]
	}
	_, proc, cleanup, err := isolation.LaunchAsVault(isolation.VaultUser, pw, cmd, work)
	if err != nil {
		return err
	}
	_, err = windows.WaitForSingleObject(proc, windows.INFINITE)
	cleanup()
	return err
}

// Службе пароль передаётся строкой не длиннее ipc.MaxPassword: более длинный потом нельзя было бы ввести.
func checkPasswordLen(pw []byte) error {
	if len(pw) > ipc.MaxPassword {
		return fmt.Errorf("пароль длиннее %d байт", ipc.MaxPassword)
	}
	return nil
}

// Короткий пароль подбирается быстро, если у вора окажется копия диска с data.enc.
const minPasswordChars = 10

func checkNewPassword(pw []byte) error {
	if utf8.RuneCount(pw) < minPasswordChars {
		return fmt.Errorf("мастер-пароль короче %d символов", minPasswordChars)
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
			return nil, errors.New("пароль не может быть пустым")
		}
		if confirm {
			if err := checkNewPassword(pw); err != nil {
				return nil, err
			}
		}
		return pw, checkPasswordLen(pw)
	}
	fmt.Fprint(os.Stderr, "Мастер-пароль: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if len(pw) == 0 {
		return nil, errors.New("пароль не может быть пустым")
	}
	if err := checkPasswordLen(pw); err != nil {
		return nil, err
	}
	if confirm {
		if err := checkNewPassword(pw); err != nil {
			return nil, err
		}
		fmt.Fprint(os.Stderr, "Повтори пароль: ")
		again, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		defer crypto.Wipe(again)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(pw, again) {
			crypto.Wipe(pw)
			return nil, errors.New("пароли не совпали")
		}
	}
	return pw, nil
}

// Ссылка открывается в защищённом браузере; если хранилище заперто, служба сама покажет окно разблокировки.
func openLink(args []string) error {
	if len(args) != 1 {
		return errors.New("укажи ссылку: sessionvault open https://example.com")
	}
	if err := ipc.ValidURL(args[0]); err != nil {
		return errors.New("ссылка должна быть http(s) без пробелов и кавычек")
	}
	c, err := ipc.Dial(ipc.CommandPipe, 3*time.Second)
	if err != nil {
		return fmt.Errorf("служба недоступна: %w", err)
	}
	defer c.Close()
	if err := c.WriteLine("open"); err != nil {
		return err
	}
	if err := c.WriteLine(args[0]); err != nil {
		return err
	}
	resp, err := c.ReadLine(3*time.Minute, ipc.MaxReply)
	if err != nil {
		return err
	}
	fmt.Println(resp)
	if resp != ipc.Ok {
		return errors.New("ссылка не открыта")
	}
	return nil
}

// Служба проверяет приманки раз в несколько минут; после защиты нового приложения просим сделать это сразу.
func nudgeService(err error) {
	if err == nil {
		service.SyncService()
	}
}
