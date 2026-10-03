package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/ipc"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"github.com/loar32/sessionvault/internal/service"
	"github.com/loar32/sessionvault/internal/ui/prompt"
	"github.com/loar32/sessionvault/internal/vault"
	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

const usage = `sessionvault install [-user имя] [-telegram-exe путь]
sessionvault import-tdata <путь-к-tdata>
sessionvault run <профиль>
sessionvault status`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	case "install":
		err = install(args)
	case "import-tdata":
		err = importTdata(args)
	case "run":
		err = run(args)
	case "status":
		err = status()
	case "service":
		err = service.RunService()
	case "prompt":
		err = promptWindow(args)
	case "launch":
		err = launch(args)
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}
}

func install(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	user := fs.String("user", "", "основная учётка (по умолчанию — вошедшая на консоль)")
	tg := fs.String("telegram-exe", profiles.Telegram.Exe, "путь к Telegram.exe")
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

func importTdata(args []string) error {
	fs := flag.NewFlagSet("import-tdata", flag.ContinueOnError)
	stdin := fs.Bool("password-stdin", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("укажи путь к tdata")
	}
	if !isolation.IsElevated() {
		return errors.New("нужен запуск от администратора")
	}
	if err := isolation.EnablePrivileges("SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege"); err != nil {
		return err
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
	// Перенос, а не копия: на старом месте открытых данных не остаётся.
	if err := os.Rename(fs.Arg(0), dst); err != nil {
		return err
	}
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
	fmt.Println("tdata зашифрована в", v.Dir)
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
	if len(args) != 1 {
		return errors.New("укажи профиль")
	}
	return prompt.Run(args[0])
}

// Запускается службой от SYSTEM в сессии пользователя: стартует приложение от vault и ждёт его выхода.
func launch(args []string) error {
	if len(args) != 1 {
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
	_, proc, err := isolation.LaunchAsVault(isolation.VaultUser, pw, p.CommandLine(work), work)
	if err != nil {
		return err
	}
	_, err = windows.WaitForSingleObject(proc, windows.INFINITE)
	return err
}

func readPassword(stdin, confirm bool) ([]byte, error) {
	if stdin {
		line, err := bufio.NewReader(os.Stdin).ReadBytes('\n')
		if err != nil && len(line) == 0 {
			return nil, err
		}
		pw := bytes.TrimRight(line, "\r\n")
		if len(pw) == 0 {
			return nil, errors.New("пароль не может быть пустым")
		}
		return pw, nil
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
	if confirm {
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
