package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"github.com/loar32/sessionvault/internal/vault"
	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

const usage = `sessionvault setup <основная-учётка>
sessionvault import-tdata <путь-к-tdata>
sessionvault run telegram [-exe путь]
sessionvault status`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "setup":
		err = setup(os.Args[2:])
	case "import-tdata":
		err = importTdata(os.Args[2:])
	case "run":
		err = run(os.Args[2:])
	case "status":
		status()
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}
}

func needElevated() error {
	if !isolation.IsElevated() {
		return errors.New("нужен запуск от администратора")
	}
	return isolation.EnablePrivileges("SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege")
}

func setup(args []string) error {
	if len(args) != 1 {
		return errors.New("укажи имя основной учётки: sessionvault setup <имя>")
	}
	if err := needElevated(); err != nil {
		return err
	}
	admin, err := isolation.IsAdminUser(args[0])
	if err != nil {
		return err
	}
	if admin {
		return fmt.Errorf("%s состоит в администраторах: администратор обходит права файлов, защита не будет работать", args[0])
	}

	if err := os.MkdirAll(isolation.BaseDir(), 0o755); err != nil {
		return err
	}
	if !isolation.PasswordSaved() {
		pw, err := isolation.GeneratePassword()
		if err != nil {
			return err
		}
		if err := isolation.CreateUser(isolation.VaultUser, pw); err != nil {
			return err
		}
		if err := isolation.SavePassword(pw); err != nil {
			return err
		}
	} else if !isolation.UserExists(isolation.VaultUser) {
		return errors.New("пароль vault сохранён, но учётки нет: удали vault.pwd и повтори")
	}
	if err := isolation.HideFromLogon(isolation.VaultUser); err != nil {
		return err
	}
	if err := isolation.SetupVaultDir(); err != nil {
		return err
	}
	fmt.Println("готово: учётка vault и защищённая папка", isolation.VaultDir())
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
	if err := needElevated(); err != nil {
		return err
	}
	p := profiles.Telegram
	v := vault.Vault{Dir: isolation.DataPath(p.Name), DataName: p.DataDir}
	if _, err := os.Stat(isolation.VaultDir()); err != nil {
		return errors.New("защищённой папки нет: сначала setup")
	}
	if v.Exists() {
		return fmt.Errorf("хранилище %s уже создано", v.Dir)
	}
	dst := filepath.Join(v.Dir, p.DataDir)
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("%s уже существует", dst)
	}
	pw, err := readPassword(*stdin, true)
	if err != nil {
		return err
	}
	defer crypto.Wipe(pw)

	if err := os.MkdirAll(v.Dir, 0o755); err != nil {
		return err
	}
	// Перенос, а не копия: на старом месте открытых данных не остаётся.
	if err := os.Rename(fs.Arg(0), dst); err != nil {
		return err
	}
	if err := isolation.ProtectVault(v.Dir); err != nil {
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

func run(args []string) error {
	if len(args) < 1 {
		return errors.New("укажи профиль: sessionvault run telegram")
	}
	p, err := profiles.Get(args[0])
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	exe := fs.String("exe", p.Exe, "путь к exe приложения")
	stdin := fs.Bool("password-stdin", false, "")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	if err := needElevated(); err != nil {
		return err
	}
	v := vault.Vault{Dir: isolation.DataPath(p.Name), DataName: p.DataDir}
	if !v.Exists() {
		return errors.New("хранилища нет: сначала import-tdata")
	}
	release, err := v.Lock()
	if err != nil {
		return err
	}
	defer release()

	pw, err := readPassword(*stdin, false)
	if err != nil {
		return err
	}
	dek, err := v.Unlock(pw)
	crypto.Wipe(pw)
	if err != nil {
		return err
	}
	defer crypto.Wipe(dek)
	if err := crypto.Lock(dek); err != nil {
		return err
	}
	defer crypto.Unlock(dek)

	lpw, err := isolation.LoadPassword()
	if err != nil {
		return fmt.Errorf("пароль vault не прочитан (был setup?): %w", err)
	}
	if v.NeedsRecovery() {
		fmt.Println("после прошлого запуска остались открытые данные, дошифровываю")
		if err := v.Encrypt(dek); err != nil {
			return err
		}
	}
	if err := v.Decrypt(dek); err != nil {
		return err
	}

	pid, h, err := isolation.Launch(isolation.VaultUser, lpw, p.CommandLine(*exe, v.Dir), v.Dir)
	if err != nil {
		return errors.Join(err, v.Encrypt(dek))
	}
	if err := isolation.KillOnClose(h); err != nil {
		_ = windows.TerminateProcess(h, 1)
		return errors.Join(err, v.Encrypt(dek))
	}
	fmt.Println("pid:", pid)

	// Ctrl+C не должен прервать шифрование после выхода приложения.
	signal.Ignore(os.Interrupt)
	if err := isolation.WaitExit(h); err != nil {
		return err
	}
	if err := v.Encrypt(dek); err != nil {
		return err
	}
	fmt.Println("приложение закрыто, данные зашифрованы")
	return nil
}

func readPassword(stdin, confirm bool) ([]byte, error) {
	if stdin {
		line, err := bufio.NewReader(os.Stdin).ReadBytes('\n')
		if err != nil && len(line) == 0 {
			return nil, err
		}
		return bytes.TrimRight(line, "\r\n"), nil
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

func status() {
	fmt.Println("учётка vault:", isolation.UserExists(isolation.VaultUser))
	fmt.Println("пароль сохранён:", isolation.PasswordSaved())
	_, err := os.Stat(isolation.VaultDir())
	fmt.Println("папка хранения:", err == nil)
	fmt.Println("текущий процесс от администратора:", isolation.IsElevated())
}
