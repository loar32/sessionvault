package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
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
	if len(args) != 1 {
		return errors.New("укажи путь к tdata")
	}
	if err := needElevated(); err != nil {
		return err
	}
	p := profiles.Telegram
	dst := filepath.Join(isolation.DataPath(p.Name), p.DataDir)
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("%s уже существует", dst)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	// Перенос, а не копия: на старом месте открытых данных не остаётся.
	if err := os.Rename(args[0], dst); err != nil {
		return err
	}
	if err := isolation.ProtectVault(isolation.DataPath(p.Name)); err != nil {
		return err
	}
	fmt.Println("tdata перенесена в", dst)
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
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	if err := needElevated(); err != nil {
		return err
	}
	pw, err := isolation.LoadPassword()
	if err != nil {
		return fmt.Errorf("пароль vault не прочитан (был setup?): %w", err)
	}
	data := isolation.DataPath(p.Name)
	pid, err := isolation.Launch(isolation.VaultUser, pw, p.CommandLine(*exe, data), data)
	if err != nil {
		return err
	}
	fmt.Println("pid:", pid)
	return nil
}

func status() {
	fmt.Println("учётка vault:", isolation.UserExists(isolation.VaultUser))
	fmt.Println("пароль сохранён:", isolation.PasswordSaved())
	_, err := os.Stat(isolation.VaultDir())
	fmt.Println("папка хранения:", err == nil)
	fmt.Println("текущий процесс от администратора:", isolation.IsElevated())
}
