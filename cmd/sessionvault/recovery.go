package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/service"
)

func recoveryCmd(args []string) error {
	fs := flag.NewFlagSet("recovery", flag.ContinueOnError)
	stdin := fs.Bool("password-stdin", false, "")
	file := fs.String("file", "", "create: записать слова в файл (например, на флешку) вместо экрана")
	if len(args) < 1 {
		return errors.New("укажи действие: sessionvault recovery create|reset|verify|revoke|status")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "create":
		words, err := service.RecoveryCreate(func(name string) ([]byte, error) {
			fmt.Fprintf(os.Stderr, "Хранилище %s. ", name)
			return readPassword(*stdin, false)
		})
		if err != nil {
			return err
		}
		if *file != "" {
			// O_EXCL: существующий файл (и ссылка на него) не перезаписывается; слова не попадают в буфер консоли.
			f, err := os.OpenFile(*file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err == nil {
				_, err = f.WriteString(words + "\n")
				err = errors.Join(err, f.Close())
			}
			if err != nil {
				return fmt.Errorf("слова не записаны в файл (хранилища уже на новом ключе, повторите create): %w", err)
			}
			fmt.Println("Ключ восстановления (24 слова) записан в", *file, "- перепишите на бумагу и удалите файл.")
			return nil
		}
		fmt.Println("Ключ восстановления (24 слова). Запишите на бумагу по порядку и спрячьте; на экране он больше не появится. Закройте это окно, когда запишете.")
		fmt.Println("Он открывает все защищённые приложения без пароля и Windows Hello. Прежний ключ, если был, больше не работает.")
		fmt.Println()
		fmt.Println(words)
		return nil
	case "verify":
		fmt.Fprint(os.Stderr, "Ключ восстановления (24 слова). ")
		words, err := readPassword(*stdin, false)
		if err != nil {
			return err
		}
		defer crypto.Wipe(words)
		ok, bad, err := service.RecoveryVerify(string(words))
		if err != nil {
			return err
		}
		if len(ok) > 0 {
			fmt.Println("ключ верный, открывает:", strings.Join(ok, ", "))
		}
		if len(bad) > 0 {
			fmt.Println("не открывает:", strings.Join(bad, ", "))
		}
		if len(ok) == 0 {
			return errors.New("ключ не подошёл ни к одному хранилищу: проверьте запись слов")
		}
		return nil
	case "revoke":
		if fs.NArg() != 1 {
			return errors.New("укажи приложение: sessionvault recovery revoke telegram")
		}
		if err := service.RecoveryRevoke(fs.Arg(0)); err != nil {
			return err
		}
		fmt.Println("ключ восстановления больше не открывает", fs.Arg(0))
		return nil
	case "reset":
		fmt.Fprint(os.Stderr, "Ключ восстановления (24 слова). ")
		words, err := readPassword(*stdin, false)
		if err != nil {
			return err
		}
		defer crypto.Wipe(words)
		fmt.Fprint(os.Stderr, "Новый мастер-пароль. ")
		pw, err := readPassword(*stdin, true)
		if err != nil {
			return err
		}
		defer crypto.Wipe(pw)
		names, skipped, err := service.RecoveryReset(string(words), pw)
		if err != nil {
			return err
		}
		fmt.Println("новый мастер-пароль задан для:", strings.Join(names, ", "))
		if len(skipped) > 0 {
			fmt.Println("не изменены (ключ их не открывает, прежний пароль остался):", strings.Join(skipped, ", "))
		}
		return nil
	case "status":
		with, without, err := service.RecoveryCovered()
		if err != nil {
			return err
		}
		if len(with) > 0 {
			fmt.Println("ключ восстановления открывает:", strings.Join(with, ", "))
		}
		if len(without) > 0 {
			fmt.Println("без ключа восстановления:", strings.Join(without, ", "), "(создайте: sessionvault recovery create)")
		}
		return nil
	}
	return errors.New("неизвестное действие: " + args[0])
}

func exportCmd(args []string) error {
	if len(args) != 2 {
		return errors.New("укажи приложение и файл: sessionvault export telegram D:\\telegram.svx")
	}
	if err := service.Export(args[0], args[1]); err != nil {
		return err
	}
	fmt.Println("готово:", args[1])
	fmt.Println("Файл зашифрован; на новом ПК его открывает мастер-пароль или ключ восстановления. Вход через Windows Hello на новом ПК включается заново.")
	return nil
}

func importCmd(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	stdin := fs.Bool("password-stdin", false, "")
	exe := fs.String("exe", "", "собственное приложение (add): путь к его .exe на этом ПК")
	copyDir := fs.Bool("copy-dir", false, "с -exe: копировать весь каталог приложения")
	yes := fs.Bool("yes", false, "с -exe: подтвердить профиль из файла без вопроса")
	pos, err := parseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("укажи файл: sessionvault import [-exe путь-к-exe [-copy-dir]] D:\telegram.svx")
	}
	app, err := service.Import(pos[0], func(app string) ([]byte, error) {
		fmt.Fprintf(os.Stderr, "Хранилище %s: введите мастер-пароль или ключ восстановления. ", app)
		return readPassword(*stdin, false)
	}, service.CustomImport{Exe: *exe, CopyDir: *copyDir, Confirm: func(info string) bool {
		fmt.Fprint(os.Stderr, info)
		return *yes || askYes("Принять профиль из файла? Введите yes: ")
	}})
	if err != nil {
		return err
	}
	fmt.Println("готово:", app, "перенесён; запускайте его из иконки SessionVault в трее")
	fmt.Println("Если на этом ПК у приложения уже была своя сессия, она осталась на прежнем месте: закройте приложение и удалите её вручную.")
	return nil
}
