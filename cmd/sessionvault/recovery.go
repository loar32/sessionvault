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
	if len(args) < 1 {
		return errors.New("укажи действие: sessionvault recovery create|reset|status")
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
		fmt.Println("Ключ восстановления (24 слова). Запишите на бумагу по порядку и спрячьте; на экране он больше не появится. Закройте это окно, когда запишете.")
		fmt.Println("Он открывает все защищённые приложения без пароля и Windows Hello. Прежний ключ, если был, больше не работает.")
		fmt.Println()
		fmt.Println(words)
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return errors.New("укажи файл: sessionvault import D:\\telegram.svx")
	}
	file := fs.Arg(0)
	// Флаг можно писать и после имени файла.
	if err := fs.Parse(fs.Args()[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("лишние аргументы")
	}
	app, err := service.Import(file, func(app string) ([]byte, error) {
		fmt.Fprintf(os.Stderr, "Хранилище %s: введите мастер-пароль или ключ восстановления. ", app)
		return readPassword(*stdin, false)
	})
	if err != nil {
		return err
	}
	fmt.Println("готово:", app, "перенесён; запускайте его из иконки SessionVault в трее")
	fmt.Println("Если на этом ПК у приложения уже была своя сессия, она осталась на прежнем месте: закройте приложение и удалите её вручную.")
	return nil
}
