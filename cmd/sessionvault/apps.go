package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/loar32/sessionvault/internal/i18n"
	"os"
	"strings"

	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"github.com/loar32/sessionvault/internal/service"
)

type argList []string

func (a *argList) String() string     { return strings.Join(*a, " ") }
func (a *argList) Set(s string) error { *a = append(*a, s); return nil }

// parseMixed разбирает флаги, стоящие и до, и после позиционных аргументов.
func parseMixed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func askYes(prompt string) bool {
	fmt.Fprint(os.Stderr, prompt)
	line, _ := stdinReader.ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "yes")
}

// sessionvault add [-yes] [-copy-dir] [-data имя] -arg "...{data_path}..." имя путь-к-exe каталог-данных
func addCmd(args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	yes := fs.Bool("yes", false, i18n.T("подтвердить без вопроса"))
	stdin := fs.Bool("password-stdin", false, "")
	copyDir := fs.Bool("copy-dir", false, i18n.T("копировать весь каталог с exe (приложение лежит в профиле пользователя)"))
	data := fs.String("data", "", i18n.T("имя папки данных внутри рабочей папки (по умолчанию имя каталога данных)"))
	var launch argList
	fs.Var(&launch, "arg", i18n.T("аргумент запуска (можно несколько); {data_path} — рабочая папка приложения"))
	pos, err := parseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 3 {
		return errors.New(`использование: sessionvault add [-yes] [-copy-dir] [-data имя] -arg "--user-data-dir={data_path}\data" имя путь-к-exe каталог-данных`)
	}
	o := service.AddOptions{Name: pos[0], Exe: pos[1], Origin: pos[2], DataDir: *data, Args: launch, CopyDir: *copyDir}
	err = service.AddApp(o, func(info string) bool {
		fmt.Fprint(os.Stderr, info)
		return *yes || askYes(i18n.T("Добавить приложение? Введите yes: "))
	}, func() ([]byte, error) { return readPassword(*stdin, true) })
	if err != nil {
		return err
	}
	fmt.Println(i18n.T("готово:"), o.Name, i18n.T("защищён; запускайте его из иконки SessionVault в трее"))
	return nil
}

func refreshCmd(args []string) error {
	if len(args) != 1 {
		return errors.New(i18n.T("использование: sessionvault refresh <приложение>"))
	}
	if err := service.RefreshApp(args[0]); err != nil {
		return err
	}
	fmt.Println(i18n.T("копия приложения обновлена"))
	return nil
}

// sessionvault trust [-yes] <профиль>: подписать профиль, прочитанный из файла как есть (после ручной правки).
func trustCmd(args []string) error {
	fs := flag.NewFlagSet("trust", flag.ContinueOnError)
	yes := fs.Bool("yes", false, i18n.T("подтвердить без вопроса"))
	pos, err := parseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || !profiles.ValidName(pos[0]) {
		return errors.New(i18n.T("использование: sessionvault trust [-yes] <профиль>"))
	}
	if !isolation.IsElevated() {
		return errors.New(i18n.T("нужен запуск от администратора"))
	}
	fmt.Fprintf(os.Stderr, i18n.T("Профиль %s будет подписан как есть: файл %s\\%s.json запускается под учётной записью приложения с доступом к расшифрованным данным.\n"),
		pos[0], isolation.ProfilesDir(), pos[0])
	if !*yes && !askYes(i18n.T("Вы проверили его содержимое? Введите yes: ")) {
		return errors.New(i18n.T("отменено"))
	}
	if err := profiles.Trust(isolation.ProfilesDir(), pos[0]); err != nil {
		return err
	}
	fmt.Println(i18n.T("профиль подписан"))
	return nil
}
