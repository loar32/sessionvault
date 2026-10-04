package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/loar32/sessionvault/internal/hello"
	"github.com/loar32/sessionvault/internal/ipc"
	"github.com/loar32/sessionvault/internal/service"
)

// Запускается службой под токеном пользователя: показывает окно Windows Hello и отдаёт службе подпись challenge.
// Ничего не пишет на диск и не выводит в консоль.
func helloHelper(mode string, args []string) error {
	if len(args) != 1 {
		return errors.New("укажи pipe")
	}
	c, err := ipc.Dial(args[0], 10*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	line, err := c.ReadLine(30*time.Second, 160)
	if err != nil {
		return err
	}
	name, chHex, ok := strings.Cut(line, " ")
	challenge, derr := hex.DecodeString(chHex)
	if !ok || name == "" || derr != nil || len(challenge) == 0 {
		_ = c.WriteLine("err запрос неверен")
		return errors.New("неверный запрос службы")
	}
	secret, err := helloSecret(mode, name, challenge)
	if err != nil {
		_ = c.WriteLine("err " + err.Error())
		return err
	}
	return c.WriteLine("ok " + hex.EncodeToString(secret))
}

func helloSecret(mode, name string, challenge []byte) ([]byte, error) {
	if ok, err := hello.Supported(); err != nil || !ok {
		return nil, hello.ErrNotSupported
	}
	if mode == "hello-enroll" {
		exists, err := hello.Exists(name)
		if err != nil {
			return nil, err
		}
		if !exists {
			if err := hello.Create(name); err != nil {
				return nil, err
			}
		}
	}
	return hello.Secret(name, challenge)
}

// sessionvault hello disable [профиль]
func helloCmd(args []string) error {
	if len(args) < 1 || args[0] != "disable" || len(args) > 2 {
		return errors.New("использование: sessionvault hello disable [профиль]")
	}
	profile := ""
	if len(args) == 2 {
		profile = args[1]
	}
	if err := service.DisableHello(profile); err != nil {
		return err
	}
	fmt.Println("вход через Windows Hello отключён; хранилище открывается мастер-паролем")
	return nil
}
