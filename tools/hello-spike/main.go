// Проба и тестовые команды Windows Hello (в релиз не входит).
//
//	hello-spike                          — поддерживается ли Hello; подпись fixed challenge дважды (ключ должен существовать)
//	hello-spike create                   — то же, но ключ сначала создаётся
//	hello-spike secret <challengeHex>    — создать ключ SessionVault при необходимости и напечатать секрет (из сеанса пользователя)
//	hello-spike enable <профиль> <challengeHex> <secretHex> — слот Hello в хранилище; мастер-пароль со stdin (от администратора)
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/loar32/sessionvault/internal/hello"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/vault"
)

const keyName = "SessionVault"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Println("ошибка:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) >= 1 && args[0] == "secret" {
		return secret(args[1:])
	}
	if len(args) >= 1 && args[0] == "enable" {
		return enable(args[1:])
	}
	ok, err := hello.Supported()
	fmt.Println("supported:", ok, err)
	if !ok {
		return errors.New("вход Windows Hello не настроен")
	}
	if len(args) > 0 && args[0] == "create" {
		fmt.Println("create:", hello.Create("sv-spike"))
	}
	challenge := bytes.Repeat([]byte{7}, 32)
	var sigs [][]byte
	for i := 1; i <= 2; i++ {
		s, err := hello.Secret("sv-spike", challenge)
		fmt.Printf("sign %d: len=%d err=%v sha256=%x\n", i, len(s), err, sha256.Sum256(s))
		sigs = append(sigs, s)
	}
	if len(sigs[0]) > 0 {
		fmt.Println("deterministic:", bytes.Equal(sigs[0], sigs[1]))
	}
	return nil
}

func secret(args []string) error {
	if len(args) != 1 {
		return errors.New("secret <challengeHex>")
	}
	challenge, err := hex.DecodeString(args[0])
	if err != nil {
		return err
	}
	exists, err := hello.Exists(keyName)
	if err != nil {
		return err
	}
	if !exists {
		if err := hello.Create(keyName); err != nil {
			return err
		}
	}
	s, err := hello.Secret(keyName, challenge)
	if err != nil {
		return err
	}
	fmt.Println("secret=" + hex.EncodeToString(s))
	return nil
}

func enable(args []string) error {
	if len(args) != 3 {
		return errors.New("enable <профиль> <challengeHex> <secretHex>")
	}
	challenge, err := hex.DecodeString(args[1])
	if err != nil {
		return err
	}
	sec, err := hex.DecodeString(args[2])
	if err != nil {
		return err
	}
	pw, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && pw == "" {
		return err
	}
	v := vault.Vault{Dir: isolation.DataPath(args[0]), DataName: "work"}
	dek, err := v.Unlock([]byte(strings.TrimRight(pw, "\r\n")))
	if err != nil {
		return err
	}
	if err := v.EnableHello(dek, keyName, challenge, sec); err != nil {
		return err
	}
	fmt.Println("слот Hello записан")
	return nil
}
