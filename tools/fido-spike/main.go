// Проба ключа FIDO2 (в релиз не входит). Запускать под обычной учёткой с вставленным ключом:
//
//	fido-spike          — поддерживается ли hmac-secret; создаёт учётные данные, дважды получает секрет и сравнивает
//	fido-spike smoke    — без ключа: оба вызова с таймаутом 4 с; код 0x80070057 (INVALIDARG) означает неверную раскладку структур
//	fido-spike secret <credHex> <saltHex> — секрет для уже созданных учётных данных (проверка на другом ПК)
//
// Секрет не печатается целиком: только SHA-256 от него.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/loar32/sessionvault/internal/fido"
)

func main() {
	fmt.Println("webauthn hmac-secret поддерживается:", fido.Supported())
	if !fido.Supported() {
		os.Exit(1)
	}
	if len(os.Args) == 2 && os.Args[1] == "smoke" {
		fido.Timeout = 4 * time.Second
		_, err := fido.Create()
		fmt.Println("create:", err)
		_, err = fido.Secret(bytes.Repeat([]byte{1}, 64), bytes.Repeat([]byte{2}, 32))
		fmt.Println("secret:", err)
		return
	}
	if len(os.Args) == 4 && os.Args[1] == "secret" {
		fido.Timeout = 6 * time.Second
		id, err1 := hex.DecodeString(os.Args[2])
		salt, err2 := hex.DecodeString(os.Args[3])
		if err1 != nil || err2 != nil {
			fmt.Println("неверный hex")
			os.Exit(2)
		}
		s, err := fido.Secret(id, salt)
		fmt.Printf("secret: len=%d err=%v sha256=%x\n", len(s), err, sha256.Sum256(s))
		return
	}
	fmt.Println("Создание учётных данных: введите PIN ключа и коснитесь его…")
	id, err := fido.Create()
	fmt.Printf("create: id len=%d err=%v\nid=%x\n", len(id), err, id)
	if err != nil {
		os.Exit(1)
	}
	salt := bytes.Repeat([]byte{7}, 32)
	fmt.Printf("salt=%x\n", salt)
	var got [][]byte
	for i := 1; i <= 2; i++ {
		fmt.Printf("Получение секрета %d: PIN и касание…\n", i)
		s, err := fido.Secret(id, salt)
		fmt.Printf("secret %d: len=%d err=%v sha256=%x\n", i, len(s), err, sha256.Sum256(s))
		got = append(got, s)
	}
	fmt.Println("детерминирован:", len(got[0]) == 32 && bytes.Equal(got[0], got[1]))
	salt[0] ^= 1
	s, err := fido.Secret(id, salt)
	fmt.Printf("другая соль: err=%v отличается=%v\n", err, !bytes.Equal(s, got[0]))
}
