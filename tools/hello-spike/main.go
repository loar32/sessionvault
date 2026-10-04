// Проба Windows Hello: создаёт ключ, подписывает один challenge дважды и сравнивает подписи.
package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"

	"github.com/loar32/sessionvault/internal/hello"
)

func main() {
	ok, err := hello.Supported()
	fmt.Println("supported:", ok, err)
	if !ok {
		os.Exit(1)
	}
	if len(os.Args) > 1 && os.Args[1] == "create" {
		fmt.Println("create:", hello.Create("sv-spike"))
	}
	challenge := bytes.Repeat([]byte{7}, 32)
	var sigs [][]byte
	for i := 1; i <= 2; i++ {
		s, err := hello.Secret("sv-spike", challenge)
		fmt.Printf("sign %d: len=%d err=%v sha256=%x\n", i, len(s), err, sha256.Sum256(s))
		sigs = append(sigs, s)
	}
	if len(sigs) == 2 && len(sigs[0]) > 0 {
		fmt.Println("deterministic:", bytes.Equal(sigs[0], sigs[1]))
	}
}
