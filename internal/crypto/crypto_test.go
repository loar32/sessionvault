package crypto

import (
	"bytes"
	"testing"
)

var fast = Params{Memory: 64, Time: 1, Threads: 1}

func TestDeriveKey(t *testing.T) {
	salt, _ := NewSalt()
	a := DeriveKey([]byte("pw"), salt, fast)
	if !bytes.Equal(a, DeriveKey([]byte("pw"), salt, fast)) {
		t.Fatal("тот же пароль и соль дали разные ключи")
	}
	if bytes.Equal(a, DeriveKey([]byte("pw2"), salt, fast)) {
		t.Fatal("разные пароли дали одинаковый ключ")
	}
	if len(a) != KeySize {
		t.Fatalf("длина ключа %d", len(a))
	}
}

func TestSealOpen(t *testing.T) {
	key, _ := NewKey()
	blob, err := Seal(key, []byte("секрет"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, blob)
	if err != nil || string(got) != "секрет" {
		t.Fatalf("round-trip: %q, %v", got, err)
	}
}

func TestOpenRejects(t *testing.T) {
	key, _ := NewKey()
	other, _ := NewKey()
	blob, _ := Seal(key, []byte("данные"))
	if _, err := Open(other, blob); err == nil {
		t.Fatal("чужой ключ принят")
	}
	blob[len(blob)-1] ^= 1
	if _, err := Open(key, blob); err == nil {
		t.Fatal("подменённый шифротекст принят")
	}
	if _, err := Open(key, []byte{1, 2}); err == nil {
		t.Fatal("обрезанные данные приняты")
	}
}

func TestNonceUnique(t *testing.T) {
	key, _ := NewKey()
	seen := map[string]bool{}
	for range 10000 {
		blob, err := Seal(key, []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		n := string(blob[:12])
		if seen[n] {
			t.Fatal("nonce повторился")
		}
		seen[n] = true
	}
}

func TestWipeAndLock(t *testing.T) {
	k, _ := NewKey()
	if err := Lock(k); err != nil {
		t.Fatal(err)
	}
	Wipe(k)
	Unlock(k)
	if !bytes.Equal(k, make([]byte, KeySize)) {
		t.Fatal("ключ не обнулён")
	}
}
