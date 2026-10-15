package crypto

import (
	"bytes"
	"errors"
	"io"
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

func TestStreamRoundTrip(t *testing.T) {
	key, _ := NewKey()
	aad := []byte("hdr")
	for _, size := range []int{0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, 3 * ChunkSize} {
		plain := bytes.Repeat([]byte{7}, size)
		var buf bytes.Buffer
		w, err := NewSealWriter(key, aad, &buf)
		if err != nil {
			t.Fatal(err)
		}
		// Запись кусками разной длины: границы блоков не должны зависеть от того, как пишут.
		for p := plain; len(p) > 0; {
			k := min(len(p), 1000+len(p)%3333)
			if _, err := w.Write(p[:k]); err != nil {
				t.Fatal(err)
			}
			p = p[k:]
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		r, err := NewOpenReader(key, aad, &buf)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("размер %d: %v", size, err)
		}
	}
}

func TestStreamWrongAADRejected(t *testing.T) {
	key, _ := NewKey()
	var buf bytes.Buffer
	w, _ := NewSealWriter(key, []byte("SVD3-1"), &buf)
	_, _ = w.Write([]byte("данные"))
	_ = w.Close()
	r, _ := NewOpenReader(key, []byte("SVD3-2"), &buf)
	if _, err := io.ReadAll(r); !errors.Is(err, ErrStream) {
		t.Fatalf("поток с другим заголовком принят: %v", err)
	}
}
