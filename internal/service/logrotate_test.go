package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotatingFileRotatesWhileRunning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.log")
	r, err := openRotating(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	chunk := []byte(strings.Repeat("x", 1<<19))
	for range 5 {
		if _, err := r.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatal("ротации не было:", err)
	}
	if fi, _ := os.Stat(path); fi.Size() > 2*maxLogSize {
		t.Fatalf("журнал не ограничен: %d", fi.Size())
	}
}

func TestRotateLogKeepGenerations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "memory.log")
	big := []byte(strings.Repeat("x", maxLogSize+1))
	for i := range 5 {
		if err := os.WriteFile(path, append([]byte{byte('a' + i)}, big...), 0o600); err != nil {
			t.Fatal(err)
		}
		rotateLogKeep(path, 3)
	}
	for i, want := range map[int]byte{1: 'e', 2: 'd', 3: 'c'} {
		b, err := os.ReadFile(fmt.Sprintf("%s.%d", path, i))
		if err != nil || b[0] != want {
			t.Fatalf("часть .%d: %v %q", i, err, b[:1])
		}
	}
	if _, err := os.Stat(path + ".4"); err == nil {
		t.Fatal("хранится больше частей, чем задано")
	}
}
