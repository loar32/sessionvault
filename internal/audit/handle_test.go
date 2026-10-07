package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenDirChecked(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	h, err := OpenDirChecked(real, 0x80, ShareAll)
	if err != nil {
		t.Fatal(err)
	}
	_ = h
	file := filepath.Join(real, "f")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDirChecked(file, 0x80, ShareAll); err == nil {
		t.Fatal("файл принят за папку")
	}
	// junction: mklink /J
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("ссылки недоступны:", err)
	}
	if _, err := OpenDirChecked(link, 0x80, ShareAll); err == nil {
		t.Fatal("ссылка принята за папку")
	}
	if _, err := OpenDirChecked(filepath.Join(link, "x"), 0x80, ShareAll); err == nil {
		t.Fatal("путь через ссылку принят")
	}
}

func TestFileIDHardlink(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a")
	b := filepath.Join(root, "b")
	if err := os.WriteFile(a, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Fatal(err)
	}
	ka, err := FileID(a)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := FileID(b)
	if err != nil {
		t.Fatal(err)
	}
	if ka != kb {
		t.Fatalf("у жёсткой ссылки другой ключ: %v %v", ka, kb)
	}
	c := filepath.Join(root, "c")
	if err := os.Rename(a, c); err != nil {
		t.Fatal(err)
	}
	if kc, _ := FileID(c); kc != ka {
		t.Fatal("после переименования ключ изменился")
	}
}

func TestDOSPath(t *testing.T) {
	nt, err := NTPath(`C:\Windows`)
	if err != nil {
		t.Skip(err)
	}
	if got, ok := DOSPath(nt); !ok || got != `C:\Windows` {
		t.Fatalf("DOSPath(%q) = %q, %v", nt, got, ok)
	}
}

func TestDOSPathKeepsDriveLetterForm(t *testing.T) {
	if got, ok := DOSPath(`C:\Users\x\f`); !ok || got != `C:\Users\x\f` {
		t.Fatalf("путь с буквой диска изменён: %q, %v", got, ok)
	}
}
