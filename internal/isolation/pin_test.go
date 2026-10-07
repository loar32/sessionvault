package isolation

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPinParentBlocksRename(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(filepath.Dir(child), 0o755); err != nil {
		t.Fatal(err)
	}
	release, err := PinParent(child)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "a"), filepath.Join(root, "x")); err == nil {
		t.Fatal("родитель переименован, хотя папка закреплена")
	}
	release()
	if err := os.Rename(filepath.Join(root, "a"), filepath.Join(root, "x")); err != nil {
		t.Fatal("после снятия закрепления переименование не прошло:", err)
	}
}

func TestPinParentRejectsLink(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("ссылки недоступны:", err)
	}
	if _, err := PinParent(filepath.Join(link, "child")); err == nil {
		t.Fatal("путь через ссылку принят")
	}
}
