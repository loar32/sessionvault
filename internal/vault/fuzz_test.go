package vault

import (
	"os"
	"path/filepath"
	"testing"
)

// Архив приходит из расшифрованного хранилища, но его содержимое собирало приложение под vault: распаковка службой
// от SYSTEM не должна выходить за пределы рабочей папки ни при каком содержимом.
func FuzzUnpack(f *testing.F) {
	src := f.TempDir()
	_ = os.MkdirAll(filepath.Join(src, "a"), 0o755)
	_ = os.WriteFile(filepath.Join(src, "a", "b.txt"), []byte("x"), 0o644)
	good, _, _ := packDir(src, nil)
	f.Add(good)
	f.Add([]byte("garbage"))
	f.Fuzz(func(t *testing.T, data []byte) {
		base := t.TempDir()
		root := filepath.Join(base, "work")
		_ = unpackDir(data, root)
		entries, err := os.ReadDir(base)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.Name() != "work" {
				t.Fatalf("распаковка создала %q рядом с рабочей папкой", e.Name())
			}
		}
	})
}
