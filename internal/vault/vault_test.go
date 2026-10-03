package vault

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func newVault(t *testing.T) Vault {
	t.Helper()
	v := Vault{Dir: t.TempDir(), DataName: "tdata"}
	write(t, filepath.Join(v.dataDir(), "key_datas"), "секрет")
	write(t, filepath.Join(v.dataDir(), "emoji", "cache"), "кэш")
	return v
}

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRoundTrip(t *testing.T) {
	v := newVault(t)
	dek, err := v.Create([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Encrypt(dek); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(v.dataDir()); !os.IsNotExist(err) {
		t.Fatal("открытая папка осталась после шифрования")
	}
	blob := read(t, v.path(dataFile))
	if bytes.Contains([]byte(blob), []byte("секрет")) {
		t.Fatal("в data.enc виден открытый текст")
	}

	dek2, err := v.Unlock([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Decrypt(dek2); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(v.dataDir(), "key_datas")) != "секрет" || read(t, filepath.Join(v.dataDir(), "emoji", "cache")) != "кэш" {
		t.Fatal("данные после расшифровки не совпали")
	}
	if !v.NeedsRecovery() {
		t.Fatal("маркер открытых данных не создан")
	}
}

func TestWrongPassword(t *testing.T) {
	v := newVault(t)
	if _, err := v.Create([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Unlock([]byte("другой")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("ждали ErrWrongPassword, получили %v", err)
	}
}

// Сбой питания после Decrypt: открытые данные и маркер остались, Encrypt их возвращает в архив.
func TestRecovery(t *testing.T) {
	v := newVault(t)
	dek, _ := v.Create([]byte("pw"))
	if err := v.Encrypt(dek); err != nil {
		t.Fatal(err)
	}
	if err := v.Decrypt(dek); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(v.dataDir(), "key_datas"), "новое")
	if !v.NeedsRecovery() {
		t.Fatal("после Decrypt должен быть маркер")
	}
	if err := v.Encrypt(dek); err != nil {
		t.Fatal(err)
	}
	if v.NeedsRecovery() {
		t.Fatal("маркер остался после дошифровки")
	}
	if err := v.Decrypt(dek); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(v.dataDir(), "key_datas")) != "новое" {
		t.Fatal("правка не сохранилась при дошифровке")
	}
}

// Недоудалённая после сбоя папка без маркера не должна смешиваться с новой распаковкой.
func TestDecryptWipesStale(t *testing.T) {
	v := newVault(t)
	dek, _ := v.Create([]byte("pw"))
	if err := v.Encrypt(dek); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(v.dataDir(), "stale"), "мусор")
	if err := v.Decrypt(dek); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(v.dataDir(), "stale")); !os.IsNotExist(err) {
		t.Fatal("старый файл пережил распаковку")
	}
}

func TestUnpackRejectsEscape(t *testing.T) {
	for _, name := range []string{"../evil", "/abs", `C:\abs`, "a/../../evil"} {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("x"))
		_ = tw.Close()
		if err := unpackDir(buf.Bytes(), filepath.Join(t.TempDir(), "d")); err == nil {
			t.Fatalf("путь %q принят", name)
		}
	}
}

func TestUnpackRejectsSymlink(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "link", Linkname: `C:\Windows`, Typeflag: tar.TypeSymlink})
	_ = tw.Close()
	if err := unpackDir(buf.Bytes(), filepath.Join(t.TempDir(), "d")); err == nil {
		t.Fatal("симлинк принят")
	}
}
