package decoy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/loar32/sessionvault/internal/isolation"
	"golang.org/x/sys/windows"
)

func setup(t *testing.T) (string, *windows.SID) {
	t.Helper()
	isolation.ProgramData = t.TempDir()
	t.Cleanup(func() { isolation.ProgramData = "" })
	if err := os.MkdirAll(isolation.BaseDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(t.TempDir(), "Telegram Desktop", "tdata"), u.User.Sid
}

func TestEnsureCreatesStructure(t *testing.T) {
	path, sid := setup(t)
	created, err := Ensure("telegram", "telegram", path, sid, time.Hour, 0)
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	for _, f := range layouts["telegram"] {
		fi, err := os.Stat(filepath.Join(path, f.name))
		if err != nil {
			t.Fatal(err)
		}
		if int(fi.Size()) < f.min || int(fi.Size()) > f.max {
			t.Errorf("%s: размер %d вне %d..%d", f.name, fi.Size(), f.min, f.max)
		}
	}
	if created, err = Ensure("telegram", "telegram", path, sid, time.Hour, 0); err != nil || created {
		t.Fatalf("повтор: created=%v err=%v", created, err)
	}
}

func TestEnsureRefreshes(t *testing.T) {
	path, sid := setup(t)
	if _, err := Ensure("telegram", "telegram", path, sid, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(path, "usertag"))
	created, err := Ensure("telegram", "telegram", path, sid, 0, 0)
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	if after, _ := os.ReadFile(filepath.Join(path, "usertag")); string(after) == string(before) {
		t.Error("содержимое не обновилось")
	}
}

func TestEnsureKeepsForeignData(t *testing.T) {
	path, sid := setup(t)
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(path, "key_datas")
	if err := os.WriteFile(real, []byte("настоящее"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure("telegram", "telegram", path, sid, 0, 0); !errors.Is(err, ErrForeign) {
		t.Fatalf("ожидался ErrForeign, получено %v", err)
	}
	if b, _ := os.ReadFile(real); string(b) != "настоящее" {
		t.Error("чужие данные изменены")
	}
	if err := Remove("telegram", path); !errors.Is(err, ErrForeign) {
		t.Fatalf("Remove чужого: %v", err)
	}
	if _, err := os.Stat(real); err != nil {
		t.Error("Remove удалил чужие данные")
	}
}

func TestForeignFileInsideOurDecoy(t *testing.T) {
	path, sid := setup(t)
	if _, err := Ensure("telegram", "telegram", path, sid, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "new"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure("telegram", "telegram", path, sid, 0, 0); !errors.Is(err, ErrForeign) {
		t.Fatalf("ожидался ErrForeign, получено %v", err)
	}
}

func TestRemoveOurs(t *testing.T) {
	path, sid := setup(t)
	if _, err := Ensure("telegram", "telegram", path, sid, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	if err := Remove("telegram", path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("приманка не удалена")
	}
}

func TestKnownSurvivesForeignFile(t *testing.T) {
	path, sid := setup(t)
	if Known("telegram", path) {
		t.Fatal("приманка известна до создания")
	}
	if _, err := Ensure("telegram", "telegram", path, sid, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "x.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure("telegram", "telegram", path, sid, 0, 0); !errors.Is(err, ErrForeign) {
		t.Fatalf("ожидался ErrForeign, получено %v", err)
	}
	if !Known("telegram", path) {
		t.Error("наблюдение за приманкой с чужим файлом потеряно")
	}
}

func TestChromiumLayout(t *testing.T) {
	_, sid := setup(t)
	path := filepath.Join(t.TempDir(), "Chrome", "User Data")
	created, err := Ensure("chrome", "chromium", path, sid, time.Hour, 0)
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	for _, f := range layouts["chromium"] {
		b, err := os.ReadFile(filepath.Join(path, f.name))
		if err != nil {
			t.Fatal(err)
		}
		if len(b) < f.min || len(b) > f.max {
			t.Errorf("%s: размер %d вне %d..%d", f.name, len(b), f.min, f.max)
		}
		if f.sqlite && (len(b)%4096 != 0 || string(b[:len(sqliteHeader)]) != sqliteHeader) {
			t.Errorf("%s: нет заголовка SQLite или размер не кратен странице", f.name)
		}
	}
	// Своя приманка с вложенными папками (Default, Default\Network) не должна считаться чужой.
	if created, err = Ensure("chrome", "chromium", path, sid, time.Hour, 0); err != nil || created {
		t.Fatalf("повтор: created=%v err=%v", created, err)
	}
	if err := Remove("chrome", path); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownKind(t *testing.T) {
	path, sid := setup(t)
	if _, err := Ensure("x", "firefox", path, sid, time.Hour, 0); !errors.Is(err, ErrKind) {
		t.Fatalf("ждали ErrKind, получили %v", err)
	}
}

func TestOverwrittenDecoyFileIsForeign(t *testing.T) {
	path, sid := setup(t)
	if _, err := Ensure("telegram", "telegram", path, sid, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "key_datas"), []byte("real session"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure("telegram", "telegram", path, sid, 0, 0); !errors.Is(err, ErrForeign) {
		t.Fatalf("ожидался ErrForeign, получено %v", err)
	}
	if err := Remove("telegram", path); !errors.Is(err, ErrForeign) {
		t.Fatalf("Remove: ожидался ErrForeign, получено %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(path, "key_datas")); string(b) != "real session" {
		t.Fatal("чужие данные затронуты")
	}
}

func TestJSONFilesAreValid(t *testing.T) {
	for kind, files := range map[string][]string{
		"chromium": {"Local State", `Default\Preferences`},
		"discord":  {"Local State", "Preferences", "settings.json"},
	} {
		path, sid := setup(t)
		if _, err := Ensure(kind, kind, path, sid, time.Hour, 0); err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			b, err := os.ReadFile(filepath.Join(path, f))
			if err != nil {
				t.Fatal(err)
			}
			if !json.Valid(b) {
				t.Errorf("%s %s: не JSON", kind, f)
			}
		}
	}
}
