package decoy

import (
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
	created, err := Ensure("telegram", path, sid, time.Hour)
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	for _, f := range layout {
		fi, err := os.Stat(filepath.Join(path, f.name))
		if err != nil {
			t.Fatal(err)
		}
		if int(fi.Size()) < f.min || int(fi.Size()) > f.max {
			t.Errorf("%s: размер %d вне %d..%d", f.name, fi.Size(), f.min, f.max)
		}
	}
	if created, err = Ensure("telegram", path, sid, time.Hour); err != nil || created {
		t.Fatalf("повтор: created=%v err=%v", created, err)
	}
}

func TestEnsureRefreshes(t *testing.T) {
	path, sid := setup(t)
	if _, err := Ensure("telegram", path, sid, time.Hour); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(path, "usertag"))
	created, err := Ensure("telegram", path, sid, 0)
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
	if _, err := Ensure("telegram", path, sid, 0); !errors.Is(err, ErrForeign) {
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
	if _, err := Ensure("telegram", path, sid, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "new"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure("telegram", path, sid, 0); !errors.Is(err, ErrForeign) {
		t.Fatalf("ожидался ErrForeign, получено %v", err)
	}
}

func TestRemoveOurs(t *testing.T) {
	path, sid := setup(t)
	if _, err := Ensure("telegram", path, sid, time.Hour); err != nil {
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
	if _, err := Ensure("telegram", path, sid, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "x.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure("telegram", path, sid, 0); !errors.Is(err, ErrForeign) {
		t.Fatalf("ожидался ErrForeign, получено %v", err)
	}
	if !Known("telegram", path) {
		t.Error("наблюдение за приманкой с чужим файлом потеряно")
	}
}
