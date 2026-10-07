package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/loar32/sessionvault/internal/profiles"
)

func write(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPlaceDirRoundTrip(t *testing.T) {
	src := filepath.Join(t.TempDir(), "Steam")
	write(t, filepath.Join(src, `htmlcache\Default\Network\Cookies`), "cookies")
	write(t, filepath.Join(src, `htmlcache\Default\Cache\f_000001`), "cache")
	write(t, filepath.Join(src, "local.vdf"), "local")
	pl := profiles.Place{Path: src, Decoy: "steamlocal", Exclude: []string{`htmlcache\Default\Cache`}}

	files, err := readPlace(pl)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("прочитано %d файлов, ждали 2 (кэш не берётся)", len(files))
	}
	if !placeHasData(pl) {
		t.Fatal("место с файлами считается пустым")
	}
	if err := removePlace(pl); err != nil {
		t.Fatal(err)
	}
	if placeHasData(pl) {
		t.Fatal("после removePlace на месте остались данные")
	}
	if err := writePlace(pl, files); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(src, `htmlcache\Default\Network\Cookies`))
	if err != nil || string(b) != "cookies" {
		t.Fatalf("после возврата: %q, %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(src, `htmlcache\Default\Cache`)); err == nil {
		t.Fatal("кэш вернулся на место")
	}
}

func TestPlaceFilesOnlyGlob(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "ssfn1234"), "ssfn")
	write(t, filepath.Join(dir, "steam.exe"), "exe")
	write(t, filepath.Join(dir, "config", "config.vdf"), "cfg")
	pl := profiles.Place{Path: dir, Files: []string{"ssfn*"}}
	files, err := readPlace(pl)
	if err != nil || len(files) != 1 || files[0].rel != "ssfn1234" {
		t.Fatalf("прочитано %v, %v", files, err)
	}
	if err := removePlace(pl); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ssfn1234")); err == nil {
		t.Fatal("ssfn не удалён")
	}
	for _, keep := range []string{"steam.exe", `config\config.vdf`} {
		if _, err := os.Stat(filepath.Join(dir, keep)); err != nil {
			t.Fatalf("удалён лишний файл %s", keep)
		}
	}
}

func TestPlaceMissingAndEmpty(t *testing.T) {
	pl := profiles.Place{Path: filepath.Join(t.TempDir(), "нет")}
	files, err := readPlace(pl)
	if err != nil || len(files) != 0 || placeHasData(pl) {
		t.Fatalf("несуществующее место: %v, %v", files, err)
	}
	empty := profiles.Place{Path: t.TempDir()}
	if placeHasData(empty) {
		t.Fatal("пустая папка считается данными")
	}
}

func TestWritePlaceRejectsEscape(t *testing.T) {
	pl := profiles.Place{Path: t.TempDir()}
	if err := writePlace(pl, []placeFile{{rel: `..\evil`, data: []byte("x")}}); err == nil {
		t.Fatal("путь за пределами места принят")
	}
}
