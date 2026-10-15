//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseRequest(t *testing.T) {
	for _, ok := range []string{"status", "list", "running", "lock", "reload", "run telegram", "unlock chromium", "open brave", "webapp chromium", "close discord"} {
		if _, err := ParseRequest(ok); err != nil {
			t.Errorf("%q отвергнут: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "run", "run ../etc", "run Telegram", "run telegram extra", "status x", "exec /bin/sh", "run tele\tgram", "unlock " + strings.Repeat("a", 64)} {
		if _, err := ParseRequest(bad); err == nil {
			t.Errorf("%q принят", bad)
		}
	}
}

func TestBrowserFlagsKeepOnlySafe(t *testing.T) {
	home := t.TempDir()
	flags := "# комментарий\n--ozone-platform=wayland\n--remote-debugging-port=9222\n--enable-features=A,B:c\n" +
		"--load-extension=/usr/share/fonts,/home/x/evil,/usr/share/../etc\n--user-data-dir=/tmp/x --enable-wayland-ime\n--password-store=gnome-libsecret\n"
	if err := os.MkdirAll(filepath.Join(home, ".config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".config", "chromium-flags.conf"), []byte(flags), 0o644); err != nil {
		t.Fatal(err)
	}
	a, _ := FindApp("chromium")
	got := browserFlags(a, os.Getuid(), home)
	want := []string{"--ozone-platform=wayland", "--enable-features=A,B:c", "--load-extension=/usr/share/fonts", "--enable-wayland-ime"}
	if !slices.Equal(got, want) {
		t.Fatalf("флаги %q, ждали %q", got, want)
	}
}

func TestBrowserFlagsRejectSymlink(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "real", "chromium-flags.conf"), []byte("--ozone-platform=wayland\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "real"), filepath.Join(home, ".config")); err != nil {
		t.Fatal(err)
	}
	a, _ := FindApp("chromium")
	if got := browserFlags(a, os.Getuid(), home); len(got) != 0 {
		t.Fatalf("файл за ссылкой прочитан: %q", got)
	}
}

func TestRewriteDesktop(t *testing.T) {
	in := "[Desktop Entry]\nName=Chromium\nExec=/usr/bin/chromium %U\nTryExec=/usr/bin/chromium\nDBusActivatable=true\n" +
		"[Desktop Action new-window]\nExec=/usr/bin/chromium --incognito\n"
	got := string(rewriteDesktop([]byte(in), "/usr/local/bin/sessionvault-chromium"))
	for _, want := range []string{"[Desktop Entry]\n" + desktopMarker, "Exec=/usr/local/bin/sessionvault-chromium %U", "Exec=/usr/local/bin/sessionvault-chromium --incognito"} {
		if !strings.Contains(got, want) {
			t.Errorf("нет %q в\n%s", want, got)
		}
	}
	if strings.Contains(got, "TryExec") || strings.Contains(got, "DBusActivatable") || strings.Contains(got, "/usr/bin/chromium") {
		t.Errorf("остались обходные строки:\n%s", got)
	}
}

func TestDecoyRemovesOnlyOwnFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tdata-root")
	files, err := makeDecoy("telegram", dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(decoyLayouts["telegram"]) {
		t.Fatalf("файлов %d", len(files))
	}
	// Файл, который переписало настоящее приложение, — уже чужие данные: он остаётся.
	changed := filepath.Join(dir, "tdata", "settingss")
	if err := os.WriteFile(changed, []byte("настоящие данные"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	_ = os.Chtimes(changed, now, now)
	if err := removeDecoy(dir, files); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(changed); err != nil {
		t.Fatal("изменённый файл удалён")
	}
	if _, err := os.Stat(filepath.Join(dir, "tdata", "key_datas")); err == nil {
		t.Fatal("файл приманки остался")
	}
	if _, err := makeDecoy("telegram", dir); err == nil {
		t.Fatal("приманка поверх существующего файла создана")
	}
}
