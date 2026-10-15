//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestExecArgv(t *testing.T) {
	cases := map[string][]string{
		`/usr/bin/obsidian %U`:                           {"/usr/bin/obsidian"},
		`env BAMF=1 GDK=x /opt/Signal/signal-desktop %U`: {"env", "BAMF=1", "GDK=x", "/opt/Signal/signal-desktop"},
		`"/home/u/My Apps/app.AppImage" --no-sandbox %f`: {"/home/u/My Apps/app.AppImage", "--no-sandbox"},
		`sh -c "echo \"hi\" 100%%"`:                      {"sh", "-c", `echo "hi" 100%`},
		`  telegram-desktop   -- %u `:                    {"telegram-desktop", "--"},
	}
	for in, want := range cases {
		if got := ExecArgv(in); !slices.Equal(got, want) {
			t.Errorf("%q: %q, ждали %q", in, got, want)
		}
	}
	prog, args := execProgram(ExecArgv(`env BAMF=1 /opt/x/x --flag %U`))
	if prog != "/opt/x/x" || !slices.Equal(args, []string{"--flag"}) {
		t.Errorf("execProgram: %q %q", prog, args)
	}
}

func TestParseDesktop(t *testing.T) {
	b := "[Desktop Entry]\nName=Signal\nName[ru]=Сигнал\nExec=signal-desktop %U\nIcon=signal\nStartupWMClass=signal\n" +
		"MimeType=x-scheme-handler/sgnl;x-scheme-handler/signalcaptcha;\nTerminal=false\n[Desktop Action new]\nName=New\nExec=other\n"
	e := ParseDesktop("signal-desktop.desktop", []byte(b))
	if e.Name != "Signal" || e.Exec != "signal-desktop %U" || e.WMClass != "signal" || len(e.MimeTypes) != 2 || e.Terminal {
		t.Fatalf("%+v", e)
	}
}

func TestRewriteDesktopKeepsArgs(t *testing.T) {
	in := "[Desktop Entry]\nExec=env BAMF=1 \"/opt/My App/app\" --start-minimized %u\n"
	got := string(rewriteDesktop([]byte(in), "/usr/local/bin/sessionvault-app"))
	if !strings.Contains(got, "Exec=/usr/local/bin/sessionvault-app --start-minimized %u") {
		t.Fatalf("%s", got)
	}
}

func TestMatchesDir(t *testing.T) {
	names := matchNames(DesktopEntry{ID: "org.localsend.localsend_app.desktop", Name: "LocalSend"}, "/usr/bin/localsend", "localsend")
	for _, d := range []string{"LocalSend", "org.localsend.localsend_app", "localsend"} {
		if !matchesDir(d, names) {
			t.Errorf("%s не найдена по %q", d, names)
		}
	}
	for _, d := range []string{"chromium", "local", "send", "pulse"} {
		if matchesDir(d, names) {
			t.Errorf("%s принята по %q", d, names)
		}
	}
	if n := matchNames(DesktopEntry{Name: "Obsidian"}, "/home/u/Obsidian-1.6.7.AppImage", "obsidian"); !slices.Contains(n, "obsidian") || slices.ContainsFunc(n, func(s string) bool { return strings.Contains(s, "167") }) {
		t.Errorf("имена AppImage: %q", n)
	}
}

func TestFindDirs(t *testing.T) {
	home := t.TempDir()
	for _, d := range []string{".config/Signal", ".config/chromium", ".local/share/signal", ".signal-cli", "Signal"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got := findDirs([]string{"signal"}, func(root string) []string {
		entries, _ := os.ReadDir(filepath.Join(home, root))
		var n []string
		for _, e := range entries {
			n = append(n, e.Name())
		}
		return n
	}, func(rel string) bool {
		fi, err := os.Lstat(filepath.Join(home, rel))
		return err == nil && fi.IsDir()
	})
	want := []string{".config/Signal", ".local/share/signal", ".signal-cli"}
	if !slices.Equal(got, want) {
		t.Fatalf("%q, ждали %q", got, want)
	}
}

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{"OBS Studio": "obs-studio", "Signal": "signal", "  Тест!": "", strings.Repeat("a", 40): strings.Repeat("a", 29)} {
		if got := slug(in); got != want {
			t.Errorf("%q: %q, ждали %q", in, got, want)
		}
	}
}

func TestLinks(t *testing.T) {
	tg := App{Schemes: []string{"tg"}}
	browser := App{Browser: true}
	for _, c := range []struct {
		a    App
		link string
		ok   bool
	}{
		{tg, "tg://resolve?domain=durov", true},
		{tg, "https://t.me/durov", false},
		{browser, "https://example.com/a?b=c", true},
		{browser, "file:///etc/passwd", false},
		{browser, "javascript:alert(1)", false},
		{tg, "TG://x", true},
		{tg, "tg://a b", false},
	} {
		if got := c.a.AcceptsLink(c.link); got != c.ok {
			t.Errorf("%q: %v", c.link, got)
		}
	}
	for link, ok := range map[string]bool{"https://example.com": true, "mailto:a@b.c": true, "file:///etc/shadow": false,
		"steam://run/1": false, "smb://host/share": false, "": false} {
		if outboundLink(link) != ok {
			t.Errorf("исходящая %q: ждали %v", link, ok)
		}
	}
	if p, err := unescapePath("/home/u/Downloads/a%20b.pdf"); err != nil || p != "/home/u/Downloads/a b.pdf" {
		t.Errorf("unescapePath: %q %v", p, err)
	}
	if _, err := unescapePath("/x%00y"); err == nil {
		t.Error("нулевой байт в пути принят")
	}
}

func TestProxyRules(t *testing.T) {
	pid := trayPID(999)
	r := proxyRules(pid)
	if !slices.Contains(r, "--filter") || !slices.Contains(r, "--own=org.kde.StatusNotifierItem-"+strconv.Itoa(pid)+"-1") {
		t.Fatalf("нет фильтра или имени значка: %q", r)
	}
	for _, x := range r {
		if strings.Contains(x, "FileChooser") || strings.Contains(x, "Properties") || x == "--talk=org.freedesktop.portal.Desktop" {
			t.Errorf("лишнее правило %q", x)
		}
	}
	if trayPID(999) == trayPID(998) {
		t.Error("у соседних учёток одинаковый pid значка")
	}
}

func TestMountsAndEncryption(t *testing.T) {
	info := "25 1 0:22 / / rw - btrfs /dev/mapper/root rw\n26 25 0:23 / /home/u\\040x rw - ext4 /dev/sda3 rw\n"
	ms := parseMountinfo([]byte(info))
	if m := mountOf(ms, "/home/u x/docs"); m.source != "/dev/sda3" {
		t.Fatalf("дом: %+v", m)
	}
	if m := mountOf(ms, "/etc"); m.source != "/dev/mapper/root" {
		t.Fatalf("корень: %+v", m)
	}
	sys := t.TempDir()
	for p, c := range map[string]string{"class/block/dm-1/dm/uuid": "LVM-abc", "class/block/dm-0/dm/uuid": "CRYPT-LUKS2-x"} {
		if err := os.MkdirAll(filepath.Join(sys, filepath.Dir(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sys, p), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(sys, "class/block/dm-1/slaves/dm-0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !encrypted(sys, "dm-1", 0) {
		t.Error("LVM поверх LUKS не распознан")
	}
	if encrypted(sys, "sda3", 0) {
		t.Error("обычный раздел принят за зашифрованный")
	}
}

func TestSudoAndUpgrade(t *testing.T) {
	if !passwordlessSudo("User tester may run:\n    (ALL) NOPASSWD: ALL\n") {
		t.Error("NOPASSWD: ALL не замечен")
	}
	if passwordlessSudo("User tester may run:\n    (ALL : ALL) ALL\n    (root) NOPASSWD: /usr/bin/pacman -Sy\n") {
		t.Error("отдельная команда без пароля принята за полный sudo без пароля")
	}
	log := "[2026-09-01T10:00:00+0300] [PACMAN] starting full system upgrade\n[2026-10-01T10:00:00+0300] [PACMAN] starting full system upgrade\n"
	if got := lastUpgrade([]byte(log)); got.Month() != time.October {
		t.Errorf("последнее обновление: %v", got)
	}
}
