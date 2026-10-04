package profiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandLine(t *testing.T) {
	got := Telegram.CommandLine(`C:\ProgramData\SessionVault\vault\telegram\work`)
	want := `"C:\Program Files\Telegram Desktop\Telegram.exe" -workdir C:\ProgramData\SessionVault\vault\telegram\work`
	if got != want {
		t.Fatalf("получили %s, ждали %s", got, want)
	}
}

func TestSaveLoad(t *testing.T) {
	dir := t.TempDir()
	if err := Save(dir, Telegram); err != nil {
		t.Fatal(err)
	}
	p, err := Load(dir, "telegram")
	if err != nil || p.Exe != Telegram.Exe || p.DataDir != "tdata" {
		t.Fatalf("round-trip: %+v, %v", p, err)
	}
}

func TestLoadRejects(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"", "nope", "../telegram", "Telegram", "tele gram", "a/b", "telegram.json", string(make([]byte, 40))} {
		if _, err := Load(dir, name); err == nil {
			t.Fatalf("имя %q принято", name)
		}
	}
	bad := map[string]string{
		"rel":   `{"name":"rel","exe":"tg.exe","data_dir":"tdata"}`,
		"other": `{"name":"x","exe":"C:\a.exe","data_dir":"tdata"}`,
		"esc":   `{"name":"esc","exe":"C:\a.exe","data_dir":"..\x"}`,
		"junk":  `не json`,
	}
	for name, body := range bad {
		if err := os.WriteFile(filepath.Join(dir, name+".json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir, name); err == nil {
			t.Fatalf("профиль %q принят", name)
		}
	}
}

func TestTemplates(t *testing.T) {
	for _, name := range TemplateNames() {
		p, ok := Template(name)
		if !ok || p.Name != name || !filepath.IsAbs(p.Exe) || p.Origin == "" || p.Publisher == "" || p.Decoy == "" {
			t.Fatalf("шаблон %s неполный: %+v", name, p)
		}
		dir := t.TempDir()
		if err := Save(dir, p); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir, name); err != nil {
			t.Fatalf("шаблон %s не проходит проверку: %v", name, err)
		}
	}
	if _, ok := Template("firefox"); ok {
		t.Fatal("неизвестный шаблон принят")
	}
}

func TestChromiumCommandLine(t *testing.T) {
	p, _ := Template("chrome")
	got := p.CommandLine(`C:\ProgramData\SessionVault\vault\chrome\work`)
	want := `--user-data-dir="C:\ProgramData\SessionVault\vault\chrome\work\User Data"`
	if !strings.Contains(got, `"--user-data-dir=C:\ProgramData\SessionVault\vault\chrome\work\User Data"`) || !strings.Contains(got, "--disable-background-mode") {
		t.Fatalf("получили %s, ждали вид %s", got, want)
	}
}

func TestLoadLegacyTelegram(t *testing.T) {
	dir := t.TempDir()
	old := `{"name":"telegram","exe":"C:\\Program Files\\Telegram Desktop\\Telegram.exe","data_dir":"tdata","launch_args":["-workdir","{data_path}"]}`
	if err := os.WriteFile(filepath.Join(dir, "telegram.json"), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(dir, "telegram")
	if err != nil || p.Origin != Telegram.Origin || p.Decoy != "telegram" || p.Title != "Telegram" {
		t.Fatalf("профиль старого формата: %+v, %v", p, err)
	}
}

func TestLoadRejectsBadNewFields(t *testing.T) {
	dir := t.TempDir()
	bad := map[string]string{
		"decoy":   `{"name":"decoy","exe":"C:\\a.exe","data_dir":"d","decoy":"zzz"}`,
		"exclude": `{"name":"exclude","exe":"C:\\a.exe","data_dir":"d","exclude":["..\\x"]}`,
		"origin":  `{"name":"origin","exe":"C:\\a.exe","data_dir":"d","origin":"C:\\abs"}`,
	}
	for name, body := range bad {
		if err := os.WriteFile(filepath.Join(dir, name+".json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir, name); err == nil {
			t.Fatalf("профиль %q принят", name)
		}
	}
}
