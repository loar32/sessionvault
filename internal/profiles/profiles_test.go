package profiles

import (
	"os"
	"path/filepath"
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
