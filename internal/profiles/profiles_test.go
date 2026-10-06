package profiles

import (
	"errors"
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
		// Путь Discord появляется при защите: служба копирует каталог приложения из профиля пользователя.
		if name == "discord" && p.Exe == "" {
			p.Exe = `C:\Program Files\SessionVault\apps\discord\Discord.exe`
		}
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

func TestLoadAcceptsBOM(t *testing.T) {
	dir := t.TempDir()
	b := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"name":"bom","exe":"C:\\a.exe","data_dir":"d"}`)...)
	if err := os.WriteFile(filepath.Join(dir, "bom.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, "bom"); err != nil {
		t.Fatalf("профиль с BOM не читается: %v", err)
	}
}

func TestExecFiles(t *testing.T) {
	dir := t.TempDir()
	// Профиль браузера, записанный до v0.13, получает исключение для Widevine.
	old := `{"name":"chrome","exe":"C:/a.exe","data_dir":"User Data","decoy":"chromium"}`
	if err := os.WriteFile(filepath.Join(dir, "chrome.json"), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(dir, "chrome")
	if err != nil || len(p.ExecFiles) != 1 || p.ExecFiles[0] != "widevinecdm.dll" || p.ExecSigner != "Google LLC" {
		t.Fatalf("исключение для Widevine: %+v, %v", p, err)
	}
	// Имя файла, а не путь: иначе запуск разрешился бы файлу в произвольной подпапке.
	bad := `{"name":"x","exe":"C:/a.exe","data_dir":"d","exec_files":["a/b.dll"]}`
	if err := os.WriteFile(filepath.Join(dir, "x.json"), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, "x"); err == nil {
		t.Fatal("путь вместо имени файла принят")
	}
	if Telegram.ExecFiles != nil {
		t.Fatal("у Telegram исключений нет")
	}
}

func TestSignature(t *testing.T) {
	RequireSignature = true
	defer func() { RequireSignature = false }()
	root := t.TempDir()
	dir := filepath.Join(root, "profiles")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := Telegram
	if _, err := Load(dir, "telegram"); err == nil {
		t.Fatal("профиль без файла принят")
	}
	if err := Save(dir, p); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir, "telegram")
	if err != nil || got.Sig == "" {
		t.Fatalf("подписанный профиль не читается: %v", err)
	}
	// Правка файла после подписи отклоняется.
	path := filepath.Join(dir, "telegram.json")
	b, _ := os.ReadFile(path)
	edited := strings.Replace(string(b), "Telegram.exe", "Evil.exe", 1)
	if edited == string(b) {
		t.Fatal("тест не изменил профиль")
	}
	if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, "telegram"); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("изменённый профиль принят: %v", err)
	}
	// Подпись, перенесённая с другого профиля, не подходит.
	other := Telegram
	other.Name = "other"
	if err := Save(dir, other); err != nil {
		t.Fatal(err)
	}
	ob, _ := os.ReadFile(filepath.Join(dir, "other.json"))
	if err := os.WriteFile(path, []byte(strings.Replace(string(ob), `"name": "other"`, `"name": "telegram"`, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, "telegram"); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("чужая подпись принята: %v", err)
	}
	// trust подписывает файл как есть; Resign подписывает все.
	if err := Trust(dir, "telegram"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, "telegram"); err != nil {
		t.Fatalf("после trust профиль не читается: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "legacy.json"), []byte(strings.Replace(string(ob), `"name": "other"`, `"name": "legacy"`, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, "legacy"); err == nil {
		t.Fatal("подпись другого профиля принята у legacy")
	}
	if err := Resign(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, "legacy"); err != nil {
		t.Fatalf("после Resign: %v", err)
	}
	// Без ключа профили не читаются, пока их не подпишут.
	if err := os.Remove(keyPath(dir)); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, "legacy"); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("профиль принят без ключа: %v", err)
	}
}
