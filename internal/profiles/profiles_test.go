package profiles

import "testing"

func TestCommandLine(t *testing.T) {
	got := Telegram.CommandLine(`C:\Program Files\Telegram Desktop\Telegram.exe`, `C:\ProgramData\SessionVault\vault\telegram`)
	want := `"C:\Program Files\Telegram Desktop\Telegram.exe" -workdir C:\ProgramData\SessionVault\vault\telegram`
	if got != want {
		t.Fatalf("получили %s, ждали %s", got, want)
	}
}

func TestGetUnknown(t *testing.T) {
	if _, err := Get("nope"); err == nil {
		t.Fatal("неизвестный профиль должен давать ошибку")
	}
}
