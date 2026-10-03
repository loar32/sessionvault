package service

import (
	"errors"
	"testing"
)

func testList(signer func(string) (string, error), extra ...Allow) allowlist {
	t := newAllowlist(extra, func(string, ...any) {})
	t.signer = signer
	return t
}

func noSigner(string) (string, error) { return "", errors.New("нет подписи") }

func TestMatchPath(t *testing.T) {
	for _, c := range []struct {
		pattern, path string
		want          bool
	}{
		{`C:\a\*\m.exe`, `c:\A\4.18\M.EXE`, true},
		{`C:\a\*\m.exe`, `C:\a\x\y\m.exe`, false},
		{`C:\a\*\m.exe`, `C:\a\m.exe`, false},
		{`C:\a\m.exe`, `C:\a\m.exe.bak`, false},
		{`C:\a\m.exe`, `C:\a\..\b\m.exe`, false},
	} {
		if got := matchPath(c.pattern, c.path); got != c.want {
			t.Errorf("matchPath(%q, %q)=%v", c.pattern, c.path, got)
		}
	}
}

func TestDefaultAllowIsNotWide(t *testing.T) {
	a := testList(noSigner)
	for _, p := range []string{`C:\Users\x\Downloads\stealer.exe`, `C:\Windows\System32\svchost.exe`, `C:\Windows\System32\cmd.exe`, "-", ""} {
		if a.allowed(p, 100) {
			t.Errorf("%q разрешён", p)
		}
	}
	if !a.allowed("System", 4) {
		t.Error("ядро не разрешено")
	}
	if a.allowed("System", 100) {
		t.Error("процесс с именем System, но не PID 4, разрешён")
	}
}

func TestUserEntryNeedsPublisherOutsideProtectedDirs(t *testing.T) {
	a := testList(noSigner, Allow{Path: `C:\Users\x\AppData\backup.exe`})
	if a.allowed(`C:\Users\x\AppData\backup.exe`, 100) {
		t.Error("запись без издателя в пользовательской папке принята")
	}
}

func TestPublisherChecked(t *testing.T) {
	e := Allow{Path: `D:\Backup\agent.exe`, Publisher: "Backup Inc"}
	if testList(noSigner, e).allowed(`D:\Backup\agent.exe`, 100) {
		t.Error("exe без подписи разрешён")
	}
	other := func(string) (string, error) { return "Evil LLC", nil }
	if testList(other, e).allowed(`D:\Backup\agent.exe`, 100) {
		t.Error("чужой издатель разрешён")
	}
	ok := func(string) (string, error) { return "backup inc", nil }
	if !testList(ok, e).allowed(`D:\Backup\agent.exe`, 100) {
		t.Error("верный издатель отклонён")
	}
	if testList(ok, e).allowed(`D:\Other\agent.exe`, 100) {
		t.Error("другой путь с верной подписью разрешён")
	}
}
