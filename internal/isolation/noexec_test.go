package isolation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func testSID(t *testing.T, s string) *windows.SID {
	t.Helper()
	sid, err := windows.StringToSid(s)
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

func sddl(t *testing.T, isDir, exec bool) string {
	t.Helper()
	acl, err := noExecACL(isDir, exec, testSID(t, "S-1-5-21-1-2-3-1001"), []*windows.SID{testSID(t, "S-1-5-18")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.SetDACL(acl, true, false); err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

func TestFileHasNoExecuteOrChangePermissions(t *testing.T) {
	s := sddl(t, false, false)
	// 0x1301df = всё, кроме FILE_EXECUTE (0x20), WRITE_DAC (0x40000) и WRITE_OWNER (0x80000).
	if !strings.Contains(s, "(A;;0x1301df;;;S-1-5-21-1-2-3-1001)") {
		t.Fatalf("у vault на файл не те права: %s", s)
	}
	if !strings.Contains(s, ";;;OW)") {
		t.Fatalf("нет ACE «Права владельца»: %s", s)
	}
}

func TestApprovedFileOnlyReadsAndExecutes(t *testing.T) {
	s := sddl(t, false, true)
	if !strings.Contains(s, "(A;;0x1200a9;;;S-1-5-21-1-2-3-1001)") {
		t.Fatalf("одобренному файлу только чтение и запуск, без записи: %s", s)
	}
}

func TestNewFilesInDirNeverExecute(t *testing.T) {
	// Каталог одобренного файла (fileExec для каталога не действует): созданные позже файлы запуска не получают.
	s := sddl(t, true, true)
	if !strings.Contains(s, "(A;OIIO;0x1301df;;;S-1-5-21-1-2-3-1001)") {
		t.Fatalf("новые файлы без запуска: %s", s)
	}
	if !strings.Contains(s, "(A;CI;0x1301ff;;;S-1-5-21-1-2-3-1001)") {
		t.Fatalf("каталогу нужны права без смены DACL: %s", s)
	}
}

func TestProtectNoExecWithApprovedFileHeldOpen(t *testing.T) {
	root := t.TempDir()
	approved := filepath.Join(root, "ok.dll")
	if err := os.WriteFile(approved, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	err = protectNoExec(root, func(p string) bool {
		calls++
		// Пока файл проверяется, его нельзя ни перезаписать, ни удалить.
		if f, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
			_ = f.Close()
			t.Error("файл открылся на запись во время проверки")
		}
		return p == approved
	}, u.User.Sid, []*windows.SID{testSID(t, "S-1-5-18")}, nil, u.User.Sid)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("проверок: %d", calls)
	}
}

func TestCleanExchangeLinks(t *testing.T) {
	ProgramData = t.TempDir()
	t.Cleanup(func() { ProgramData = "" })
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "keep.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(ExchangeDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(ExchangeDir(), "link")); err != nil {
		t.Skip("ссылки недоступны:", err)
	}
	if n := CleanExchangeLinks(); n != 1 {
		t.Fatalf("удалено ссылок: %d", n)
	}
	if _, err := os.Stat(filepath.Join(target, "keep.txt")); err != nil {
		t.Fatal("цель ссылки пострадала:", err)
	}
}
