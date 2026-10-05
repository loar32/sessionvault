package isolation

import (
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

func TestExecAllowedInWhitelistedDir(t *testing.T) {
	s := sddl(t, true, true)
	if !strings.Contains(s, "(A;OIIO;0x1301ff;;;S-1-5-21-1-2-3-1001)") {
		t.Fatalf("в белой папке файлам нужен запуск: %s", s)
	}
	if !strings.Contains(s, "(A;CI;0x1301ff;;;S-1-5-21-1-2-3-1001)") {
		t.Fatalf("каталогу нужны права без смены DACL: %s", s)
	}
	n := sddl(t, true, false)
	if !strings.Contains(n, "(A;OIIO;0x1301df;;;S-1-5-21-1-2-3-1001)") {
		t.Fatalf("вне белой папки файлы без запуска: %s", n)
	}
}

func TestInExecDir(t *testing.T) {
	root := `C:\v\work`
	dirs := []string{`User Data\WidevineCdm`}
	for p, want := range map[string]bool{
		root + `\User Data\WidevineCdm`:           true,
		root + `\User Data\WidevineCdm\1.0\a.dll`: true,
		root + `\User Data\WidevineCdmX`:          false,
		root + `\User Data\Default`:               false,
		root:                                      false,
	} {
		if got := inExecDir(root, p, dirs); got != want {
			t.Errorf("%s: %v, ждали %v", p, got, want)
		}
	}
}
