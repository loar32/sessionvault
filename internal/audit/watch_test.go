package audit

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func enableSecurityPrivilege(t *testing.T) {
	t.Helper()
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		t.Skip(err)
	}
	defer func() { _ = tok.Close() }()
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeSecurityPrivilege"), &luid); err != nil {
		t.Skip(err)
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	if err := windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil); err != nil || windows.GetLastError() != nil {
		t.Skip("нужна привилегия SeSecurity (запуск от администратора)")
	}
}

func hasSACL(t *testing.T, path string) bool {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.SACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	sacl, _, err := sd.SACL()
	return err == nil && sacl != nil && sacl.AceCount > 0
}

func TestWatchReadsPropagatesToChildren(t *testing.T) {
	enableSecurityPrivilege(t)
	root := filepath.Join(t.TempDir(), "d")
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(root, "sub", "f")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WatchReads(root); err != nil {
		t.Fatal(err)
	}
	if !hasSACL(t, root) {
		t.Fatal("на папке нет SACL")
	}
	if !hasSACL(t, f) {
		t.Fatal("SACL не дошёл до вложенного файла")
	}
}
