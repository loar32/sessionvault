package lockdown

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func testSID(t *testing.T) *windows.SID {
	t.Helper()
	// Чужая учётная запись из известных: Everyone не подходит (она есть в обычных ACL), берём «Гости».
	sid, err := windows.StringToSid("S-1-5-32-546")
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

func TestDenyAllowExec(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.exe")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sid := testSID(t)
	if IsDenied(p, sid) {
		t.Fatal("запрет есть до установки")
	}
	for range 2 {
		if err := DenyExec(p, sid); err != nil {
			t.Fatal(err)
		}
	}
	if !IsDenied(p, sid) {
		t.Fatal("запрет не поставлен")
	}
	// Повтор не плодит записи.
	h, _ := openForACL(p)
	sd, _ := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	_ = windows.CloseHandle(h)
	acl, _, _ := sd.DACL()
	if n := len(denyIndexes(acl, sid)); n != 1 {
		t.Fatalf("записей запрета %d, нужна 1", n)
	}
	if err := AllowExec(p, sid); err != nil {
		t.Fatal(err)
	}
	if IsDenied(p, sid) {
		t.Fatal("запрет остался после снятия")
	}
	// Файл остался доступен владельцу.
	if _, err := os.ReadFile(p); err != nil {
		t.Fatal(err)
	}
}

func TestListsExistOnWindows(t *testing.T) {
	if len(Interpreters()) == 0 {
		t.Fatal("интерпретаторы не найдены")
	}
	for _, p := range NetTools() {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("в списке несуществующий файл %s", p)
		}
	}
}
