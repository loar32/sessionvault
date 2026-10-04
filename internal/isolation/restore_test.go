package isolation

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func currentUser(t *testing.T) *windows.SID {
	t.Helper()
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid
}

// Данные после защиты должны вернуться обычными файлами пользователя: владелец он, наследование включено.
func TestGiveToUserRestoresInheritance(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tdata")
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "sub", "key_datas")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	me := currentUser(t)
	// Закрытый DACL, как у защищённых данных: без наследования, доступ только владельцу.
	if err := Protect(root, me, me); err != nil {
		t.Fatal(err)
	}
	if err := GiveToUser(root, me); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{root, file} {
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		owner, _, _ := sd.Owner()
		if !windows.EqualSid(owner, me) {
			t.Fatalf("%s: владелец не пользователь", p)
		}
		ctl, _, _ := sd.Control()
		if ctl&windows.SE_DACL_PROTECTED != 0 {
			t.Fatalf("%s: наследование прав не включено", p)
		}
	}
}

func TestGiveToUserSkipsJunction(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "outside")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(target, "victim.txt")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "tdata")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(root, "link"), target).CombinedOutput(); err != nil {
		t.Skip("junction не создан:", string(out))
	}
	me := currentUser(t)
	if err := Protect(target, me, me); err != nil {
		t.Fatal(err)
	}
	before, err := windows.GetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	beforeCtl, _, _ := before.Control()
	if err := GiveToUser(root, me); err != nil {
		t.Fatal(err)
	}
	after, err := windows.GetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	afterCtl, _, _ := after.Control()
	if beforeCtl != afterCtl {
		t.Fatal("права файла за ссылкой изменены")
	}
}
