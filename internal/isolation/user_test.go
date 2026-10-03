package isolation

import "testing"

func TestGeneratePassword(t *testing.T) {
	a, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GeneratePassword()
	if len(a) != passwordLen {
		t.Fatalf("длина %d, ждали %d", len(a), passwordLen)
	}
	if a == b {
		t.Fatal("два пароля подряд совпали")
	}
}

func TestIsAdminUser(t *testing.T) {
	ok, err := IsAdminUser("Administrator")
	if err != nil {
		t.Skip("учётки Administrator нет:", err)
	}
	if !ok {
		t.Fatal("Administrator должен быть администратором")
	}
}
