package isolation

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestAccountName(t *testing.T) {
	if got := AccountName("telegram"); got != "sv-telegram" {
		t.Fatalf("короткое имя: %q", got)
	}
	if got := AccountName("abcdefghijklmn"); got != "sv-abcdefghijklmn" || len(got) != 17 {
		t.Fatalf("имя на границе: %q", got)
	}
	seen := map[string]string{}
	for _, name := range []string{
		"abcdefghijklmnopq", "abcdefghijklmnopr", "abcdefghijklmnopqrstuvwxyz0123", "abcdefghijklmnopqrstuvwxyz0124",
		"very-long-application-name-1", "very-long-application-name-2",
	} {
		got := AccountName(name)
		if len(got) > maxAccountLen || !strings.HasPrefix(got, AccountPrefix) {
			t.Fatalf("%q: недопустимая учётка %q", name, got)
		}
		if prev, dup := seen[got]; dup {
			t.Fatalf("%q и %q дали одну учётку %q", prev, name, got)
		}
		seen[got] = name
		if AccountName(name) != got {
			t.Fatalf("%q: имя нестабильно", name)
		}
	}
}

func TestAccountsStore(t *testing.T) {
	old := ProgramData
	ProgramData = t.TempDir()
	defer func() { ProgramData = old }()
	if err := os.MkdirAll(BaseDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	seed := map[string]string{}
	for i := range 30 {
		seed[fmt.Sprintf("sv-nouser-%d", i)] = "pw"
	}
	if err := saveAccounts(seed); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(accountsFile() + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("временный файл остался после записи")
	}
	if pw, err := LoadAccountPassword("sv-nouser-3"); err != nil || pw != "pw" {
		t.Fatalf("пароль не прочитан: %q %v", pw, err)
	}
	if _, err := LoadAccountPassword("sv-nouser-x"); err == nil {
		t.Fatal("несуществующая запись найдена")
	}
	// Одновременное удаление: без блокировки часть записей осталась бы (потерянное обновление).
	var wg sync.WaitGroup
	for name := range seed {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := DeleteAppAccount(name); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if left := AccountNames(); len(left) != 0 {
		t.Fatalf("после удаления осталось %d записей", len(left))
	}
}
