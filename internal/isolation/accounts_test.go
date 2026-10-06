package isolation

import (
	"strings"
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
