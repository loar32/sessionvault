package checkwin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/loar32/sessionvault/internal/checkup"
)

func report(overall checkup.Level, items ...checkup.Item) checkup.Report {
	return checkup.Report{Overall: overall, Items: items}
}

func TestText(t *testing.T) {
	r := report(checkup.Bad,
		checkup.Item{ID: "a", Title: "Аудит", Level: checkup.Bad, Detail: "не работает", Hint: "включить"},
		checkup.Item{ID: "b", Title: "BitLocker", Level: checkup.Warn, Detail: "выключен", Hint: "включить диск"},
		checkup.Item{ID: "c", Title: "Defender", Level: checkup.OK, Detail: "включён"},
		checkup.Item{ID: "d", Title: "Справка", Level: checkup.Info, Detail: "про справку", Hint: "скрыта в окне"})
	got := Text(r)
	for _, want := range []string{"Итог: есть серьёзные проблемы", "[x] Аудит: не работает", "включить диск", "В порядке: 1 из 3", "ClickFix", "sessionvault check"} {
		if !strings.Contains(got, want) {
			t.Errorf("в тексте нет %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Defender") || strings.Contains(got, "про справку") {
		t.Errorf("зелёные и справочные пункты в окне не нужны:\n%s", got)
	}
}

func TestAutoCheck(t *testing.T) {
	flag := filepath.Join(t.TempDir(), "sub", "check-shown")
	shown := 0
	show := func(checkup.Report) { shown++ }
	fetch := func(l checkup.Level) func() (checkup.Report, error) {
		return func() (checkup.Report, error) { return report(l), nil }
	}

	autoCheck(func() (checkup.Report, error) {
		return checkup.Report{}, errors.New("служба недоступна")
	}, show, flag)
	if _, err := os.Stat(flag); err == nil || shown != 0 {
		t.Fatal("служба недоступна: флаг и окно не нужны")
	}
	autoCheck(fetch(checkup.Warn), show, flag)
	if _, err := os.Stat(flag); err != nil || shown != 0 {
		t.Fatalf("жёлтые пункты: окна нет, флаг есть (%v, окон %d)", err, shown)
	}
	autoCheck(fetch(checkup.Bad), show, flag)
	if shown != 0 {
		t.Fatal("после установки уже проверяли: красные пункты сами окно не открывают")
	}

	flag2 := filepath.Join(t.TempDir(), "check-shown")
	autoCheck(fetch(checkup.Bad), show, flag2)
	if shown != 1 {
		t.Fatal("красные пункты в первый раз должны открыть окно")
	}
	autoCheck(fetch(checkup.Bad), show, flag2)
	if shown != 1 {
		t.Fatal("окно показывается один раз")
	}
}
