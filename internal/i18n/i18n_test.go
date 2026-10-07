package i18n

import "testing"

func TestT(t *testing.T) {
	en["тест"] = "test"
	defer delete(en, "тест")
	SetEnglish(false)
	if T("тест") != "тест" {
		t.Fatal("русский интерфейс должен вернуть исходную строку")
	}
	SetEnglish(true)
	defer SetEnglish(false)
	if T("тест") != "test" || T("нет перевода") != "нет перевода" {
		t.Fatal("перевод или запасной вариант не сработал")
	}
	if Tf("тест %d", 1) != "test %d" && Tf("тест %d", 1) != "тест 1" {
		t.Fatal("Tf")
	}
}
