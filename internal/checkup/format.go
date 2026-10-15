package checkup

import (
	"fmt"
	"github.com/loar32/sessionvault/internal/i18n"
	"strings"
)

var marks = map[Level][2]string{
	OK:   {"[ok]", "32"},
	Warn: {"[!]", "33"},
	Bad:  {"[x]", "31"},
	Info: {"[i]", "36"},
}

func Verdict(l Level) string {
	switch l {
	case OK:
		return i18n.T("всё в порядке")
	case Warn:
		return i18n.T("есть что улучшить (жёлтые пункты)")
	case Bad:
		return i18n.T("есть серьёзные проблемы (красные пункты)")
	}
	return ""
}

func Mark(l Level) string { return marks[l][0] }

// Format — текст отчёта для консоли: строка на пункт, под ней подсказка; color включает ANSI-цвета.
func Format(r Report, color bool) string {
	paint := func(l Level, s string) string {
		if !color {
			return s
		}
		return "\x1b[" + marks[l][1] + "m" + s + "\x1b[0m"
	}
	var b strings.Builder
	for _, it := range r.Items {
		fmt.Fprintf(&b, "%s %s: %s\n", paint(it.Level, marks[it.Level][0]), it.Title, it.Detail)
		if it.Hint != "" && it.Level != OK {
			fmt.Fprintf(&b, "    %s\n", it.Hint)
		}
	}
	fmt.Fprintf(&b, i18n.T("\nИтог: %s\n"), paint(r.Overall, Verdict(r.Overall)))
	return b.String()
}
