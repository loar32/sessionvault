package checkup

import (
	"fmt"
	"strings"
)

var marks = map[Level][2]string{
	OK:   {"[ok]", "32"},
	Warn: {"[!]", "33"},
	Bad:  {"[x]", "31"},
	Info: {"[i]", "36"},
}

var verdict = map[Level]string{
	OK:   "всё в порядке",
	Warn: "есть что улучшить (жёлтые пункты)",
	Bad:  "есть серьёзные проблемы (красные пункты)",
}

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
	fmt.Fprintf(&b, "\nИтог: %s\n", paint(r.Overall, verdict[r.Overall]))
	return b.String()
}
