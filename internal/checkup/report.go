package checkup

import "time"

type Level string

const (
	OK   Level = "ok"
	Warn Level = "warn"
	Bad  Level = "bad"
	Info Level = "info" // справка, на итог не влияет
)

type Item struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Level  Level  `json:"level"`
	Detail string `json:"detail"`
	Hint   string `json:"hint,omitempty"`
}

type Report struct {
	Time    time.Time `json:"time"`
	Overall Level     `json:"overall"`
	Items   []Item    `json:"items"`
}

// Summarize — отчёт с итогом: худший уровень среди пунктов (справка на итог не влияет).
func Summarize(items []Item, now time.Time) Report {
	overall := OK
	for _, it := range items {
		if it.Level == Bad || (it.Level == Warn && overall == OK) {
			overall = it.Level
		}
	}
	return Report{Time: now, Overall: overall, Items: items}
}
