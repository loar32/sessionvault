package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/loar32/sessionvault/internal/checkup"
	"github.com/loar32/sessionvault/internal/ipc"
)

// Отчёт уходит клиенту одной строкой не длиннее MaxCheck: в худшем случае (все пункты красные, длинные имена
// расширений и пути последнего обращения) он не должен упираться в предел, иначе check у пользователя перестанет работать.
func TestCheckReportFitsPipe(t *testing.T) {
	long := strings.Repeat("я", 60)
	in := checkup.Input{
		MainUserAdmin: true,
		ExtScanned:    []string{"chrome", "edge", "brave"},
		ExtRisky:      []string{long + " (chrome)", long + " (edge)", long + " (brave)", long + " (a)", long + " (b)", long + " (c)", long + " (d)"},
		MemAudit:      true,
		MemReads:      99999,
		MemLast:       "2026/10/05 13:11:15 " + strings.Repeat("ю", 20) + ": C:\\" + strings.Repeat("п", 255) + " (PID 4294967295) -> chrome.exe, чтение памяти, запись памяти, операции с памятью, создание потока (отказано)",
	}
	b, err := json.Marshal(checkup.Run(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) >= ipc.MaxCheck {
		t.Fatalf("отчёт %d байт при пределе %d", len(b), ipc.MaxCheck)
	}
	t.Logf("худший отчёт: %d байт из %d", len(b), ipc.MaxCheck)
}
