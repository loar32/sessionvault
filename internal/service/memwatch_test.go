package service

import (
	"os"
	"strings"
	"testing"

	"github.com/loar32/sessionvault/internal/audit"
	"github.com/loar32/sessionvault/internal/isolation"
)

func TestHandleMemory(t *testing.T) {
	isolation.ProgramData = t.TempDir()
	t.Cleanup(func() { isolation.ProgramData = "" })
	if err := os.MkdirAll(isolation.BaseDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	s := testService(0)
	s.exe = `C:\Program Files\SessionVault\sessionvault.exe`
	s.targets = func() []string { return []string{`C:\Program Files\Google\Chrome\Application\chrome.exe`} }
	read := audit.Read{Type: "Process", Object: `\Device\HarddiskVolume3\Chrome\chrome.exe`, Process: `C:\Users\u\steal.exe`, PID: 7, Mask: 0x10, SID: "S-1-5-21-1-2-3-1001", User: "u"}

	s.handleMemory(read)
	s.handleMemory(read) // повтор от того же процесса с теми же правами в пределах минуты
	if n, _ := s.memoryState(); n != 1 {
		t.Fatalf("повтор должен схлопываться, записей %d", n)
	}
	other := read
	other.Mask = 0x20
	s.handleMemory(other)
	if n, _ := s.memoryState(); n != 2 {
		t.Fatalf("другие права — новая запись, всего %d", n)
	}
	for _, sid := range []string{"S-1-5-18", "S-1-5-19", "S-1-5-20"} {
		sys := read
		sys.SID, sys.PID = sid, 99
		s.handleMemory(sys)
	}
	notOurs := read
	notOurs.Object, notOurs.PID = `\Device\HarddiskVolume3\Windows\System32\lsass.exe`, 101
	s.handleMemory(notOurs) // обращение не к защищённому приложению
	own := read
	own.Process, own.PID = s.exe, 100
	s.handleMemory(own)
	if n, _ := s.memoryState(); n != 2 {
		t.Fatalf("системные учётки и сама служба не считаются, записей %d", n)
	}
	b, err := os.ReadFile(MemoryLogPath())
	if err != nil || !strings.Contains(string(b), "чтение памяти") || !strings.Contains(string(b), "chrome.exe") || strings.Count(string(b), "\n") != 2 {
		t.Fatalf("журнал: %q, %v", b, err)
	}
	if _, last := s.memoryState(); !strings.Contains(last, "запись памяти") {
		t.Fatalf("последнее обращение: %q", last)
	}
	denied := read
	denied.ID, denied.Failure, denied.PID = 4656, true, 8
	s.handleMemory(denied)
	if n, last := s.memoryState(); n != 3 || !strings.Contains(last, "(отказано)") {
		t.Fatalf("отказанная попытка — отдельная запись с пометкой: %d %q", n, last)
	}
}

func TestMemAccess(t *testing.T) {
	if got := memAccess(0x3a); !strings.Contains(got, "чтение памяти") || !strings.Contains(got, "операции с памятью") || !strings.Contains(got, "запись памяти") {
		t.Fatal(got)
	}
	if got := memAccess(0x400); !strings.Contains(got, "0x400") {
		t.Fatal(got)
	}
}

func TestMemLastIsShort(t *testing.T) {
	isolation.ProgramData = t.TempDir()
	t.Cleanup(func() { isolation.ProgramData = "" })
	if err := os.MkdirAll(isolation.BaseDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	s := testService(0)
	s.targets = func() []string { return []string{`C:\chrome.exe`} }
	s.handleMemory(audit.Read{Type: "Process", Object: `\Device\X\chrome.exe`, Process: `C:\` + strings.Repeat("я", 300), PID: 1, Mask: 0x10, SID: "S-1-5-21-1-2-3-1001"})
	if _, last := s.memoryState(); len([]rune(last)) > 201 {
		t.Fatalf("последнее обращение для check не обрезано: %d", len([]rune(last)))
	}
}

func TestMemDedupIgnoresPID(t *testing.T) {
	isolation.ProgramData = t.TempDir()
	t.Cleanup(func() { isolation.ProgramData = "" })
	if err := os.MkdirAll(isolation.BaseDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	s := testService(0)
	s.targets = func() []string { return []string{`C:\chrome.exe`} }
	r := audit.Read{Type: "Process", Object: `\Device\X\chrome.exe`, Process: `C:\spam.exe`, Mask: 0x10, SID: "S-1-5-21-1-2-3-1001"}
	for pid := uint32(1); pid <= 50; pid++ {
		r.PID = pid // потомки одной программы
		s.handleMemory(r)
	}
	if n, _ := s.memoryState(); n != 1 {
		t.Fatalf("50 процессов одной программы дают %d записей, ждали 1", n)
	}
}
