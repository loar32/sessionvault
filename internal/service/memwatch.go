package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/loar32/sessionvault/internal/audit"
	"github.com/loar32/sessionvault/internal/isolation"
	"golang.org/x/sys/windows"
)

const (
	memDedup      = time.Minute
	memWatchEvery = 5 * time.Second // не чаще: статус опрашивает трей раз в 10 с, а после действия чаще
	memLogMax     = 8 * 1024
)

func MemoryLogPath() string { return filepath.Join(isolation.BaseDir(), "memory.log") }

// jobBasicProcessIDList — JOBOBJECT_BASIC_PROCESS_ID_LIST с запасом под потомков браузера.
type jobPIDList struct {
	Assigned uint32
	InList   uint32
	IDs      [512]uintptr
}

// jobPIDs — процессы, которые сейчас работают в job-объекте службы (все защищённые приложения и их потомки).
func jobPIDs(job windows.Handle) []uint32 {
	var l jobPIDList
	if err := windows.QueryInformationJobObject(job, 3, uintptr(unsafe.Pointer(&l)), uint32(unsafe.Sizeof(l)), nil); err != nil {
		return nil
	}
	n := min(int(l.InList), len(l.IDs))
	pids := make([]uint32, 0, n)
	for _, id := range l.IDs[:n] {
		pids = append(pids, uint32(id))
	}
	return pids
}

// watchMemory ставит аудит чтения памяти на процессы защищённых приложений. Потомки (процессы браузера) появляются
// после запуска, поэтому служба вызывает её при запуске приложения и при опросе статуса, но не чаще раза в memWatchEvery:
// отдельного таймера нет, а без запущенных приложений вызов ничего не стоит.
func (s *Service) watchMemory() {
	s.mu.Lock()
	if len(s.running) == 0 || time.Since(s.memWatchAt) < memWatchEvery {
		s.mu.Unlock()
		return
	}
	s.memWatchAt = time.Now()
	job := s.job
	s.mu.Unlock()
	for _, pid := range jobPIDs(job) {
		if err := audit.WatchProcess(pid); err != nil {
			s.log.Printf("аудит процесса %d: %v", pid, err)
		}
	}
}

// handleMemory пишет в memory.log обращение чужого процесса к памяти защищённого приложения. Без окон и тревог: журнал
// только для разбора. Свои процессы (vault, SYSTEM, служба) не считаются.
func (s *Service) handleMemory(r audit.Read) {
	if r.SID == "S-1-5-18" || r.SID == "S-1-5-19" || r.SID == "S-1-5-20" || strings.EqualFold(r.Process, s.exe) {
		return
	}
	if vault, _, _, err := windows.LookupSID("", isolation.VaultUser); err == nil && r.SID == vault.String() {
		return
	}
	key := fmt.Sprintf("%d:%d", r.PID, r.Mask)
	s.mu.Lock()
	if s.memSeen == nil {
		s.memSeen = map[string]time.Time{}
	}
	if t, ok := s.memSeen[key]; ok && time.Since(t) < memDedup {
		s.mu.Unlock()
		return
	}
	if len(s.memSeen) > memLogMax {
		clear(s.memSeen)
	}
	s.memSeen[key] = time.Now()
	line := fmt.Sprintf("%s %s: %s (PID %d) -> %s, %s", time.Now().Format("2006/01/02 15:04:05"), r.User, r.Process, r.PID, filepath.Base(r.Object), memAccess(r.Mask))
	s.memReads++
	s.memLast = line
	s.mu.Unlock()
	s.log.Println("обращение к памяти защищённого приложения:", line)
	checkMu.Lock()
	lastCheck = "" // отчёт должен учесть свежее обращение, а не кеш
	checkMu.Unlock()
	rotateLog(MemoryLogPath())
	f, err := os.OpenFile(MemoryLogPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(line + "\n")
}

func memAccess(mask uint32) string {
	var parts []string
	for _, a := range []struct {
		bit  uint32
		name string
	}{{0x10, "чтение памяти"}, {0x20, "запись памяти"}, {0x8, "операции с памятью"}, {0x2, "создание потока"}} {
		if mask&a.bit != 0 {
			parts = append(parts, a.name)
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("доступ 0x%x", mask)
	}
	return strings.Join(parts, ", ")
}

// memoryState — сколько обращений записано с запуска службы и последнее из них.
func (s *Service) memoryState() (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memReads, s.memLast
}
