package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/loar32/sessionvault/internal/audit"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"golang.org/x/sys/windows"
)

const (
	memDedup          = time.Minute
	memSeenMax        = 8 * 1024
	exeCacheTTL       = 30 * time.Second
	memLinesPerMinute = 60
	memTimesMax       = 10000
	memLogParts       = 4 // прежних частей журнала обращений к памяти
	memKeep           = 24 * time.Hour
)

func MemoryLogPath() string { return filepath.Join(isolation.BaseDir(), "memory.log") }

func (s *Service) memWorker() {
	for {
		select {
		case <-s.quit:
			return
		case r := <-s.memEvents:
			s.handleMemory(r)
		}
	}
}

// Имена exe защищённых приложений и самой программы: обращение к любому другому процессу (например, у которого есть
// собственный системный аудит) к защищённым приложениям не относится.
func (s *Service) protectedExes() []string {
	if s.targets != nil {
		return s.targets()
	}
	// Список читается с диска, а событий может быть много (чужой процесс способен слать их потоком): кеш на полминуты.
	s.mu.Lock()
	if s.exeCache != nil && time.Since(s.exeCacheAt) < exeCacheTTL {
		defer s.mu.Unlock()
		return s.exeCache
	}
	s.mu.Unlock()
	exes := []string{s.exe}
	for _, name := range strings.Split(s.list(), ",") {
		if p, err := profiles.Load(isolation.ProfilesDir(), name); err == nil {
			exes = append(exes, p.Exe)
		}
	}
	s.mu.Lock()
	s.exeCache, s.exeCacheAt = exes, time.Now()
	s.mu.Unlock()
	return exes
}

// isVaultSID — SID принадлежит учётке защищённого приложения (sv-*); результат по SID запоминается.
func (s *Service) isVaultSID(sid string) bool {
	s.mu.Lock()
	v, ok := s.appSIDs[sid]
	s.mu.Unlock()
	if ok {
		return v
	}
	p, err := windows.StringToSid(sid)
	v = err == nil && isolation.IsAppAccount(p)
	s.mu.Lock()
	if s.appSIDs == nil {
		s.appSIDs = map[string]bool{}
	}
	s.appSIDs[sid] = v
	s.mu.Unlock()
	return v
}

// handleMemory пишет в memory.log обращение чужого процесса к памяти защищённого приложения. Без окон и тревог: журнал
// только для разбора. Свои процессы (vault, SYSTEM, служба) не считаются.
func (s *Service) handleMemory(r audit.Read) {
	if r.SID == "S-1-5-18" || r.SID == "S-1-5-19" || r.SID == "S-1-5-20" || strings.EqualFold(r.Process, s.exe) || s.isVaultSID(r.SID) {
		return
	}
	// Повторы одной программы с теми же правами сливаются на минуту независимо от PID: процесс-спамер, порождающий
	// потомков, не должен вытеснить из журнала нужную запись. Дешёвая проверка идёт первой: событий может быть много.
	key := fmt.Sprintf("%s:%d:%t", strings.ToLower(r.Process), r.Mask, r.Failure)
	s.mu.Lock()
	if t, ok := s.memSeen[key]; ok && time.Since(t) < memDedup {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	target := filepath.Base(r.Object)
	if !protectedTarget(target, s.protectedExes()) {
		return
	}
	s.mu.Lock()
	if s.memSeen == nil {
		s.memSeen = map[string]time.Time{}
	}
	if len(s.memSeen) > memSeenMax {
		clear(s.memSeen)
	}
	s.memSeen[key] = time.Now()
	s.memTimes = append(s.memTimes, time.Now())
	if len(s.memTimes) > memTimesMax {
		s.memTimes = s.memTimes[len(s.memTimes)-memTimesMax:]
	}
	// Лимит записей в минуту: поток уникальных имён не должен вытеснить из ротации журнала нужную запись.
	if time.Since(s.memWindow) > time.Minute {
		s.memWindow, s.memWritten = time.Now(), 0
	}
	if s.memWritten >= memLinesPerMinute {
		s.memSkipped++
		s.mu.Unlock()
		return
	}
	s.memWritten++
	skipped := ""
	if s.memSkipped > 0 {
		skipped = fmt.Sprintf(" [пропущено до этой записи: %d]", s.memSkipped)
		s.memSkipped = 0
	}
	outcome := ""
	if r.Failure {
		outcome = " (отказано)"
	}
	line := fmt.Sprintf("%s %s: %s (PID %d) -> %s, %s%s", time.Now().Format("2006/01/02 15:04:05"), clean(r.User), clean(r.Process), r.PID, clean(target), memAccess(r.Mask), outcome) + skipped
	s.memLast = truncRunes(line, 200) // идёт в ответ check: он ограничен по размеру
	s.mu.Unlock()
	s.log.Println("обращение к памяти защищённого приложения:", line)
	checkMu.Lock()
	lastCheck = "" // отчёт должен учесть свежее обращение, а не кеш
	checkMu.Unlock()
	rotateLogKeep(MemoryLogPath(), memLogParts)
	f, err := os.OpenFile(MemoryLogPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		defer func() { _ = f.Close() }()
		_, err = f.WriteString(line + "\n")
	}
	if err != nil {
		s.mu.Lock()
		first := !s.memWriteFailed
		s.memWriteFailed = true
		s.mu.Unlock()
		if first {
			s.log.Println("memory.log не записывается:", err)
		}
	}
}

func protectedTarget(base string, exes []string) bool {
	for _, e := range exes {
		if strings.EqualFold(filepath.Base(e), base) {
			return true
		}
	}
	return false
}

// Имена приходят из события Windows: управляющие символы в журнал не пускаем.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
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

// memoryState — сколько обращений записано за последние сутки и последнее из них.
func (s *Service) memoryState() (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := 0
	for i < len(s.memTimes) && time.Since(s.memTimes[i]) > memKeep {
		i++
	}
	s.memTimes = s.memTimes[i:]
	return len(s.memTimes), s.memLast
}

// loadMemoryHistory поднимает из memory.log записи последних суток: служба перезапускается, а журнал остаётся.
func (s *Service) loadMemoryHistory() {
	b, err := os.ReadFile(MemoryLogPath())
	if err != nil {
		return
	}
	var times []time.Time
	last := ""
	for _, l := range strings.Split(string(b), "\n") {
		if len(l) < 19 {
			continue
		}
		t, err := time.ParseInLocation("2006/01/02 15:04:05", l[:19], time.Local)
		if err != nil || time.Since(t) > memKeep {
			continue
		}
		times = append(times, t)
		last = truncRunes(l, 200)
	}
	if len(times) > memTimesMax {
		times = times[len(times)-memTimesMax:]
	}
	s.mu.Lock()
	s.memTimes, s.memLast = append(times, s.memTimes...), last
	s.mu.Unlock()
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
