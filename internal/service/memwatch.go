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
	"github.com/loar32/sessionvault/internal/profiles"
	"golang.org/x/sys/windows"
)

const (
	memDedup          = time.Minute
	memWatchEvery     = 5 * time.Second // не чаще: статус опрашивает трей раз в 10 с, а после действия чаще
	memSeenMax        = 8 * 1024
	exeCacheTTL       = 30 * time.Second
	memLinesPerMinute = 60
)

func MemoryLogPath() string { return filepath.Join(isolation.BaseDir(), "memory.log") }

// jobPIDList — JOBOBJECT_BASIC_PROCESS_ID_LIST с запасом под потомков браузера.
type jobPIDList struct {
	Assigned uint32
	InList   uint32
	IDs      [512]uintptr
}

// jobPIDs — процессы, которые сейчас работают в job-объекте службы (все защищённые приложения и их потомки).
func jobPIDs(job windows.Handle) []uint32 {
	var l jobPIDList
	// Процессов больше, чем влезло в список: берём то, что вернулось (ERROR_MORE_DATA).
	if err := windows.QueryInformationJobObject(job, 3, uintptr(unsafe.Pointer(&l)), uint32(unsafe.Sizeof(l)), nil); err != nil && err != windows.ERROR_MORE_DATA {
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
	job, done, prevFailed := s.job, s.memWatched, s.memFailed
	s.mu.Unlock()
	// Процесс, на который аудит уже поставлен, второй раз не трогаем; вышедшие процессы из набора пропадают. Неудача
	// запоминается лишь до следующего опроса, но пишется в журнал один раз на процесс: процесс мог ещё не дозапуститься.
	now, failed := map[uint32]bool{}, map[uint32]bool{}
	for _, pid := range jobPIDs(job) {
		if done[pid] {
			now[pid] = true
			continue
		}
		if err := audit.WatchProcess(pid); err != nil {
			if !prevFailed[pid] {
				s.log.Printf("аудит процесса %d: %v", pid, err)
			}
			failed[pid] = true
			continue
		}
		now[pid] = true
	}
	s.mu.Lock()
	s.memWatched, s.memFailed = now, failed
	s.mu.Unlock()
}

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
	s.memReads++
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
	rotateLog(MemoryLogPath())
	f, err := os.OpenFile(MemoryLogPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(line + "\n")
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

// memoryState — сколько обращений записано с запуска службы и последнее из них.
func (s *Service) memoryState() (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memReads, s.memLast
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
