package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/loar32/sessionvault/internal/audit"
	"github.com/loar32/sessionvault/internal/decoy"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"github.com/loar32/sessionvault/internal/ui/alert"
	"golang.org/x/sys/windows"
)

const (
	trapTick     = 5 * time.Minute // приманка и так обновляется раз в decoyRefresh; раньше срока службу будит команда sync
	trapMinGap   = 5 * time.Second
	decoyRefresh = 6 * time.Hour
	alarmLatch   = 10 * time.Minute
	alarmDedup   = 30 * time.Second
	eventQueue   = 256
)

func AlertsPath() string { return filepath.Join(isolation.BaseDir(), "alerts.log") }

// StartTraps включает аудит и приманки; без них служба продолжает работать, но не видит чтения.
func (s *Service) StartTraps() {
	if err := isolation.EnablePrivileges("SeSecurityPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege"); err != nil {
		s.log.Println("привилегии для аудита:", err)
	}
	s.allow = newAllowlist(s.cfg.DecoyAllow, s.log.Printf)
	s.ensureAudit()
	s.watchSync()
	stop, err := audit.Subscribe(s.onRead)
	if err != nil {
		s.log.Println("подписка на журнал аудита:", err)
	} else {
		s.stopAudit = stop
	}
	go s.trapWorker()
	go s.trapLoop()
}

func (s *Service) stopTraps() {
	s.quitOnce.Do(func() {
		close(s.quit)
		if s.syncEvent != 0 {
			_ = windows.SetEvent(s.syncEvent)
		}
	})
	if s.stopAudit != nil {
		s.stopAudit()
	}
}

// Политику аудита могли сбросить (групповая политика, администратор): проверяем её вместе с приманками.
func (s *Service) ensureAudit() {
	changed, err := audit.EnableFileSystem()
	if err != nil {
		s.log.Println("аудит файловой системы не включён:", err)
	} else if changed {
		s.log.Println("аудит файловой системы включён")
		if cfg, err := LoadConfig(); err == nil && !cfg.AuditByUs {
			if err := UpdateConfig(func(c *Config) { c.AuditByUs = true }); err != nil {
				s.log.Println("config.json:", err)
			}
		}
	}
	changed, err = audit.EnableKernelObject()
	if err != nil {
		s.log.Println("аудит объектов ядра не включён:", err)
		return
	}
	if !changed {
		return
	}
	s.log.Println("аудит объектов ядра включён")
	if cfg, err := LoadConfig(); err == nil && !cfg.KernelAuditByUs {
		if err := UpdateConfig(func(c *Config) { c.KernelAuditByUs = true }); err != nil {
			s.log.Println("config.json:", err)
		}
	}
}

func (s *Service) trapLoop() {
	t := time.NewTicker(trapTick)
	defer t.Stop()
	for {
		s.syncDecoys()
		select {
		case <-s.quit:
			return
		case <-t.C:
			s.ensureAudit()
		case <-s.nudge:
			s.ensureAudit()
			select {
			case <-s.quit:
				return
			case <-time.After(trapMinGap):
			}
		}
	}
}

// Приманка кладётся на прежнее место данных профиля, но только после импорта: пока там настоящая tdata, её не трогаем.
func (s *Service) syncDecoys() {
	cfg, err := LoadConfig()
	if err != nil {
		return
	}
	user, _, _, err := windows.LookupSID("", cfg.MainUser)
	if err != nil {
		s.log.Println("приманка:", err)
		return
	}
	watch := map[string]bool{}
	for name, origin := range cfg.Origins {
		// Пока data.enc не записан, импорт не закончен: при его откате данные должны вернуться на это место.
		if _, err := os.Stat(filepath.Join(isolation.DataPath(name), "data.enc")); err != nil {
			continue
		}
		p, err := profiles.Load(isolation.ProfilesDir(), name)
		if err != nil || p.Decoy == "" {
			continue
		}
		created, err := decoy.Ensure(name, p.Decoy, origin, user, decoyRefresh)
		foreign := errors.Is(err, decoy.ErrForeign)
		switch {
		case foreign && !decoy.Known(name, origin):
			// Настоящие данные (например, обычный Telegram): не трогаем и не наблюдаем.
			if !s.warned[name] {
				s.log.Printf("приманка %s: на %s лежат чужие данные, не трогаю", name, origin)
				s.warned[name] = true
			}
			continue
		case err != nil && !foreign:
			s.log.Printf("приманка %s: %v", name, err)
		}
		// Наблюдение не должно зависеть от успеха обновления: чужой файл в нашей приманке или занятый файл
		// иначе снимали бы её с наблюдения. SACL ставится заново на каждом проходе, на случай прежней ошибки.
		if _, statErr := os.Stat(origin); statErr != nil {
			continue
		}
		s.warned[name] = false
		// Путь лежит в профиле пользователя: ссылка или junction на нём увела бы SACL (и шум в журнале) на чужую папку.
		if err := decoy.NoReparse(origin); err != nil {
			s.log.Printf("приманка %s: %v", name, err)
			continue
		}
		if err := audit.WatchReads(origin); err != nil {
			s.log.Printf("аудит приманки %s: %v", name, err)
			continue
		}
		if created {
			s.log.Printf("приманка %s создана: %s", name, origin)
		}
		// Журнал пишет объект то с буквой диска, то в формате устройства: ждём обе записи.
		watch[origin] = true
		if nt, err := audit.NTPath(origin); err == nil {
			watch[nt] = true
		}
	}
	s.trapMu.Lock()
	s.watch = watch
	s.trapMu.Unlock()
}

func (s *Service) watched(object string) bool {
	s.trapMu.Lock()
	defer s.trapMu.Unlock()
	for root := range s.watch {
		if audit.Under(root, object) {
			return true
		}
	}
	return false
}

// Объект можно открыть по короткому имени (ADMINI~1): сравниваем и с полным.
func (s *Service) watchedLong(object string) bool {
	if s.watched(object) {
		return true
	}
	if !strings.Contains(object, "~") || len(object) < 3 || object[1] != ':' {
		return false
	}
	p, err := windows.UTF16PtrFromString(object)
	if err != nil {
		return false
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(p, &buf[0], uint32(len(buf)))
	return err == nil && n > 0 && int(n) < len(buf) && s.watched(windows.UTF16ToString(buf))
}

// Вызывается из потока доставки событий ОС: только ставит событие в очередь, тяжёлое делает trapWorker.
func (s *Service) onRead(r audit.Read) {
	select {
	case s.events <- r:
	default:
	}
}

func (s *Service) trapWorker() {
	for {
		select {
		case <-s.quit:
			return
		case r := <-s.events:
			s.handleRead(r)
		}
	}
}

func (s *Service) handleRead(r audit.Read) {
	defer func() {
		if p := recover(); p != nil {
			s.log.Printf("обработка события чтения: %v", p)
		}
	}()
	if r.Type == "Process" {
		s.handleMemory(r)
		return
	}
	// Сама служба читает приманку при проверке (список файлов) — это не тревога.
	if !s.watchedLong(r.Object) || strings.EqualFold(r.Process, s.exe) || s.allow.allowed(r.Process, r.PID) {
		return
	}
	// Один разбор на серию чтений: окно, звук и журнал не должны множиться, если процесс порождает потомков.
	s.trapMu.Lock()
	repeat := !s.alarmAt.IsZero() && time.Since(s.alarmAt) < alarmDedup
	if !repeat {
		s.alarmAt = time.Now()
	}
	s.trapMu.Unlock()
	if repeat {
		s.log.Printf("повторное чтение приманки: %q (PID %d)", r.Process, r.PID)
		return
	}
	s.alarm(r)
}

func (s *Service) alarmed() bool {
	s.trapMu.Lock()
	defer s.trapMu.Unlock()
	return !s.alarmAt.IsZero() && time.Since(s.alarmAt) < alarmLatch
}

// Сначала гасим приложения — это единственное, что нельзя откладывать; остальное (хэш, журнал, окно) уже не торопится.
// Ключи стираем только после шифрования: оно идёт на тех же ключах.
func (s *Service) alarm(r audit.Read) {
	s.killApps()
	go func() {
		s.wg.Wait()
		s.mu.Lock()
		if len(s.running) == 0 && !s.prompting {
			s.lock()
		}
		s.mu.Unlock()
	}()

	info := alert.Info{Process: r.Process, PID: r.PID, SHA256: fileHash(r.Process), Object: r.Object, Time: time.Now()}
	s.log.Printf("ТРЕВОГА: приманку прочитал %q (PID %d, SHA-256 %s)", info.Process, info.PID, info.SHA256)
	if err := appendAlert(info); err != nil {
		s.log.Println("журнал тревог:", err)
	}
	arg, err := alert.Encode(info)
	if err != nil {
		return
	}
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xFFFFFFFF {
		return
	}
	_, proc, _, err := isolation.StartInSession(session, fmt.Sprintf(`"%s" alert %s`, s.exe, arg), false)
	if err != nil {
		s.log.Println("окно тревоги:", err)
		return
	}
	_ = windows.CloseHandle(proc)
}

// Закрытие job убивает приложения; новый job нужен следующим запускам.
func (s *Service) killApps() {
	fresh, err := killOnCloseJob()
	if err != nil {
		// Нового job нет: гасим приложения в текущем (он же останется рабочим).
		s.log.Println("job:", err)
		_ = windows.TerminateJobObject(s.jobHandle(), 1)
		return
	}
	s.mu.Lock()
	old := s.job
	s.job = fresh
	s.mu.Unlock()
	_ = windows.CloseHandle(old)
}

func fileHash(path string) string {
	// Путь процесса приходит из журнала: exe с сетевой шары заставил бы SYSTEM обратиться к чужому серверу.
	if !localFixed(path) {
		return "не считался (не локальный диск)"
	}
	f, err := os.Open(path)
	if err != nil {
		return "недоступен"
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "недоступен"
	}
	return hex.EncodeToString(h.Sum(nil))
}

func appendAlert(i alert.Info) error {
	b, err := json.Marshal(i)
	if err != nil {
		return err
	}
	rotateLog(AlertsPath())
	f, err := os.OpenFile(AlertsPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.Write(append(b, '\n'))
	return err
}

func localFixed(path string) bool {
	if len(path) < 3 || path[1] != ':' || path[2] != '\\' {
		return false
	}
	root, err := windows.UTF16PtrFromString(path[:3])
	return err == nil && windows.GetDriveType(root) == windows.DRIVE_FIXED
}
