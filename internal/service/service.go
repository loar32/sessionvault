package service

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/loar32/sessionvault/internal/audit"
	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/extscan"
	"github.com/loar32/sessionvault/internal/ipc"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"github.com/loar32/sessionvault/internal/vault"
	"golang.org/x/sys/windows"
)

const (
	passwordWait   = 2 * time.Minute
	launchGrace    = 3 * time.Second
	maxAttempts    = 3
	workDataName   = "work"
	stopWait       = 30 * time.Second
	systemOnlySDDL = "D:P(A;;GA;;;SY)"

	// Процесс основной учётки может слать run сколько угодно: без пауз он засыпал бы пользователя окнами пароля.
	runGap         = 2 * time.Second
	promptCooldown = 10 * time.Second
	failLogEvery   = 5 * time.Second
)

type Service struct {
	cfg          Config
	idleAfter    time.Duration
	exe          string
	log          *log.Logger
	job          windows.Handle       // под mu: после тревоги заменяется новым
	memWatchAt   time.Time            // под mu: когда в последний раз ставили аудит на процессы приложений
	memSeen      map[string]time.Time // под mu: недавние обращения к памяти (процесс+права), чтобы не писать повторы
	memReads     int                  // под mu: записано обращений с запуска службы
	memLast      string               // под mu: последнее обращение
	memWatched   map[uint32]bool      // под mu: процессы, на которые уже ставили аудит
	exeCache     []string             // под mu: exe защищённых приложений для фильтра обращений к памяти
	exeCacheAt   time.Time
	memWindow    time.Time // под mu: начало минуты для лимита записей журнала памяти
	memWritten   int
	memSkipped   int
	memFailed    map[uint32]bool // под mu: процессы, на которые аудит поставить не удалось (в журнал пишется один раз)
	targets      func() []string // только для тестов: exe защищённых приложений
	vaultSID     string
	vaultSIDOnce sync.Once
	cmdL         *ipc.Listener

	allow     allowlist
	stopAudit func()
	quit      chan struct{}
	nudge     chan struct{} // просьба проверить приманки и аудит раньше срока (событие syncEventName)
	syncEvent windows.Handle
	trapMu    sync.Mutex
	watch     map[string]bool // папки приманок в формате устройства
	events    chan audit.Read
	memEvents chan audit.Read // обращения к памяти приложений: отдельно от чтения приманки
	quitOnce  sync.Once
	alarmAt   time.Time
	warned    map[string]bool

	mu          sync.Mutex
	keys        map[string][]byte // DEK профилей, пока хранилище разблокировано
	running     map[string]bool
	closing     map[string]bool           // приложение вышло, данные ещё шифруются: новый экземпляр запускать нельзя
	ext         map[string]extscan.Result // результат последней проверки расширений по профилям браузеров
	prompting   bool
	lastFailLog time.Time            // когда последний раз писали об ошибке запуска
	lastRun     map[string]time.Time // по профилям: запуск одного приложения не задерживает другое
	lastOpen    time.Time
	promptEnd   map[string]time.Time // когда последнее окно пароля профиля закончилось отказом или закрытием
	idle        *time.Timer
	lockPending bool // блокировка запрошена событием Windows, но приложение ещё запущено
	wg          sync.WaitGroup
}

func New(cfg Config, exe string, l *log.Logger) (*Service, error) {
	job, err := killOnCloseJob()
	if err != nil {
		return nil, err
	}
	return &Service{cfg: cfg, idleAfter: idleDuration(cfg.IdleMinutes), exe: exe, log: l, job: job, keys: map[string][]byte{}, running: map[string]bool{}, quit: make(chan struct{}), nudge: make(chan struct{}, 1), events: make(chan audit.Read, eventQueue), memEvents: make(chan audit.Read, eventQueue), warned: map[string]bool{}}, nil
}

func killOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	return job, err
}

// Pipe команд открыт SYSTEM и основной учётке; остальным даже подключиться нельзя.
func (s *Service) Listen() error {
	sid, _, _, err := windows.LookupSID("", s.cfg.MainUser)
	if err != nil {
		return fmt.Errorf("учётка %q не найдена: %w", s.cfg.MainUser, err)
	}
	l, err := ipc.Listen(ipc.CommandPipe, "D:P(A;;GA;;;SY)(A;;0x12019b;;;"+sid.String()+")")
	if err != nil {
		return err
	}
	s.cmdL = l
	return nil
}

const maxConns = 16

// Права основной учётки на pipe — чтение и запись без FILE_APPEND_DATA (он же CREATE_PIPE_INSTANCE):
// иначе процесс пользователя мог бы создать свой экземпляр pipe и подменять ответы.
// Ошибка одного подключения (клиент отвалился на ходу) не должна останавливать приём остальных.
func (s *Service) Serve() {
	sem := make(chan struct{}, maxConns)
	for {
		c, err := s.cmdL.Accept(0)
		if err != nil {
			if s.cmdL.Closed() {
				return
			}
			s.log.Println("pipe команд:", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				s.handle(c)
			}()
		default:
			c.Close() // слишком много одновременных подключений
		}
	}
}

// Остановка: закрытие job убивает приложения, затем данные шифруются кэшированными ключами.
func (s *Service) Stop() {
	s.stopTraps()
	s.cmdL.Close()
	s.mu.Lock()
	_ = windows.CloseHandle(s.job)
	s.mu.Unlock()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		s.mu.Lock()
		s.lock()
		s.mu.Unlock()
	case <-time.After(stopWait):
		// Ключи не стираем: их ещё использует шифрование, процесс всё равно завершается.
		s.log.Println("не все данные успели зашифроваться при остановке")
	}
}

func (s *Service) handle(c *ipc.Conn) {
	defer c.Close()
	// Паника в обработчике одного подключения не должна останавливать службу.
	defer func() {
		if p := recover(); p != nil {
			s.log.Printf("паника при обработке запроса: %v", p)
		}
	}()
	line, err := c.ReadLine(5*time.Second, ipc.MaxLine)
	if err != nil {
		return
	}
	req, err := ipc.Parse(line)
	if err != nil {
		_ = c.WriteLine(ipc.Failed)
		return
	}
	switch req.Cmd {
	case "status":
		s.watchMemory()
		_ = c.WriteLine(s.state())
	case "list":
		_ = c.WriteLine(s.list())
	case "run":
		_ = c.WriteLine(s.run(c, req.Profile, ""))
	case "check":
		_ = c.WriteLine(s.check())
	case "open":
		_ = c.WriteLine(s.open(c))
	case "hello":
		_ = c.WriteLine(s.enableHello(c, req.Profile))
	case "fido":
		_ = c.WriteLine(s.enableFido(c, req.Profile))
	}
}

// Имена профилей, у которых есть хранилище: по ним трей строит меню. Ничего, кроме имён, наружу не уходит.
func (s *Service) list() string {
	entries, err := os.ReadDir(isolation.VaultDir())
	if err != nil {
		return ""
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() || !profiles.ValidName(e.Name()) {
			continue
		}
		v := vault.Vault{Dir: isolation.DataPath(e.Name()), DataName: workDataName}
		if _, err := profiles.Load(isolation.ProfilesDir(), e.Name()); err == nil && v.Exists() {
			names = append(names, e.Name())
		}
	}
	return strings.Join(names, ",")
}

func (s *Service) state() string {
	if s.alarmed() {
		return ipc.Alarm
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.keys) == 0 {
		return ipc.Locked
	}
	return ipc.Unlocked
}

func (s *Service) run(c *ipc.Conn, name, link string) string {
	p, err := profiles.Load(isolation.ProfilesDir(), name)
	if err != nil {
		s.logRunFailure("run %s: %v", name, err)
		return ipc.Failed
	}
	session, err := c.ClientSession()
	if err != nil || session == 0 {
		return ipc.Failed
	}
	v := vault.Vault{Dir: isolation.DataPath(name), DataName: workDataName, Exclude: p.Exclude}
	if !v.Exists() {
		s.logRunFailure("run %s: хранилища нет", name)
		return ipc.Failed
	}

	s.mu.Lock()
	if !s.admit(name, time.Now()) {
		s.mu.Unlock()
		return ipc.Busy
	}
	s.running[name] = true
	s.stopIdle()
	dek := s.keys[name]
	s.mu.Unlock()

	resp, err := s.start(p, v, dek, session, link)
	if err != nil {
		s.log.Printf("run %s: %v", name, err)
		s.finish(name)
		if errors.Is(err, errBusy) {
			return ipc.Busy
		}
		return ipc.Failed
	}
	return resp
}

var errBusy = errors.New("занято")

// Запросы run с несуществующими именами может слать любой процесс основной учётки: без ограничения журнал рос бы без предела.
func (s *Service) logRunFailure(format string, args ...any) {
	s.mu.Lock()
	ok := time.Since(s.lastFailLog) > failLogEvery
	if ok {
		s.lastFailLog = time.Now()
	}
	s.mu.Unlock()
	if ok {
		s.log.Printf(format, args...)
	}
}

// Вызывается под mu. Окно пароля после отказа или закрытия не появляется снова сразу;
// при разблокированном хранилище окна нет и пауза не нужна.
func (s *Service) admit(name string, now time.Time) bool {
	if s.running[name] || s.prompting {
		return false
	}
	if now.Sub(s.lastRun[name]) < runGap || (s.keys[name] == nil && now.Sub(s.promptEnd[name]) < promptCooldown) {
		return false
	}
	if s.lastRun == nil {
		s.lastRun = map[string]time.Time{}
	}
	s.lastRun[name] = now
	return true
}

func (s *Service) start(p profiles.Profile, v vault.Vault, dek []byte, session uint32, link string) (string, error) {
	if dek == nil {
		var err error
		if dek, err = s.askPassword(p.Name, v, session, true); err != nil {
			s.mu.Lock()
			if s.promptEnd == nil {
				s.promptEnd = map[string]time.Time{}
			}
			s.promptEnd[p.Name] = time.Now()
			s.mu.Unlock()
			return "", err
		}
	}
	unlock, err := v.Lock()
	if err != nil {
		return "", errBusy
	}
	if v.NeedsRecovery() {
		s.log.Printf("%s: дошифровываю открытые данные после сбоя", p.Name)
		if err := v.Encrypt(dek); err != nil {
			unlock()
			return "", err
		}
	}
	if err := v.Decrypt(dek); err != nil {
		unlock()
		return "", err
	}
	if err := isolation.ProtectWork(isolation.WorkPath(p.Name), execApproved(p)); err != nil {
		unlock()
		return "", errors.Join(err, v.Encrypt(dek))
	}
	s.scanExtensions(p)

	_, proc, thread, err := isolation.StartInSession(session, launchLine(s.exe, p.Name, link), true)
	if err != nil {
		unlock()
		return "", errors.Join(err, v.Encrypt(dek))
	}
	if err := windows.AssignProcessToJobObject(s.jobHandle(), proc); err != nil {
		_ = windows.TerminateProcess(proc, 1)
		_ = windows.CloseHandle(proc)
		_ = windows.CloseHandle(thread)
		unlock()
		return "", errors.Join(err, v.Encrypt(dek))
	}
	_, _ = windows.ResumeThread(thread)
	_ = windows.CloseHandle(thread)
	// Приложение запущено: потомки появятся позже, их подхватит ближайший опрос статуса.
	time.AfterFunc(memWatchEvery, s.watchMemory)

	// Быстрый выход помощника — ошибка запуска, а не нормальная работа приложения.
	if ev, _ := windows.WaitForSingleObject(proc, uint32(launchGrace.Milliseconds())); ev == windows.WAIT_OBJECT_0 {
		var code uint32
		_ = windows.GetExitCodeProcess(proc, &code)
		_ = windows.CloseHandle(proc)
		unlock()
		return "", errors.Join(fmt.Errorf("приложение не запустилось (код %d)", code), v.Encrypt(dek))
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_, _ = windows.WaitForSingleObject(proc, windows.INFINITE)
		_ = windows.CloseHandle(proc)
		s.mu.Lock()
		if s.closing == nil {
			s.closing = map[string]bool{}
		}
		s.closing[p.Name] = true
		s.mu.Unlock()
		if err := v.Encrypt(dek); err != nil {
			s.log.Printf("%s: шифрование после закрытия: %v", p.Name, err)
		}
		unlock()
		s.finish(p.Name)
	}()
	return ipc.Ok, nil
}

func (s *Service) finish(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.running, name)
	delete(s.closing, name)
	if s.lockPending && len(s.running) == 0 {
		s.lock()
		s.log.Println("хранилище заблокировано после выхода приложений (блокировка сеанса, сон или выход)")
		return
	}
	s.resetIdle()
}

// Блокировка сеанса, выход из системы или сон: ключи стираются сразу, а если приложение запущено,
// то после его выхода (ключ нужен для шифрования).
func (s *Service) lockRequested() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.running) > 0 {
		s.lockPending = true
		return
	}
	s.lock()
	s.log.Println("хранилище заблокировано (блокировка сеанса, сон или выход)")
}

// Ключ нужен при выходе приложения для шифрования, поэтому блокировка — только когда ничего не запущено.
func (s *Service) resetIdle() {
	s.stopIdle()
	if len(s.running) > 0 || len(s.keys) == 0 || s.idleAfter <= 0 {
		return
	}
	s.idle = time.AfterFunc(s.idleAfter, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(s.running) == 0 {
			s.lock()
			s.log.Println("хранилище заблокировано по бездействию")
		}
	})
}

func (s *Service) stopIdle() {
	if s.idle != nil {
		s.idle.Stop()
		s.idle = nil
	}
}

func (s *Service) lock() {
	s.lockPending = false
	for name, k := range s.keys {
		crypto.Wipe(k)
		crypto.Unlock(k)
		delete(s.keys, name)
	}
}

// Окно пароля запускается от SYSTEM в сессии пользователя и общается с нами по pipe, закрытому для обычных учёток.
func (s *Service) askPassword(name string, v vault.Vault, session uint32, allowHello bool) ([]byte, error) {
	s.mu.Lock()
	if s.prompting {
		s.mu.Unlock()
		return nil, errBusy
	}
	s.prompting = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.prompting = false
		s.mu.Unlock()
	}()

	if allowHello {
		if dek, ok := s.tryFido(name, v, session); ok {
			return s.keep(name, dek)
		}
		if dek, ok := s.tryHello(name, v, session); ok {
			return s.keep(name, dek)
		}
	}

	tail, err := crypto.NewSalt()
	if err != nil {
		return nil, err
	}
	pipe := ipc.UnlockPipe + hex.EncodeToString(tail)
	l, err := ipc.Listen(pipe, systemOnlySDDL)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	pid, proc, _, err := isolation.StartInSession(session, fmt.Sprintf(`"%s" prompt %s %s`, s.exe, name, pipe), false)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = windows.TerminateProcess(proc, 0)
		_ = windows.CloseHandle(proc)
	}()

	c, err := l.Accept(30 * time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if cp, err := c.ClientPID(); err != nil || cp != pid {
		return nil, errors.New("к pipe пароля подключился чужой процесс")
	}
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		pw, err := c.ReadBytes(passwordWait, ipc.MaxPassword)
		if err != nil {
			return nil, err
		}
		dek, err := v.Unlock(pw)
		crypto.Wipe(pw)
		if err == nil {
			s.log.Printf("%s: хранилище разблокировано (попытка %d)", name, attempt)
			_ = c.WriteLine(ipc.Ok)
			return s.keep(name, dek)
		}
		s.log.Printf("%s: неверный пароль (попытка %d): %v", name, attempt, err)
		if !errors.Is(err, vault.ErrWrongPassword) {
			_ = c.WriteLine(ipc.Failed)
			return nil, err
		}
		_ = c.WriteLine("bad")
	}
	return nil, vault.ErrWrongPassword
}

func (s *Service) keep(name string, dek []byte) ([]byte, error) {
	if err := crypto.Lock(dek); err != nil {
		crypto.Wipe(dek)
		return nil, err
	}
	s.mu.Lock()
	if old := s.keys[name]; old != nil {
		// Повторный ввод (например, при включении Hello): прежний ключ не должен остаться в памяти.
		crypto.Wipe(old)
		crypto.Unlock(old)
	}
	s.keys[name] = dek
	s.mu.Unlock()
	return dek, nil
}

func OpenLog() (*log.Logger, func(), error) {
	rotateLog(isolation.BaseDir() + `\service.log`)
	f, err := os.OpenFile(isolation.BaseDir()+`\service.log`, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, err
	}
	// Паника службы иначе пропала бы: у службы нет stderr.
	_ = debug.SetCrashOutput(f, debug.CrashOptions{})
	return log.New(f, "", log.LstdFlags), func() { _ = f.Close() }, nil
}

func (s *Service) jobHandle() windows.Handle {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.job
}

// Запуск разрешается только файлам из списка профиля, подписанным нужным издателем: подпись проверяется перед каждым
// запуском приложения, пока оно ничего не может менять.
func execApproved(p profiles.Profile) func(string) bool {
	if len(p.ExecFiles) == 0 || p.ExecSigner == "" {
		return nil
	}
	return func(path string) bool {
		if !slices.ContainsFunc(p.ExecFiles, func(n string) bool { return strings.EqualFold(n, filepath.Base(path)) }) {
			return false
		}
		name, err := audit.Signer(path)
		return err == nil && strings.EqualFold(name, p.ExecSigner)
	}
}
