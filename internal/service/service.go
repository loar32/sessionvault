package service

import (
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/loar32/sessionvault/internal/crypto"
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
	systemOnlySDDL = "D:P(A;;GA;;;SY)"
)

type Service struct {
	cfg  Config
	exe  string
	log  *log.Logger
	job  windows.Handle
	cmdL *ipc.Listener

	mu        sync.Mutex
	keys      map[string][]byte // DEK профилей, пока хранилище разблокировано
	running   map[string]bool
	prompting bool
	idle      *time.Timer
	wg        sync.WaitGroup
}

func New(cfg Config, exe string, l *log.Logger) (*Service, error) {
	job, err := killOnCloseJob()
	if err != nil {
		return nil, err
	}
	return &Service{cfg: cfg, exe: exe, log: l, job: job, keys: map[string][]byte{}, running: map[string]bool{}}, nil
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
	l, err := ipc.Listen(ipc.CommandPipe, "D:P(A;;GA;;;SY)(A;;GRGW;;;"+sid.String()+")")
	if err != nil {
		return err
	}
	s.cmdL = l
	return nil
}

func (s *Service) Serve() {
	for {
		c, err := s.cmdL.Accept(0)
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

// Остановка: закрытие job убивает приложения, затем данные шифруются кэшированными ключами.
func (s *Service) Stop() {
	s.cmdL.Close()
	_ = windows.CloseHandle(s.job)
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		s.log.Println("не все данные успели зашифроваться при остановке")
	}
	s.mu.Lock()
	s.lock()
	s.mu.Unlock()
}

func (s *Service) handle(c *ipc.Conn) {
	defer c.Close()
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
		_ = c.WriteLine(s.state())
	case "run":
		_ = c.WriteLine(s.run(c, req.Profile))
	}
}

func (s *Service) state() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.keys) == 0 {
		return ipc.Locked
	}
	return ipc.Unlocked
}

func (s *Service) run(c *ipc.Conn, name string) string {
	p, err := profiles.Load(isolation.ProfilesDir(), name)
	if err != nil {
		s.log.Printf("run %s: %v", name, err)
		return ipc.Failed
	}
	session, err := c.ClientSession()
	if err != nil || session == 0 {
		return ipc.Failed
	}
	v := vault.Vault{Dir: isolation.DataPath(name), DataName: workDataName}
	if !v.Exists() {
		s.log.Printf("run %s: хранилища нет", name)
		return ipc.Failed
	}

	s.mu.Lock()
	if s.running[name] || s.prompting {
		s.mu.Unlock()
		return ipc.Busy
	}
	s.running[name] = true
	s.stopIdle()
	dek := s.keys[name]
	s.mu.Unlock()

	resp, err := s.start(p, v, dek, session)
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

func (s *Service) start(p profiles.Profile, v vault.Vault, dek []byte, session uint32) (string, error) {
	if dek == nil {
		var err error
		if dek, err = s.askPassword(p.Name, v, session); err != nil {
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
	if err := isolation.ProtectWork(isolation.WorkPath(p.Name)); err != nil {
		unlock()
		return "", errors.Join(err, v.Encrypt(dek))
	}

	_, proc, thread, err := isolation.StartInSession(session, fmt.Sprintf(`"%s" launch %s`, s.exe, p.Name), true)
	if err != nil {
		unlock()
		return "", errors.Join(err, v.Encrypt(dek))
	}
	if err := windows.AssignProcessToJobObject(s.job, proc); err != nil {
		_ = windows.TerminateProcess(proc, 1)
		_ = windows.CloseHandle(proc)
		_ = windows.CloseHandle(thread)
		unlock()
		return "", errors.Join(err, v.Encrypt(dek))
	}
	_, _ = windows.ResumeThread(thread)
	_ = windows.CloseHandle(thread)

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
	s.resetIdle()
}

// Ключ нужен при выходе приложения для шифрования, поэтому блокировка — только когда ничего не запущено.
func (s *Service) resetIdle() {
	s.stopIdle()
	if len(s.running) > 0 || len(s.keys) == 0 {
		return
	}
	s.idle = time.AfterFunc(time.Duration(s.cfg.IdleMinutes)*time.Minute, func() {
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
	for name, k := range s.keys {
		crypto.Wipe(k)
		crypto.Unlock(k)
		delete(s.keys, name)
	}
}

// Окно пароля запускается от SYSTEM в сессии пользователя и общается с нами по pipe, закрытому для обычных учёток.
func (s *Service) askPassword(name string, v vault.Vault, session uint32) ([]byte, error) {
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

	l, err := ipc.Listen(ipc.UnlockPipe, systemOnlySDDL)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	pid, proc, _, err := isolation.StartInSession(session, fmt.Sprintf(`"%s" prompt %s`, s.exe, name), false)
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
	for range maxAttempts {
		pw, err := c.ReadBytes(passwordWait, ipc.MaxPassword)
		if err != nil {
			return nil, err
		}
		dek, err := v.Unlock(pw)
		crypto.Wipe(pw)
		if err == nil {
			_ = c.WriteLine(ipc.Ok)
			return s.keep(name, dek)
		}
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
	s.keys[name] = dek
	s.mu.Unlock()
	return dek, nil
}

func OpenLog() (*log.Logger, func(), error) {
	f, err := os.OpenFile(isolation.BaseDir()+`\service.log`, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return log.New(f, "", log.LstdFlags), func() { _ = f.Close() }, nil
}
