package ipc

import (
	"bytes"
	"errors"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetClientSession = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetNamedPipeClientSessionId")

var ErrTimeout = errors.New("таймаут")

// Listener отдаёт соединения одного именованного pipe. DACL задаётся SDDL-строкой.
type Listener struct {
	name  string
	sa    *windows.SecurityAttributes
	first bool

	mu      sync.Mutex
	pending windows.Handle
	closed  bool
}

func Listen(name, sddl string) (*Listener, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	return &Listener{name: name, sa: sa, first: true}, nil
}

func (l *Listener) newInstance() (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(l.name)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.PIPE_ACCESS_DUPLEX)
	if l.first {
		// Первый экземпляр не даёт чужому процессу занять имя pipe раньше службы.
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	h, err := windows.CreateNamedPipe(p, flags,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		windows.PIPE_UNLIMITED_INSTANCES, 512, 512, 0, l.sa)
	if err == nil {
		l.first = false
	}
	return h, err
}

// timeout 0 — ждать бесконечно (до Close).
func (l *Listener) Accept(timeout time.Duration) (*Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, errors.New("listener закрыт")
	}
	h, err := l.newInstance()
	if err != nil {
		l.mu.Unlock()
		return nil, err
	}
	l.pending = h
	l.mu.Unlock()

	var timedOut bool
	var tm *time.Timer
	if timeout > 0 {
		tm = time.AfterFunc(timeout, func() {
			l.mu.Lock()
			timedOut = true
			l.mu.Unlock()
			_ = windows.CancelIoEx(h, nil)
		})
	}
	err = windows.ConnectNamedPipe(h, nil)
	if tm != nil {
		tm.Stop()
	}
	l.mu.Lock()
	l.pending = 0
	expired := timedOut
	l.mu.Unlock()
	if err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		_ = windows.CloseHandle(h)
		if expired {
			return nil, ErrTimeout
		}
		return nil, err
	}
	return &Conn{h: h}, nil
}

func (l *Listener) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	if l.pending != 0 {
		_ = windows.CancelIoEx(l.pending, nil)
	}
}

type Conn struct{ h windows.Handle }

func (c *Conn) ClientPID() (uint32, error) {
	var pid uint32
	err := windows.GetNamedPipeClientProcessId(c.h, &pid)
	return pid, err
}

func (c *Conn) ClientSession() (uint32, error) {
	var s uint32
	r, _, e := procGetClientSession.Call(uintptr(c.h), uintptr(unsafe.Pointer(&s)))
	if r == 0 {
		return 0, e
	}
	return s, nil
}

// Читает одну строку не длиннее MaxLine; длиннее или медленнее timeout — ошибка.
func (c *Conn) ReadLine(timeout time.Duration) (string, error) {
	var line []byte
	done := make(chan struct{})
	tm := time.AfterFunc(timeout, func() {
		select {
		case <-done:
		default:
			_ = windows.CancelIoEx(c.h, nil)
		}
	})
	defer func() { close(done); tm.Stop() }()
	buf := make([]byte, 1)
	for {
		var n uint32
		if err := windows.ReadFile(c.h, buf, &n, nil); err != nil || n == 0 {
			if err == nil {
				err = errors.New("pipe закрыт")
			}
			return "", err
		}
		if buf[0] == '\n' {
			return string(bytes.TrimRight(line, "\r")), nil
		}
		if len(line) >= MaxLine+1 {
			return "", errBadRequest
		}
		line = append(line, buf[0])
	}
}

func (c *Conn) WriteLine(s string) error {
	var n uint32
	return windows.WriteFile(c.h, []byte(s+"\n"), &n, nil)
}

func (c *Conn) Close() {
	_ = windows.FlushFileBuffers(c.h)
	_ = windows.DisconnectNamedPipe(c.h)
	_ = windows.CloseHandle(c.h)
}

// Подключение клиента к pipe; занятый pipe (все экземпляры заняты) — повтор до таймаута.
func Dial(name string, timeout time.Duration) (*Conn, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	end := time.Now().Add(timeout)
	for {
		h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
		if err == nil {
			return &Conn{h: h}, nil
		}
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) || time.Now().After(end) {
			return nil, err
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Call — запрос-ответ одной строкой.
func Call(name, request string, timeout time.Duration) (string, error) {
	c, err := Dial(name, timeout)
	if err != nil {
		return "", err
	}
	defer func() { _ = windows.CloseHandle(c.h) }()
	if err := c.WriteLine(request); err != nil {
		return "", err
	}
	return c.ReadLine(timeout)
}
