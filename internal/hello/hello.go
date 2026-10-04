// Package hello получает стабильный секрет от Windows Hello: подпись фиксированного запроса ключом, который
// хранится у пользователя (TPM) и открывается жестом (отпечаток, лицо, PIN). WinRT вызывается напрямую через
// combase.dll, без сторонних библиотек.
package hello

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	combase                = windows.NewLazySystemDLL("combase.dll")
	procRoInitialize       = combase.NewProc("RoInitialize")
	procRoGetFactory       = combase.NewProc("RoGetActivationFactory")
	procWindowsCreateStr   = combase.NewProc("WindowsCreateString")
	procWindowsDeleteStr   = combase.NewProc("WindowsDeleteString")
	user32                 = windows.NewLazySystemDLL("user32.dll")
	procFindWindow         = user32.NewProc("FindWindowW")
	procGetForegroundWnd   = user32.NewProc("GetForegroundWindow")
	procSetForegroundWnd   = user32.NewProc("SetForegroundWindow")
	procShowWindow         = user32.NewProc("ShowWindow")
	procKeybdEvent         = user32.NewProc("keybd_event")
	iidKeyCredentialStatic = windows.GUID{Data1: 0x6aac468b, Data2: 0x0ef1, Data3: 0x4ce0, Data4: [8]byte{0x82, 0x90, 0x41, 0x06, 0xda, 0x6a, 0x63, 0xb5}}
	iidAsyncInfo           = windows.GUID{Data1: 0x00000036, Data2: 0, Data3: 0, Data4: [8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46}}
	iidBufferFactory       = windows.GUID{Data1: 0x71af914d, Data2: 0xc10f, Data3: 0x484b, Data4: [8]byte{0xbc, 0x50, 0x14, 0xbc, 0x62, 0x3b, 0x3a, 0x27}}
	iidBufferByteAccess    = windows.GUID{Data1: 0x905a0fef, Data2: 0xbc53, Data3: 0x11df, Data4: [8]byte{0x8c, 0x49, 0x00, 0x1e, 0x4f, 0xc6, 0x86, 0xda}}
)

// Статусы KeyCredentialStatus.
const (
	statusSuccess    = 0
	statusNotFound   = 2
	statusUserCancel = 3
)

var (
	ErrCancelled    = errors.New("вход через Windows Hello отменён")
	ErrNotSupported = errors.New("не настроен вход Windows Hello на этом компьютере")
	ErrNotFound     = errors.New("ключ Windows Hello не найден")
)

const dialogClass = "Credential Dialog Xaml Host"

// Сколько ждать жеста пользователя. Вызывающий задаёт меньше, чем ждёт сам: по таймауту операция отменяется
// и окно Hello закрывается, а убитый процесс оставил бы окно висеть на экране.
var Timeout = 2 * time.Minute

// com — указатель на COM-объект; методы вызываются по номеру в таблице (0-2 IUnknown, 3-5 IInspectable).
type com struct{ p unsafe.Pointer }

func (c com) call(idx int, args ...uintptr) (uintptr, error) {
	vtbl := *(*unsafe.Pointer)(c.p)
	fn := *(*uintptr)(unsafe.Add(vtbl, idx*int(unsafe.Sizeof(uintptr(0)))))
	r, _, _ := syscall.SyscallN(fn, append([]uintptr{uintptr(c.p)}, args...)...)
	if int32(r) < 0 {
		return r, fmt.Errorf("HRESULT 0x%08X", uint32(r))
	}
	return r, nil
}

func (c com) release() {
	if c.p != nil {
		_, _ = c.call(2)
	}
}

func (c com) query(iid *windows.GUID) (com, error) {
	var out unsafe.Pointer
	if _, err := c.call(0, uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&out))); err != nil {
		return com{}, err
	}
	return com{out}, nil
}

type hstring uintptr

func newHString(s string) (hstring, error) {
	u, err := windows.UTF16FromString(s)
	if err != nil {
		return 0, err
	}
	var h hstring
	r, _, _ := procWindowsCreateStr.Call(uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)-1), uintptr(unsafe.Pointer(&h)))
	if int32(r) < 0 {
		return 0, fmt.Errorf("WindowsCreateString: 0x%08X", uint32(r))
	}
	return h, nil
}

func (h hstring) free() { _, _, _ = procWindowsDeleteStr.Call(uintptr(h)) }

func factory(class string, iid *windows.GUID) (com, error) {
	h, err := newHString(class)
	if err != nil {
		return com{}, err
	}
	defer h.free()
	var out unsafe.Pointer
	r, _, _ := procRoGetFactory.Call(uintptr(h), uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&out)))
	if int32(r) < 0 {
		return com{}, fmt.Errorf("RoGetActivationFactory(%s): 0x%08X", class, uint32(r))
	}
	return com{out}, nil
}

// Диалог Hello, созданный процессом без права на передний план, остаётся мигать в панели задач.
// Пока операция идёт, выводим его вперёд; уже активное окно не трогаем, иначе мы сбивали бы ввод.
func raiseDialog() {
	cls, err := windows.UTF16PtrFromString(dialogClass)
	if err != nil {
		return
	}
	h, _, _ := procFindWindow.Call(uintptr(unsafe.Pointer(cls)), 0)
	if h == 0 {
		return
	}
	if fg, _, _ := procGetForegroundWnd.Call(); fg == h {
		return
	}
	// Нажатие Alt снимает блокировку смены переднего плана.
	_, _, _ = procKeybdEvent.Call(0x12, 0, 0, 0)
	_, _, _ = procKeybdEvent.Call(0x12, 0, 2, 0)
	_, _, _ = procShowWindow.Call(h, 9)
	_, _, _ = procSetForegroundWnd.Call(h)
}

// await ждёт завершения асинхронной операции и вызывает raiseDialog, пока идёт диалог.
func await(op com, timeout time.Duration) error {
	info, err := op.query(&iidAsyncInfo)
	if err != nil {
		return err
	}
	defer info.release()
	deadline := time.Now().Add(timeout)
	for {
		var st int32
		if _, err := info.call(7, uintptr(unsafe.Pointer(&st))); err != nil {
			return err
		}
		switch st {
		case 1:
			return nil
		case 2:
			return ErrCancelled
		case 3:
			var code int32
			_, _ = info.call(8, uintptr(unsafe.Pointer(&code)))
			return fmt.Errorf("операция Hello завершилась ошибкой 0x%08X", uint32(code))
		}
		if time.Now().After(deadline) {
			_, _ = info.call(9) // Cancel
			return errors.New("время ожидания Windows Hello вышло")
		}
		raiseDialog()
		time.Sleep(250 * time.Millisecond)
	}
}

// WinRT-объекты принадлежат потоку: операция начинается и заканчивается в одном закреплённом потоке.
func withRuntime[T any](f func() (T, error)) (T, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var zero T
	// RO_INIT_MULTITHREADED = 1; S_FALSE (уже инициализировано) не ошибка.
	if r, _, _ := procRoInitialize.Call(1); int32(r) < 0 && uint32(r) != 0x80010106 {
		return zero, fmt.Errorf("RoInitialize: 0x%08X", uint32(r))
	}
	return f()
}

func statics() (com, error) {
	return factory("Windows.Security.Credentials.KeyCredentialManager", &iidKeyCredentialStatic)
}

// Supported — Hello настроен (есть PIN, лицо или отпечаток) и доступен ключ.
func Supported() (bool, error) {
	return withRuntime(func() (bool, error) {
		st, err := statics()
		if err != nil {
			return false, err
		}
		defer st.release()
		var op unsafe.Pointer
		if _, err := st.call(6, uintptr(unsafe.Pointer(&op))); err != nil {
			return false, err
		}
		o := com{op}
		defer o.release()
		if err := await(o, 30*time.Second); err != nil {
			return false, err
		}
		var ok byte
		if _, err := o.call(8, uintptr(unsafe.Pointer(&ok))); err != nil {
			return false, err
		}
		return ok != 0, nil
	})
}

func retrievalStatus(op com) (cred com, status int32, err error) {
	if err = await(op, Timeout); err != nil {
		return com{}, 0, err
	}
	var res unsafe.Pointer
	if _, err = op.call(8, uintptr(unsafe.Pointer(&res))); err != nil {
		return com{}, 0, err
	}
	r := com{res}
	defer r.release()
	if _, err = r.call(7, uintptr(unsafe.Pointer(&status))); err != nil {
		return com{}, 0, err
	}
	if status != statusSuccess {
		return com{}, status, nil
	}
	var c unsafe.Pointer
	if _, err = r.call(6, uintptr(unsafe.Pointer(&c))); err != nil {
		return com{}, 0, err
	}
	return com{c}, status, nil
}

func statusError(status int32) error {
	switch status {
	case statusSuccess:
		return nil
	case statusUserCancel:
		return ErrCancelled
	case statusNotFound:
		return ErrNotFound
	case 4:
		return ErrCancelled // UserPrefersPassword
	}
	return fmt.Errorf("статус Windows Hello %d", status)
}

// Create создаёт (или заменяет) ключ Hello с этим именем; пользователь подтверждает жестом.
func Create(name string) error {
	_, err := withRuntime(func() (struct{}, error) {
		st, err := statics()
		if err != nil {
			return struct{}{}, err
		}
		defer st.release()
		h, err := newHString(name)
		if err != nil {
			return struct{}{}, err
		}
		defer h.free()
		var op unsafe.Pointer
		// KeyCredentialCreationOption.ReplaceExisting = 0
		if _, err := st.call(8, uintptr(h), 0, uintptr(unsafe.Pointer(&op))); err != nil {
			return struct{}{}, err
		}
		o := com{op}
		defer o.release()
		cred, status, err := retrievalStatus(o)
		if err != nil {
			return struct{}{}, err
		}
		cred.release()
		return struct{}{}, statusError(status)
	})
	return err
}

// Secret подписывает challenge ключом Hello и возвращает подпись (RSA PKCS#1 v1.5 детерминирована:
// один и тот же challenge даёт одну и ту же подпись). Нужен жест пользователя.
func Secret(name string, challenge []byte) ([]byte, error) {
	return withRuntime(func() ([]byte, error) {
		st, err := statics()
		if err != nil {
			return nil, err
		}
		defer st.release()
		h, err := newHString(name)
		if err != nil {
			return nil, err
		}
		defer h.free()
		var op unsafe.Pointer
		if _, err := st.call(9, uintptr(h), uintptr(unsafe.Pointer(&op))); err != nil {
			return nil, err
		}
		o := com{op}
		defer o.release()
		cred, status, err := retrievalStatus(o)
		if err != nil {
			return nil, err
		}
		if err := statusError(status); err != nil {
			return nil, err
		}
		defer cred.release()

		buf, err := newBuffer(challenge)
		if err != nil {
			return nil, err
		}
		defer buf.release()
		var sop unsafe.Pointer
		if _, err := cred.call(9, uintptr(buf.p), uintptr(unsafe.Pointer(&sop))); err != nil {
			return nil, err
		}
		so := com{sop}
		defer so.release()
		if err := await(so, Timeout); err != nil {
			return nil, err
		}
		var res unsafe.Pointer
		if _, err := so.call(8, uintptr(unsafe.Pointer(&res))); err != nil {
			return nil, err
		}
		r := com{res}
		defer r.release()
		var ss int32
		if _, err := r.call(7, uintptr(unsafe.Pointer(&ss))); err != nil {
			return nil, err
		}
		if err := statusError(ss); err != nil {
			return nil, err
		}
		var out unsafe.Pointer
		if _, err := r.call(6, uintptr(unsafe.Pointer(&out))); err != nil {
			return nil, err
		}
		sig := com{out}
		defer sig.release()
		return readBuffer(sig)
	})
}

// Delete удаляет ключ Hello с этим именем.
func Delete(name string) error {
	_, err := withRuntime(func() (struct{}, error) {
		st, err := statics()
		if err != nil {
			return struct{}{}, err
		}
		defer st.release()
		h, err := newHString(name)
		if err != nil {
			return struct{}{}, err
		}
		defer h.free()
		var op unsafe.Pointer
		if _, err := st.call(10, uintptr(h), uintptr(unsafe.Pointer(&op))); err != nil {
			return struct{}{}, err
		}
		o := com{op}
		defer o.release()
		return struct{}{}, await(o, time.Minute)
	})
	return err
}

func newBuffer(data []byte) (com, error) {
	f, err := factory("Windows.Storage.Streams.Buffer", &iidBufferFactory)
	if err != nil {
		return com{}, err
	}
	defer f.release()
	var b unsafe.Pointer
	if _, err := f.call(6, uintptr(len(data)), uintptr(unsafe.Pointer(&b))); err != nil {
		return com{}, err
	}
	buf := com{b}
	ba, err := buf.query(&iidBufferByteAccess)
	if err != nil {
		buf.release()
		return com{}, err
	}
	defer ba.release()
	var raw unsafe.Pointer
	if _, err := ba.call(3, uintptr(unsafe.Pointer(&raw))); err != nil {
		buf.release()
		return com{}, err
	}
	copy(unsafe.Slice((*byte)(raw), len(data)), data)
	if _, err := buf.call(8, uintptr(len(data))); err != nil { // put_Length
		buf.release()
		return com{}, err
	}
	return buf, nil
}

func readBuffer(buf com) ([]byte, error) {
	var n uint32
	if _, err := buf.call(7, uintptr(unsafe.Pointer(&n))); err != nil { // get_Length
		return nil, err
	}
	ba, err := buf.query(&iidBufferByteAccess)
	if err != nil {
		return nil, err
	}
	defer ba.release()
	var raw unsafe.Pointer
	if _, err := ba.call(3, uintptr(unsafe.Pointer(&raw))); err != nil {
		return nil, err
	}
	out := make([]byte, n)
	copy(out, unsafe.Slice((*byte)(raw), n))
	return out, nil
}

// Exists — ключ Hello с этим именем уже создан (жеста не требуется).
func Exists(name string) (bool, error) {
	return withRuntime(func() (bool, error) {
		st, err := statics()
		if err != nil {
			return false, err
		}
		defer st.release()
		h, err := newHString(name)
		if err != nil {
			return false, err
		}
		defer h.free()
		var op unsafe.Pointer
		if _, err := st.call(9, uintptr(h), uintptr(unsafe.Pointer(&op))); err != nil {
			return false, err
		}
		o := com{op}
		defer o.release()
		cred, status, err := retrievalStatus(o)
		if err != nil {
			return false, err
		}
		cred.release()
		if status == statusNotFound {
			return false, nil
		}
		return true, statusError(status)
	})
}
