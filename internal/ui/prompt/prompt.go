// Окно ввода мастер-пароля. Запускается службой от SYSTEM в сессии пользователя и отдаёт пароль
// по закрытому для обычных учёток pipe; процессы пользователя не могут ни читать это окно, ни подменить его (UIPI).
package prompt

import (
	"errors"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/ipc"
	"golang.org/x/sys/windows"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")

	pRegisterClassEx  = user32.NewProc("RegisterClassExW")
	pCreateWindowEx   = user32.NewProc("CreateWindowExW")
	pDefWindowProc    = user32.NewProc("DefWindowProcW")
	pGetMessage       = user32.NewProc("GetMessageW")
	pIsDialogMessage  = user32.NewProc("IsDialogMessageW")
	pTranslateMessage = user32.NewProc("TranslateMessage")
	pDispatchMessage  = user32.NewProc("DispatchMessageW")
	pPostQuitMessage  = user32.NewProc("PostQuitMessage")
	pShowWindow       = user32.NewProc("ShowWindow")
	pSetForeground    = user32.NewProc("SetForegroundWindow")
	pSetFocus         = user32.NewProc("SetFocus")
	pGetWindowText    = user32.NewProc("GetWindowTextW")
	pGetWindowTextLen = user32.NewProc("GetWindowTextLengthW")
	pSetWindowText    = user32.NewProc("SetWindowTextW")
	pSendMessage      = user32.NewProc("SendMessageW")
	pLoadCursor       = user32.NewProc("LoadCursorW")
	pGetSystemMetrics = user32.NewProc("GetSystemMetrics")
	pDestroyWindow    = user32.NewProc("DestroyWindow")
	pKeybdEvent       = user32.NewProc("keybd_event")
	pAdjustWindowRect = user32.NewProc("AdjustWindowRectEx")
	pSetWindowPos     = user32.NewProc("SetWindowPos")
	pGetModuleHandle  = kernel32.NewProc("GetModuleHandleW")
	pGetThreadID      = kernel32.NewProc("GetCurrentThreadId")
	pGetForeground    = user32.NewProc("GetForegroundWindow")
	pGetWindowThread  = user32.NewProc("GetWindowThreadProcessId")
	pAttachThread     = user32.NewProc("AttachThreadInput")
	pBringToTop       = user32.NewProc("BringWindowToTop")
	pGetWindowRect    = user32.NewProc("GetWindowRect")
	pSetCursorPos     = user32.NewProc("SetCursorPos")
	pMouseEvent       = user32.NewProc("mouse_event")
	pGetStockObject   = gdi32.NewProc("GetStockObject")
)

const (
	wsCaption     = 0x00C00000
	wsSysMenu     = 0x00080000
	wsChild       = 0x40000000
	wsVisible     = 0x10000000
	wsTabStop     = 0x00010000
	wsBorder      = 0x00800000
	esPassword    = 0x20
	esAutoHScrl   = 0x80
	bsDefPush     = 0x1
	wsExTopmost   = 0x8
	wmDestroy     = 0x2
	wmClose       = 0x10
	wmSetFont     = 0x30
	wmCommand     = 0x111
	idOK          = 1
	idCancel      = 2
	idEdit        = 100
	idStatus      = 101
	swShow        = 5
	idcArrow      = 32512
	defaultGUI    = 17
	colorWindow   = 5
	vkMenu        = 0x12
	keyUp         = 0x2
	mouseLeftDown = 0x2
	mouseLeftUp   = 0x4
	swpNoMove     = 0x2
	swpNoSize     = 0x1
	smCxScreen    = 0
	smCyScreen    = 1
	winWidth      = 360
	winHeight     = 150

	dialTimeout = 10 * time.Second
)

const (
	emSetLimitText = 0xC5
	// Ключ восстановления (24 слова BIP-39) занимает до 215 символов; пароль длиннее ipc.MaxPassword в байтах отклоняется в submit.
	maxPasswordChars = 220
)

var hwndTopmost = ^uintptr(0)

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

type point struct{ X, Y int32 }

type msg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

type rect struct{ Left, Top, Right, Bottom int32 }

var (
	conn   *ipc.Conn
	edit   uintptr
	status uintptr
	result error
)

func wstr(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

// Run показывает окно и отправляет введённый пароль службе; возвращается, когда пароль принят или окно закрыто.
func Run(profile, pipe string) error {
	// Окно принадлежит потоку ОС, на котором создано: без привязки рантайм Go может перенести горутину на другой поток,
	// и цикл сообщений перестанет получать сообщения окна (оно зависает: «Not Responding»).
	runtime.LockOSThread()
	c, err := ipc.Dial(pipe, dialTimeout)
	if err != nil {
		return err
	}
	conn = c
	defer conn.Close()
	result = errors.New("окно закрыто без ввода пароля")

	inst, _, _ := pGetModuleHandle.Call(0)
	cur, _, _ := pLoadCursor.Call(0, idcArrow)
	class := wstr("SessionVaultPrompt")
	wc := wndClassEx{
		Size:       uint32(unsafe.Sizeof(wndClassEx{})),
		WndProc:    syscall.NewCallback(wndProc),
		Instance:   inst,
		Cursor:     cur,
		Background: colorWindow + 1,
		ClassName:  class,
	}
	if r, _, e := pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return e
	}

	const style = wsCaption | wsSysMenu
	rc := rect{0, 0, winWidth, winHeight}
	_, _, _ = pAdjustWindowRect.Call(uintptr(unsafe.Pointer(&rc)), style, 0, wsExTopmost)
	sw, _, _ := pGetSystemMetrics.Call(smCxScreen)
	sh, _, _ := pGetSystemMetrics.Call(smCyScreen)
	w, h := uintptr(rc.Right-rc.Left), uintptr(rc.Bottom-rc.Top)
	hwnd, _, e := pCreateWindowEx.Call(wsExTopmost, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(wstr("SessionVault"))), style, (sw-w)/2, (sh-h)/3, w, h, 0, 0, inst, 0)
	if hwnd == 0 {
		return e
	}
	font, _, _ := pGetStockObject.Call(defaultGUI)
	child := func(cls, text string, st uintptr, x, y, cw, ch, id uintptr) uintptr {
		hc, _, _ := pCreateWindowEx.Call(0, uintptr(unsafe.Pointer(wstr(cls))), uintptr(unsafe.Pointer(wstr(text))), wsChild|wsVisible|st, x, y, cw, ch, hwnd, id, inst, 0)
		_, _, _ = pSendMessage.Call(hc, wmSetFont, font, 1)
		return hc
	}
	child("STATIC", "Пароль или ключ восстановления, «"+profile+"»:", 0, 16, 14, 320, 20, 0)
	edit = child("EDIT", "", wsTabStop|wsBorder|esPassword|esAutoHScrl, 16, 36, 320, 24, idEdit)
	_, _, _ = pSendMessage.Call(edit, emSetLimitText, maxPasswordChars, 0)
	status = child("STATIC", "", 0, 16, 66, 320, 20, idStatus)
	child("BUTTON", "OK", wsTabStop|bsDefPush, 176, 92, 76, 28, idOK)
	child("BUTTON", "Отмена", wsTabStop, 260, 92, 76, 28, idCancel)

	_, _, _ = pShowWindow.Call(hwnd, swShow)
	_, _, _ = pSetWindowPos.Call(hwnd, hwndTopmost, 0, 0, 0, 0, swpNoMove|swpNoSize)
	focus(hwnd)

	var m msg
	for {
		r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		if d, _, _ := pIsDialogMessage.Call(hwnd, uintptr(unsafe.Pointer(&m))); d != 0 {
			continue
		}
		_, _, _ = pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		_, _, _ = pDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
	return result
}

// Процесс запущен службой, а не пользователем, и система не отдаёт ему передний план просто так:
// присоединяемся к потоку текущего окна переднего плана и «нажимаем» Alt.
func focus(hwnd uintptr) {
	fg, _, _ := pGetForeground.Call()
	fgThread, _, _ := pGetWindowThread.Call(fg, 0)
	me, _, _ := pGetThreadID.Call()
	if fgThread != 0 && fgThread != me {
		_, _, _ = pAttachThread.Call(me, fgThread, 1)
		defer func() { _, _, _ = pAttachThread.Call(me, fgThread, 0) }()
	}
	_, _, _ = pKeybdEvent.Call(vkMenu, 0, 0, 0)
	_, _, _ = pBringToTop.Call(hwnd)
	_, _, _ = pSetForeground.Call(hwnd)
	_, _, _ = pKeybdEvent.Call(vkMenu, 0, keyUp, 0)
	_, _, _ = pSetFocus.Call(edit)
	if now, _, _ := pGetForeground.Call(); now != hwnd {
		click(hwnd)
	}
}

// Если система не отдала передний план, активируем окно как это сделал бы пользователь: кликом по нему.
// Активация по вводу не подпадает под ограничения SetForegroundWindow.
func click(hwnd uintptr) {
	var rc rect
	_, _, _ = pGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
	x, y := uintptr(rc.Left+(rc.Right-rc.Left)/2), uintptr(rc.Top+(rc.Bottom-rc.Top)/2)
	_, _, _ = pSetCursorPos.Call(x, y)
	_, _, _ = pMouseEvent.Call(mouseLeftDown, 0, 0, 0, 0)
	_, _, _ = pMouseEvent.Call(mouseLeftUp, 0, 0, 0, 0)
	_, _, _ = pSetFocus.Call(edit)
}

func wndProc(hwnd, message, wparam, lparam uintptr) uintptr {
	switch message {
	case wmCommand:
		switch wparam & 0xffff {
		case idOK:
			submit(hwnd)
			return 0
		case idCancel:
			_, _, _ = pDestroyWindow.Call(hwnd)
			return 0
		}
	case wmClose:
		_, _, _ = pDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		_, _, _ = pPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := pDefWindowProc.Call(hwnd, message, wparam, lparam)
	return r
}

func submit(hwnd uintptr) {
	n, _, _ := pGetWindowTextLen.Call(edit)
	if n == 0 {
		return
	}
	buf := make([]uint16, n+1)
	_, _, _ = pGetWindowText.Call(edit, uintptr(unsafe.Pointer(&buf[0])), n+1)
	pw := []byte(windows.UTF16ToString(buf))
	clear(buf)
	if len(pw) > ipc.MaxPassword {
		crypto.Wipe(pw)
		setStatus("Слишком длинный пароль")
		return
	}
	_, _, _ = pSetWindowText.Call(edit, uintptr(unsafe.Pointer(wstr(""))))
	setStatus("Проверка…")
	err := conn.WriteLine(string(pw))
	crypto.Wipe(pw)
	reply := ""
	if err == nil {
		reply, err = conn.ReadLine(30*time.Second, ipc.MaxLine)
	}
	_, _, _ = pSetFocus.Call(edit)
	switch {
	case err != nil:
		result = err
		_, _, _ = pDestroyWindow.Call(hwnd)
	case reply == ipc.Ok:
		result = nil
		_, _, _ = pDestroyWindow.Call(hwnd)
	default:
		setStatus("Неверный пароль, попробуйте ещё раз")
	}
}

func setStatus(s string) { _, _, _ = pSetWindowText.Call(status, uintptr(unsafe.Pointer(wstr(s)))) }
