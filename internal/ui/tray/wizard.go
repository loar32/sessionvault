package tray

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/loar32/sessionvault/internal/i18n"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/ui/checkwin"
	"golang.org/x/sys/windows"
)

// Мастер первой настройки: одно окно с четырьмя шагами. Каждая кнопка запускает то же действие, что и пункт меню трея
// (проверка, защита приложения, Windows Hello, ключ восстановления); окно само ничего не защищает и не хранит секретов.
var (
	pSetTimer      = user32.NewProc("SetTimer")
	pKillTimer     = user32.NewProc("KillTimer")
	pEnableWindow  = user32.NewProc("EnableWindow")
	pSetWindowText = user32.NewProc("SetWindowTextW")
	pSendMessage   = user32.NewProc("SendMessageW")
	pLoadCursor    = user32.NewProc("LoadCursorW")
	pShowWindow    = user32.NewProc("ShowWindow")
	pSysMetrics    = user32.NewProc("GetSystemMetrics")
	pAdjustRect    = user32.NewProc("AdjustWindowRectEx")
	pStockObject   = gdi32.NewProc("GetStockObject")
)

const (
	wmClose      = 0x10
	wmSetFont    = 0x30
	wmTimer      = 0x113
	wmWizState   = 0x410 // WM_USER+16: список защищённых приложений обновился
	wsCaption    = 0x00C00000
	wsSysMenu    = 0x00080000
	wsMinimize   = 0x00020000
	wsChild      = 0x40000000
	wsVisible    = 0x10000000
	wsTabStop    = 0x00010000
	bsPushButton = 0x0
	bsDefPush    = 0x1
	ssLeft       = 0x0
	idcArrow     = 32512
	defaultGUI   = 17
	colorBtnFace = 15
	wizTimerID   = 1
	wizTimerMs   = 3000
	idWCheck     = 2001
	idWHello     = 2002
	idWRecovery  = 2003
	idWClose     = 2004
	idWApp       = 2010 // и далее по одному на приложение
	wizWidth     = 480
)

// Приложения, которые мастер умеет защитить командой protect.
var wizardApps = []string{"telegram", "chrome", "edge", "brave", "discord"}

var (
	wizOpen    atomic.Bool
	wizHwnd    atomic.Uintptr
	wizBtns    []uintptr
	wizStates  []uintptr
	wizNeedApp []uintptr // кнопки, которым нужно хотя бы одно защищённое приложение
	wizDone    atomic.Pointer[[]string]
	wizClass   uintptr
	wizProcCB  = syscall.NewCallback(wizProc)
)

func wizardFlag() string {
	dir := isolation.KnownDir(windows.FOLDERID_LocalAppData, os.Getenv("LOCALAPPDATA"))
	return filepath.Join(dir, "SessionVault", "wizard-shown")
}

// autoWizard показывает мастер один раз за учётку после установки; возвращает true, если показал (проверка защиты в нём
// есть, отдельное окно итога тогда не нужно).
func autoWizard() bool {
	flag := wizardFlag()
	if _, err := os.Stat(flag); err == nil || !os.IsNotExist(err) {
		return false
	}
	if os.MkdirAll(filepath.Dir(flag), 0o700) != nil || os.WriteFile(flag, nil, 0o600) != nil {
		return false
	}
	checkwin.MarkShown()
	go showWizard()
	return true
}

// showWizard открывает окно мастера в своём потоке; второе окно не открывается.
func showWizard() {
	if !wizOpen.CompareAndSwap(false, true) {
		return
	}
	defer wizOpen.Store(false)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	inst, _, _ := pGetModuleHandle.Call(0)
	class := wstr("SessionVaultWizard")
	if wizClass == 0 {
		cur, _, _ := pLoadCursor.Call(0, idcArrow)
		wc := wndClassEx{
			Size:       uint32(unsafe.Sizeof(wndClassEx{})),
			WndProc:    wizProcCB,
			Instance:   inst,
			Cursor:     cur,
			Background: colorBtnFace + 1,
			ClassName:  class,
		}
		if r, _, _ := pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
			return
		}
		wizClass = 1
	}

	const style = wsCaption | wsSysMenu | wsMinimize
	rowH := 30
	height := 150 + len(wizardApps)*rowH + 3*rowH
	type rect struct{ L, T, R, B int32 }
	rc := rect{0, 0, wizWidth, int32(height)}
	_, _, _ = pAdjustRect.Call(uintptr(unsafe.Pointer(&rc)), style, 0, 0)
	sw, _, _ := pSysMetrics.Call(0)
	sh, _, _ := pSysMetrics.Call(1)
	w, h := uintptr(rc.R-rc.L), uintptr(rc.B-rc.T)
	hw, _, _ := pCreateWindowEx.Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(wstr(i18n.T("SessionVault: первая настройка")))),
		style, (sw-w)/2, (sh-h)/3, w, h, 0, 0, inst, 0)
	if hw == 0 {
		return
	}
	wizHwnd.Store(hw)
	font, _, _ := pStockObject.Call(defaultGUI)
	child := func(cls, text string, st uintptr, x, y, cw, ch, id uintptr) uintptr {
		hc, _, _ := pCreateWindowEx.Call(0, uintptr(unsafe.Pointer(wstr(cls))), uintptr(unsafe.Pointer(wstr(text))), wsChild|wsVisible|st, x, y, cw, ch, hw, id, inst, 0)
		_, _, _ = pSendMessage.Call(hc, wmSetFont, font, 1)
		return hc
	}
	label := func(text string, y, ch uintptr) { child("STATIC", text, ssLeft, 16, y, wizWidth-32, ch, 0) }
	rowLabel := func(text string, y uintptr) { child("STATIC", text, ssLeft, 16, y, wizWidth-32-120, 20, 0) }

	label(i18n.T("Защита в четыре шага. Окно можно закрыть и открыть позже из меню значка в трее."), 14, 36)
	y := uintptr(56)
	rowLabel(i18n.T("1. Проверьте, какие меры защиты Windows уже включены:"), y+6)
	child("BUTTON", i18n.T("Проверить"), wsTabStop|bsPushButton, wizWidth-16-110, y, 110, 26, idWCheck)
	y += uintptr(rowH) + 8
	label(i18n.T("2. Защитите приложения (откроется окно с запросом администратора и мастер-пароля):"), y, 32)
	y += 34
	wizBtns, wizStates = wizBtns[:0], wizStates[:0]
	for i, name := range wizardApps {
		wizStates = append(wizStates, child("STATIC", appTitle(name), ssLeft, 32, y+6, 250, 20, 0))
		wizBtns = append(wizBtns, child("BUTTON", i18n.T("Защитить"), wsTabStop|bsPushButton, wizWidth-16-110, y, 110, 26, uintptr(idWApp+i)))
		y += uintptr(rowH)
	}
	y += 6
	rowLabel(i18n.T("3. Вход через Windows Hello вместо ввода пароля:"), y+6)
	hello := child("BUTTON", i18n.T("Включить"), wsTabStop|bsPushButton, wizWidth-16-110, y, 110, 26, idWHello)
	y += uintptr(rowH)
	rowLabel(i18n.T("4. Ключ восстановления (24 слова на бумагу):"), y+6)
	rec := child("BUTTON", i18n.T("Создать"), wsTabStop|bsPushButton, wizWidth-16-110, y, 110, 26, idWRecovery)
	wizNeedApp = []uintptr{hello, rec}
	for _, b := range wizNeedApp {
		_, _, _ = pEnableWindow.Call(b, 0)
	}
	y += uintptr(rowH) + 10
	child("BUTTON", i18n.T("Закрыть"), wsTabStop|bsDefPush, wizWidth-16-110, y, 110, 28, idWClose)

	_, _, _ = pShowWindow.Call(hw, 5)
	_, _, _ = pSetForeground.Call(hw)
	_, _, _ = pSetTimer.Call(hw, wizTimerID, wizTimerMs, 0)
	refreshWizard(hw)

	var m msg
	for {
		r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		if d, _, _ := pIsDialog.Call(hw, uintptr(unsafe.Pointer(&m))); d != 0 {
			continue
		}
		_, _, _ = pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		_, _, _ = pDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
	wizHwnd.Store(0)
}

var pIsDialog = user32.NewProc("IsDialogMessageW")

// Список защищённых приложений спрашивается у службы вне потока окна: ответ может занять до двух секунд.
func refreshWizard(hw uintptr) {
	go func() {
		apps := protectedApps()
		wizDone.Store(&apps)
		_, _, _ = pPostMessage.Call(hw, wmWizState, 0, 0)
	}()
}

func updateWizardRows() {
	done := wizDone.Load()
	if done == nil {
		return
	}
	enableAll := uintptr(0)
	if len(*done) > 0 {
		enableAll = 1
	}
	for _, b := range wizNeedApp {
		_, _, _ = pEnableWindow.Call(b, enableAll)
	}
	for i, name := range wizardApps {
		if i >= len(wizBtns) {
			break
		}
		protected := slices.Contains(*done, name)
		text, enable := i18n.T("Защитить"), uintptr(1)
		title := appTitle(name)
		if protected {
			text, enable = i18n.T("Защищено"), 0
			title += " ✓"
		}
		_, _, _ = pSetWindowText.Call(wizBtns[i], uintptr(unsafe.Pointer(wstr(text))))
		_, _, _ = pEnableWindow.Call(wizBtns[i], enable)
		_, _, _ = pSetWindowText.Call(wizStates[i], uintptr(unsafe.Pointer(wstr(title))))
	}
}

// protectApp открывает консоль администратора: protect спрашивает мастер-пароль и подтверждения, как при ручном запуске.
func protectApp(name string) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	args := `/k ""` + exe + `" protect ` + name + `"`
	_ = windows.ShellExecute(0, windows.StringToUTF16Ptr("runas"), windows.StringToUTF16Ptr("cmd.exe"), windows.StringToUTF16Ptr(args), nil, windows.SW_SHOWNORMAL)
}

func wizProc(h, message, wparam, lparam uintptr) uintptr {
	switch message {
	case wmCommand:
		id := int(wparam & 0xffff)
		switch {
		case id == idWCheck:
			go checkProtection()
		case id >= idWApp && id < idWApp+len(wizardApps):
			protectApp(wizardApps[id-idWApp])
		case id == idWHello:
			go enableHello()
		case id == idWRecovery:
			recoveryKey()
		case id == idWClose:
			_, _, _ = pDestroyWindow.Call(h)
		}
		return 0
	case wmTimer:
		refreshWizard(h)
		return 0
	case wmWizState:
		updateWizardRows()
		return 0
	case wmClose:
		_, _, _ = pDestroyWindow.Call(h)
		return 0
	case wmDestroy:
		_, _, _ = pKillTimer.Call(h, wizTimerID)
		_, _, _ = pPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := pDefWindowProc.Call(h, message, wparam, lparam)
	return r
}
