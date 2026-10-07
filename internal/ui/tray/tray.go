// Иконка в трее: цвет показывает состояние хранилища, меню запускает защищённые приложения через pipe службы.
package tray

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/loar32/sessionvault/internal/checkup"
	"github.com/loar32/sessionvault/internal/fido"
	"github.com/loar32/sessionvault/internal/hello"
	"github.com/loar32/sessionvault/internal/ipc"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"github.com/loar32/sessionvault/internal/ui/checkwin"
	"golang.org/x/sys/windows"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	pRegisterClassEx  = user32.NewProc("RegisterClassExW")
	pCreateWindowEx   = user32.NewProc("CreateWindowExW")
	pDefWindowProc    = user32.NewProc("DefWindowProcW")
	pGetMessage       = user32.NewProc("GetMessageW")
	pTranslateMessage = user32.NewProc("TranslateMessage")
	pDispatchMessage  = user32.NewProc("DispatchMessageW")
	pPostQuitMessage  = user32.NewProc("PostQuitMessage")
	pPostMessage      = user32.NewProc("PostMessageW")
	pCreatePopupMenu  = user32.NewProc("CreatePopupMenu")
	pAppendMenu       = user32.NewProc("AppendMenuW")
	pTrackPopupMenu   = user32.NewProc("TrackPopupMenu")
	pDestroyMenu      = user32.NewProc("DestroyMenu")
	pGetCursorPos     = user32.NewProc("GetCursorPos")
	pSetForeground    = user32.NewProc("SetForegroundWindow")
	pCreateIconInd    = user32.NewProc("CreateIconIndirect")
	pRegisterMessage  = user32.NewProc("RegisterWindowMessageW")
	pDestroyWindow    = user32.NewProc("DestroyWindow")
	pNotifyIcon       = shell32.NewProc("Shell_NotifyIconW")
	pCreateBitmap     = gdi32.NewProc("CreateBitmap")
	pDeleteObject     = gdi32.NewProc("DeleteObject")
	pGetModuleHandle  = kernel32.NewProc("GetModuleHandleW")
	pCreateMutex      = kernel32.NewProc("CreateMutexW")
)

const (
	wmDestroy     = 0x2
	wmCommand     = 0x111
	wmLButtonUp   = 0x202
	wmRButtonUp   = 0x205
	wmNull        = 0x0
	wmCallback    = 0x401 // WM_USER+1: события иконки
	wmState       = 0x402 // WM_USER+2: новое состояние хранилища из опроса
	wmBalloon     = 0x403 // WM_USER+3: показать сообщение об ошибке запуска
	nifMessage    = 0x1
	nifIcon       = 0x2
	nifTip        = 0x4
	nifInfo       = 0x10
	nimAdd        = 0
	nimModify     = 1
	nimDelete     = 2
	mfString      = 0x0
	mfSeparator   = 0x800
	mfGrayed      = 0x1
	tpmRightBtn   = 0x2
	tpmBottomAlgn = 0x20
	idRun         = 1001 // и далее по одному на приложение; меньше idExit не бывает: приложений не больше maxMenuApps
	maxMenuApps   = 16
	idHello       = 1050
	idRecovery    = 1051
	idFido        = 1052
	idClose       = 1020 // и далее по одному на запущенное приложение (до 1035)
	idCheck       = 1060
	idExchange    = 1061
	idExit        = 1100
	pollEvery     = 2 * time.Second  // частый опрос: после действия пользователя, чтобы иконка не отставала
	pollIdle      = 10 * time.Second // обычный опрос в простое
	pollFastFor   = time.Minute
	iconSize      = 32
)

// Состояния иконки.
const (
	stateDown     = iota // служба недоступна
	stateLocked          // ключи не в памяти: защищено
	stateUnlocked        // ключи в памяти службы
	stateAlarm           // недавно прочитана приманка
)

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

type iconInfo struct {
	IsIcon   uint32
	XHotspot uint32
	YHotspot uint32
	Mask     uintptr
	Color    uintptr
}

type notifyIcon struct {
	Size            uint32
	Hwnd            uintptr
	ID              uint32
	Flags           uint32
	CallbackMessage uint32
	Icon            uintptr
	Tip             [128]uint16
	State           uint32
	StateMask       uint32
	Info            [256]uint16
	Version         uint32
	InfoTitle       [64]uint16
	InfoFlags       uint32
	Guid            [16]byte
	BalloonIcon     uintptr
}

var (
	hwnd        uintptr
	icons       [4]uintptr
	state       = stateDown
	taskbarMsg  uintptr
	menuApps    []string
	menuRunning []string
	stateTitles = [4]string{"SessionVault: служба недоступна", "SessionVault: заблокировано", "SessionVault: открыто", "SessionVault: ТРЕВОГА, прочитана приманка"}
)

func wstr(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

func copyUTF16(dst []uint16, s string) {
	u, _ := windows.UTF16FromString(s)
	copy(dst, u)
	dst[len(dst)-1] = 0
}

// Run — цикл окна трея; возвращается при выборе «Выход».
func Run() error {
	// Окно принадлежит потоку ОС, на котором создано: без привязки рантайм Go может перенести горутину на другой поток,
	// и цикл сообщений перестанет получать сообщения окна (оно зависает: «Not Responding»).
	runtime.LockOSThread()
	name := wstr(`Local\SessionVaultTray`)
	m, _, e := pCreateMutex.Call(0, 0, uintptr(unsafe.Pointer(name)))
	if m == 0 {
		return e
	}
	if errors.Is(e, windows.ERROR_ALREADY_EXISTS) {
		return errors.New("трей уже запущен")
	}
	for i, c := range [4]uint32{0xff8a8a8a, 0xff2e9e4f, 0xffe08a1e, 0xffd62b2b} { // серый, зелёный, оранжевый, красный
		icons[i] = makeIcon(c)
	}
	taskbarMsg, _, _ = pRegisterMessage.Call(uintptr(unsafe.Pointer(wstr("TaskbarCreated"))))

	inst, _, _ := pGetModuleHandle.Call(0)
	class := wstr("SessionVaultTray")
	wc := wndClassEx{
		Size:      uint32(unsafe.Sizeof(wndClassEx{})),
		WndProc:   syscall.NewCallback(wndProc),
		Instance:  inst,
		ClassName: class,
	}
	if r, _, e := pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return e
	}
	h, _, e := pCreateWindowEx.Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(wstr("SessionVault"))), 0, 0, 0, 0, 0, 0, 0, inst, 0)
	if h == 0 {
		return e
	}
	hwnd = h
	notify(nimAdd, "")
	go poll()

	var mm msg
	for {
		r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&mm)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		_, _, _ = pTranslateMessage.Call(uintptr(unsafe.Pointer(&mm)))
		_, _, _ = pDispatchMessage.Call(uintptr(unsafe.Pointer(&mm)))
	}
	return nil
}

// Круг нужного цвета с мягким краем: 32x32 BGRA без внешних файлов-иконок.
func makeIcon(argb uint32) uintptr {
	px := make([]byte, iconSize*iconSize*4)
	r, g, b := byte(argb>>16), byte(argb>>8), byte(argb)
	for y := range iconSize {
		for x := range iconSize {
			dx, dy := float64(x)-15.5, float64(y)-15.5
			d := dx*dx + dy*dy
			var a float64
			switch {
			case d <= 12*12:
				a = 1
			case d <= 14*14:
				a = (14*14 - d) / (14*14 - 12*12)
			}
			i := (y*iconSize + x) * 4
			// Цвет с предумноженной прозрачностью, как требует 32-битная иконка.
			px[i], px[i+1], px[i+2], px[i+3] = byte(float64(b)*a), byte(float64(g)*a), byte(float64(r)*a), byte(a*255)
		}
	}
	color, _, _ := pCreateBitmap.Call(iconSize, iconSize, 1, 32, uintptr(unsafe.Pointer(&px[0])))
	mask := make([]byte, iconSize*iconSize/8)
	mbm, _, _ := pCreateBitmap.Call(iconSize, iconSize, 1, 1, uintptr(unsafe.Pointer(&mask[0])))
	ii := iconInfo{IsIcon: 1, Mask: mbm, Color: color}
	h, _, _ := pCreateIconInd.Call(uintptr(unsafe.Pointer(&ii)))
	_, _, _ = pDeleteObject.Call(color)
	_, _, _ = pDeleteObject.Call(mbm)
	return h
}

func notify(op uintptr, balloon string) {
	n := notifyIcon{Size: uint32(unsafe.Sizeof(notifyIcon{})), Hwnd: hwnd, ID: 1,
		Flags: nifMessage | nifIcon | nifTip, CallbackMessage: wmCallback, Icon: icons[state]}
	copyUTF16(n.Tip[:], stateTitles[state])
	if balloon != "" {
		n.Flags |= nifInfo
		copyUTF16(n.InfoTitle[:], "SessionVault")
		copyUTF16(n.Info[:], balloon)
	}
	_, _, _ = pNotifyIcon.Call(op, uintptr(unsafe.Pointer(&n)))
}

var (
	fastUntil atomic.Int64
	wake      = make(chan struct{}, 1)
)

// После запуска или ввода пароля состояние меняется быстро: минуту опрашиваем чаще, в остальное время службу не дёргаем.
func speedUp() {
	fastUntil.Store(time.Now().Add(pollFastFor).UnixNano())
	select {
	case wake <- struct{}{}:
	default:
	}
}

func poll() {
	autoChecked := false
	for {
		s := stateDown
		switch resp, err := ipc.Call(ipc.CommandPipe, "status", pollEvery); {
		case err != nil:
		case resp == ipc.Locked:
			s = stateLocked
		case resp == ipc.Unlocked:
			s = stateUnlocked
		case resp == ipc.Alarm:
			s = stateAlarm
		}
		_, _, _ = pPostMessage.Call(hwnd, wmState, uintptr(s), 0)
		if s != stateDown {
			refreshApps()
		}
		// Первый ответ службы после запуска трея: окно проверки при красных пунктах, один раз за учётку.
		if s != stateDown && !autoChecked {
			autoChecked = true
			go checkwin.AutoCheck()
		}
		delay := pollIdle
		if time.Now().UnixNano() < fastUntil.Load() {
			delay = pollEvery
		}
		select {
		case <-time.After(delay):
		case <-wake:
		}
	}
}

var runMessages = map[string]string{
	ipc.Busy:   "Уже идёт запуск или ввод пароля",
	ipc.Failed: "Не удалось запустить приложение",
}

var checking atomic.Bool

// Разные причины требуют разных действий: остановленную службу запускают, занятой дают время.
func serviceItem(err error) checkup.Item {
	it := checkup.Item{Title: "Служба SessionVault", Level: checkup.Bad, Detail: "не отвечает (занята)", Hint: "Повторите через минуту"}
	switch {
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
		it.Detail, it.Hint = "остановлена", "Запустите службу SessionVault (services.msc) или перезагрузите компьютер"
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		it.Detail, it.Hint = "нет доступа", "Запускать трей нужно из основной учётки, для которой установлена защита"
	}
	return it
}

// Проверка идёт до 15 с, поэтому в отдельной горутине; повторный клик за это время ничего не запускает.
func checkProtection() {
	if !checking.CompareAndSwap(false, true) {
		return
	}
	defer checking.Store(false)
	r, err := checkwin.Fetch()
	if err != nil {
		r = checkup.Report{Overall: checkup.Bad, Items: []checkup.Item{serviceItem(err)}}
	}
	checkwin.Show(r)
}

func runApp(profile string) {
	speedUp()
	defer speedUp()
	resp, err := ipc.Call(ipc.CommandPipe, "run "+profile, 3*time.Minute)
	text := runMessages[resp]
	if err != nil {
		text = "Служба SessionVault недоступна"
	}
	if text != "" {
		code := 1
		if err != nil {
			code = 2
		} else if resp == ipc.Busy {
			code = 3
		}
		_, _, _ = pPostMessage.Call(hwnd, wmBalloon, uintptr(code), 0)
	}
}

// Ключу восстановления нужны права администратора (он пишет в закрытую папку хранилищ): окно консоли открывается через UAC
// и остаётся на экране, пока пользователь не запишет слова.
func recoveryKey() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	args := `/k ""` + exe + `" recovery create"`
	_ = windows.ShellExecute(0, windows.StringToUTF16Ptr("runas"), windows.StringToUTF16Ptr("cmd.exe"), windows.StringToUTF16Ptr(args), nil, windows.SW_SHOWNORMAL)
}

// Для каждого защищённого приложения служба спрашивает мастер-пароль, затем ключ FIDO2 создаёт учётные данные:
// Windows просит PIN ключа и касание (для создания и для первого получения секрета).
func enableFido() {
	speedUp()
	defer speedUp()
	if !fido.Supported() {
		_, _, _ = pPostMessage.Call(hwnd, wmBalloon, 8, 0)
		return
	}
	code := uintptr(7)
	for _, name := range protectedApps() {
		resp, err := ipc.Call(ipc.CommandPipe, "fido "+name, 6*time.Minute)
		if err != nil {
			code = 2
			break
		}
		if resp != ipc.Ok {
			code = 8
			if resp == ipc.Busy {
				code = 3
			}
			break
		}
	}
	_, _, _ = pPostMessage.Call(hwnd, wmBalloon, code, 0)
}

// Для каждого защищённого приложения служба спрашивает мастер-пароль, затем Windows Hello создаёт ключ и подтверждает вход.
func enableHello() {
	speedUp()
	defer speedUp()
	// Проверка без жеста и до вопроса про мастер-пароль: без настроенного Hello пароль вводить незачем.
	if ok, _ := hello.Supported(); !ok {
		_, _, _ = pPostMessage.Call(hwnd, wmBalloon, 6, 0)
		return
	}
	code := uintptr(4)
	for _, name := range protectedApps() {
		resp, err := ipc.Call(ipc.CommandPipe, "hello "+name, 4*time.Minute)
		if err != nil {
			code = 2
			break
		}
		if resp != ipc.Ok {
			code = 5
			if resp == ipc.Busy {
				code = 3
			}
		}
	}
	_, _, _ = pPostMessage.Call(hwnd, wmBalloon, code, 0)
}

var titles = map[string]string{"telegram": "Telegram", "chrome": "Google Chrome", "edge": "Microsoft Edge", "brave": "Brave", "discord": "Discord"}

func appTitle(name string) string {
	if t, ok := titles[name]; ok {
		return t
	}
	return name
}

// Приложения с хранилищем спрашиваем у службы: у обычной учётки нет доступа к её папкам.
func protectedApps() []string { return askNames("list") }

func askNames(cmd string) []string {
	resp, err := ipc.Call(ipc.CommandPipe, cmd, 2*time.Second)
	if err != nil || resp == "" {
		return nil
	}
	var apps []string
	for _, n := range strings.Split(resp, ",") {
		if profiles.ValidName(n) && len(apps) < maxMenuApps {
			apps = append(apps, n)
		}
	}
	return apps
}

// Меню открывается из потока окна: запрос к службе прямо там подвесил бы интерфейс до двух секунд, поэтому списки
// приложений обновляет опрос состояния, а меню берёт последние.
var (
	appsMu        sync.Mutex
	cachedApps    []string
	cachedRunning []string
)

func refreshApps() {
	apps, running := protectedApps(), askNames("running")
	appsMu.Lock()
	cachedApps, cachedRunning = apps, running
	appsMu.Unlock()
}

func closeApp(profile string) {
	speedUp()
	defer speedUp()
	if resp, err := ipc.Call(ipc.CommandPipe, "close "+profile, 15*time.Second); err != nil || resp != ipc.Ok {
		_, _, _ = pPostMessage.Call(hwnd, wmBalloon, 9, 0)
	}
}

func showMenu() {
	menu, _, _ := pCreatePopupMenu.Call()
	defer func() { _, _, _ = pDestroyMenu.Call(menu) }()
	_, _, _ = pAppendMenu.Call(menu, mfString|mfGrayed, 0, uintptr(unsafe.Pointer(wstr(stateTitles[state]))))
	_, _, _ = pAppendMenu.Call(menu, mfSeparator, 0, 0)
	appsMu.Lock()
	menuApps, menuRunning = cachedApps, cachedRunning
	appsMu.Unlock()
	if len(menuApps) == 0 {
		_, _, _ = pAppendMenu.Call(menu, mfString|mfGrayed, 0, uintptr(unsafe.Pointer(wstr("Нет защищённых приложений"))))
	}
	for i, name := range menuApps {
		_, _, _ = pAppendMenu.Call(menu, mfString, uintptr(idRun+i), uintptr(unsafe.Pointer(wstr("Запустить "+appTitle(name)))))
	}
	for i, name := range menuRunning {
		_, _, _ = pAppendMenu.Call(menu, mfString, uintptr(idClose+i), uintptr(unsafe.Pointer(wstr("Закрыть "+appTitle(name)+" и зашифровать данные"))))
	}
	_, _, _ = pAppendMenu.Call(menu, mfSeparator, 0, 0)
	if len(menuApps) > 0 {
		_, _, _ = pAppendMenu.Call(menu, mfString, idHello, uintptr(unsafe.Pointer(wstr("Включить вход через Windows Hello"))))
		_, _, _ = pAppendMenu.Call(menu, mfString, idFido, uintptr(unsafe.Pointer(wstr("Включить вход по ключу FIDO2 (YubiKey)"))))
		_, _, _ = pAppendMenu.Call(menu, mfString, idRecovery, uintptr(unsafe.Pointer(wstr("Создать ключ восстановления…"))))
	}
	_, _, _ = pAppendMenu.Call(menu, mfString, idExchange, uintptr(unsafe.Pointer(wstr("Папка обмена с защищёнными приложениями"))))
	checkLabel, checkFlags := "Проверить защиту", uintptr(mfString)
	if checking.Load() {
		checkLabel, checkFlags = "Проверка защиты…", mfString|mfGrayed
	}
	_, _, _ = pAppendMenu.Call(menu, checkFlags, idCheck, uintptr(unsafe.Pointer(wstr(checkLabel))))
	_, _, _ = pAppendMenu.Call(menu, mfString, idExit, uintptr(unsafe.Pointer(wstr("Выход"))))
	var p point
	_, _, _ = pGetCursorPos.Call(uintptr(unsafe.Pointer(&p)))
	// Без переднего плана меню не закрывается кликом вне него.
	_, _, _ = pSetForeground.Call(hwnd)
	_, _, _ = pTrackPopupMenu.Call(menu, tpmRightBtn|tpmBottomAlgn, uintptr(p.X), uintptr(p.Y), 0, hwnd, 0)
	_, _, _ = pPostMessage.Call(hwnd, wmNull, 0, 0)
}

func wndProc(h, message, wparam, lparam uintptr) uintptr {
	switch message {
	case wmCallback:
		if lparam == wmLButtonUp || lparam == wmRButtonUp {
			showMenu()
		}
		return 0
	case wmState:
		if int(wparam) != state {
			state = int(wparam)
			notify(nimModify, "")
		}
		return 0
	case wmBalloon:
		texts := map[uintptr]string{1: runMessages[ipc.Failed], 2: "Служба SessionVault недоступна", 3: runMessages[ipc.Busy],
			4: "Вход через Windows Hello включён", 5: "Не удалось включить Windows Hello",
			6: "Windows Hello не настроен: добавьте PIN, лицо или отпечаток в Параметрах Windows",
			7: "Вход по ключу FIDO2 включён", 8: "Не удалось включить вход по ключу FIDO2: нужны Windows 11, ключ с hmac-secret и PIN ключа",
			9: "Не удалось закрыть приложение"}
		notify(nimModify, texts[wparam])
		return 0
	case wmCommand:
		id := int(wparam & 0xffff)
		switch {
		case id >= idRun && id < idRun+maxMenuApps:
			// Список строится при открытии меню; команду могли послать и без него.
			apps := menuApps
			if len(apps) == 0 {
				apps = protectedApps()
			}
			if i := id - idRun; i < len(apps) {
				go runApp(apps[i])
			}
		case id >= idClose && id < idClose+maxMenuApps:
			if i := id - idClose; i < len(menuRunning) {
				go closeApp(menuRunning[i])
			}
		case id == idHello:
			go enableHello()
		case id == idFido:
			go enableFido()
		case id == idRecovery:
			recoveryKey()
		case id == idCheck:
			go checkProtection()
		case id == idExchange:
			_ = windows.ShellExecute(0, windows.StringToUTF16Ptr("open"), windows.StringToUTF16Ptr(isolation.ExchangeDir()), nil, nil, windows.SW_SHOWNORMAL)
		case id == idExit:
			_, _, _ = pDestroyWindow.Call(h)
		}
		return 0
	case wmDestroy:
		notify(nimDelete, "")
		_, _, _ = pPostQuitMessage.Call(0)
		return 0
	}
	if message == taskbarMsg {
		notify(nimAdd, "")
		return 0
	}
	r, _, _ := pDefWindowProc.Call(h, message, wparam, lparam)
	return r
}
