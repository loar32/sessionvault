package isolation

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procLogonUser         = windows.NewLazySystemDLL("advapi32.dll").NewProc("LogonUserW")
	procLoadUserProfile   = windows.NewLazySystemDLL("userenv.dll").NewProc("LoadUserProfileW")
	procUnloadUserProfile = windows.NewLazySystemDLL("userenv.dll").NewProc("UnloadUserProfile")
	procOpenWindowStation = windows.NewLazySystemDLL("user32.dll").NewProc("OpenWindowStationW")
	procOpenDesktop       = windows.NewLazySystemDLL("user32.dll").NewProc("OpenDesktopW")
	procCloseWindowStn    = windows.NewLazySystemDLL("user32.dll").NewProc("CloseWindowStation")
	procCloseDesktop      = windows.NewLazySystemDLL("user32.dll").NewProc("CloseDesktop")
)

const (
	logon32LogonInteractive = 2
	logon32ProviderDefault  = 0
	piNoUI                  = 1
)

type profileInfo struct {
	Size        uint32
	Flags       uint32
	UserName    *uint16
	ProfilePath *uint16
	DefaultPath *uint16
	ServerName  *uint16
	PolicyPath  *uint16
	Profile     windows.Handle
}

// StartInSession запускает процесс от SYSTEM в сессии пользователя: так служба (сессия 0) показывает окно на его рабочем столе.
// Токен берётся от самой службы, поэтому процесс получает права SYSTEM.
func StartInSession(session uint32, cmdline string, suspended bool) (pid uint32, process, thread windows.Handle, err error) {
	var cur windows.Token
	if err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &cur); err != nil {
		return
	}
	defer func() { _ = cur.Close() }()
	var tok windows.Token
	if err = windows.DuplicateTokenEx(cur, windows.MAXIMUM_ALLOWED, nil, windows.SecurityIdentification, windows.TokenPrimary, &tok); err != nil {
		return
	}
	defer func() { _ = tok.Close() }()
	if err = windows.SetTokenInformation(tok, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), 4); err != nil {
		return
	}
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT)
	if suspended {
		flags |= windows.CREATE_SUSPENDED
	}
	return createAsUser(tok, cmdline, "", flags)
}

func createAsUser(tok windows.Token, cmdline, workDir string, flags uint32) (pid uint32, process, thread windows.Handle, err error) {
	var env *uint16
	if err = windows.CreateEnvironmentBlock(&env, tok, false); err != nil {
		return
	}
	defer func() { _ = windows.DestroyEnvironmentBlock(env) }()
	cl, err := windows.UTF16PtrFromString(cmdline)
	if err != nil {
		return
	}
	var wd *uint16
	if workDir != "" {
		if wd, err = windows.UTF16PtrFromString(workDir); err != nil {
			return
		}
	}
	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: desktop}
	var pi windows.ProcessInformation
	if err = windows.CreateProcessAsUser(tok, nil, cl, nil, nil, false, flags|windows.CREATE_UNICODE_ENVIRONMENT, env, wd, &si, &pi); err != nil {
		return
	}
	if flags&windows.CREATE_SUSPENDED == 0 {
		_ = windows.CloseHandle(pi.Thread)
		pi.Thread = 0
	}
	return pi.ProcessId, pi.Process, pi.Thread, nil
}

// LaunchAsVault вызывается из процесса SYSTEM, уже работающего в сессии пользователя:
// CreateProcessWithLogonW из LocalSystem недоступна, поэтому вход и права на рабочий стол оформляем сами.
// Возвращает функцию, которую нужно вызвать после выхода приложения: она выгружает профиль и закрывает вход.
// Невыгруженный профиль остаётся загруженным в реестре и мешает удалить учётку vault.
func LaunchAsVault(user, password, cmdline, workDir string) (pid uint32, process windows.Handle, cleanup func(), err error) {
	u, err := windows.UTF16PtrFromString(user)
	if err != nil {
		return
	}
	dom, _ := windows.UTF16PtrFromString(".")
	pw, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return
	}
	var tok windows.Token
	r, _, e := procLogonUser.Call(uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(dom)), uintptr(unsafe.Pointer(pw)),
		logon32LogonInteractive, logon32ProviderDefault, uintptr(unsafe.Pointer(&tok)))
	if r == 0 {
		return 0, 0, nil, e
	}
	sid, err := logonSID(tok)
	if err != nil {
		_ = tok.Close()
		return
	}
	if err = setDesktopAccess(sid, windows.GRANT_ACCESS); err != nil {
		_ = tok.Close()
		return
	}
	if err = setNamedObjectAccess(sid, windows.GRANT_ACCESS); err != nil {
		_ = setDesktopAccess(sid, windows.REVOKE_ACCESS)
		_ = tok.Close()
		return
	}
	// Без загруженного профиля у приложения нет HKCU.
	pi := profileInfo{Size: uint32(unsafe.Sizeof(profileInfo{})), Flags: piNoUI, UserName: u}
	if r, _, e := procLoadUserProfile.Call(uintptr(tok), uintptr(unsafe.Pointer(&pi))); r == 0 {
		_ = setNamedObjectAccess(sid, windows.REVOKE_ACCESS)
		_ = setDesktopAccess(sid, windows.REVOKE_ACCESS)
		_ = tok.Close()
		return 0, 0, nil, e
	}
	cleanup = func() {
		_, _, _ = procUnloadUserProfile.Call(uintptr(tok), uintptr(pi.Profile))
		_ = setNamedObjectAccess(sid, windows.REVOKE_ACCESS)
		_ = setDesktopAccess(sid, windows.REVOKE_ACCESS)
		_ = tok.Close()
	}
	if pid, process, _, err = createAsUser(tok, cmdline, workDir, 0); err != nil {
		cleanup()
		return 0, 0, nil, err
	}
	return
}

func logonSID(tok windows.Token) (*windows.SID, error) {
	var n uint32
	_ = windows.GetTokenInformation(tok, windows.TokenLogonSid, nil, 0, &n)
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, windows.TokenLogonSid, &buf[0], n, &n); err != nil {
		return nil, err
	}
	return (*windows.Tokengroups)(unsafe.Pointer(&buf[0])).Groups[0].Sid.Copy()
}

// Рабочий стол пользователя закрыт для чужих учёток: без ACE для logon-SID процесс vault не стартует (0xC0000142).
// После выхода приложения ACE снимается: logon-SID у каждого входа свой, и старые копились бы до конца сеанса пользователя.
func setDesktopAccess(sid *windows.SID, mode windows.ACCESS_MODE) error {
	name, _ := windows.UTF16PtrFromString("WinSta0")
	const access = windows.READ_CONTROL | windows.WRITE_DAC
	h, _, e := procOpenWindowStation.Call(uintptr(unsafe.Pointer(name)), 0, access)
	if h == 0 {
		return e
	}
	defer func() { _, _, _ = procCloseWindowStn.Call(h) }()
	if err := editObjectACL(windows.Handle(h), windows.SE_WINDOW_OBJECT, sid, mode, windows.GENERIC_ALL); err != nil {
		return err
	}
	dname, _ := windows.UTF16PtrFromString("Default")
	d, _, e := procOpenDesktop.Call(uintptr(unsafe.Pointer(dname)), 0, 0, access)
	if d == 0 {
		return e
	}
	defer func() { _, _, _ = procCloseDesktop.Call(d) }()
	return editObjectACL(windows.Handle(d), windows.SE_WINDOW_OBJECT, sid, mode, windows.GENERIC_ALL)
}

func editObjectACL(h windows.Handle, typ windows.SE_OBJECT_TYPE, sid *windows.SID, mode windows.ACCESS_MODE, access uint32) error {
	sd, err := windows.GetSecurityInfo(h, typ, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	old, _, err := sd.DACL()
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.ACCESS_MASK(access),
		AccessMode:        mode,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, old)
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(h, typ, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

var (
	procQuerySession = windows.NewLazySystemDLL("wtsapi32.dll").NewProc("WTSQuerySessionInformationW")
	procWTSFree      = windows.NewLazySystemDLL("wtsapi32.dll").NewProc("WTSFreeMemory")
)

const wtsUserName = 5

// Имя пользователя, вошедшего на консоль: установщик защищает именно его.
func ConsoleUser() (string, error) {
	session := windows.WTSGetActiveConsoleSessionId()
	var buf *uint16
	var n uint32
	r, _, e := procQuerySession.Call(0, uintptr(session), wtsUserName, uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return "", e
	}
	defer func() { _, _, _ = procWTSFree.Call(uintptr(unsafe.Pointer(buf))) }()
	return windows.UTF16PtrToString(buf), nil
}

// sessionUserToken — первичный токен пользователя, вошедшего в сессию. Запрашивать его может только SYSTEM.
func sessionUserToken(session uint32) (windows.Token, error) {
	var imp windows.Token
	if err := windows.WTSQueryUserToken(session, &imp); err != nil {
		return 0, err
	}
	defer func() { _ = imp.Close() }()
	var tok windows.Token
	if err := windows.DuplicateTokenEx(imp, windows.MAXIMUM_ALLOWED, nil, windows.SecurityIdentification, windows.TokenPrimary, &tok); err != nil {
		return 0, err
	}
	return tok, nil
}

// SessionUserSID — SID пользователя сессии (строкой для SDDL).
func SessionUserSID(session uint32) (string, error) {
	tok, err := sessionUserToken(session)
	if err != nil {
		return "", err
	}
	defer func() { _ = tok.Close() }()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

// StartAsSessionUser запускает процесс от имени пользователя сессии: ключ Windows Hello принадлежит ему, а не SYSTEM.
func StartAsSessionUser(session uint32, cmdline string) (pid uint32, process windows.Handle, err error) {
	tok, err := sessionUserToken(session)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tok.Close() }()
	pid, process, _, err = createAsUser(tok, cmdline, "", 0)
	return
}
