package isolation

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procWTSQueryUserToken     = windows.NewLazySystemDLL("wtsapi32.dll").NewProc("WTSQueryUserToken")
	procImpersonateLoggedOnUs = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf          = windows.NewLazySystemDLL("advapi32.dll").NewProc("RevertToSelf")
)

// ErrNoUser — пользователь сейчас не вошёл на консоль.
var ErrNoUser = errors.New("основная учётка не вошла в систему")

// UserToken возвращает токен учётки sid, если она вошла на консоль. Нужна привилегия SeTcb (у службы SYSTEM она есть).
func UserToken(sid *windows.SID) (windows.Token, error) {
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xFFFFFFFF {
		return 0, ErrNoUser
	}
	var tok windows.Token
	if r, _, e := procWTSQueryUserToken.Call(uintptr(session), uintptr(unsafe.Pointer(&tok))); r == 0 {
		return 0, e
	}
	u, err := tok.GetTokenUser()
	if err != nil || !windows.EqualSid(u.User.Sid, sid) {
		_ = tok.Close()
		return 0, ErrNoUser
	}
	return tok, nil
}

// AsUser выполняет fn с правами пользователя: файловые операции по путям из его профиля, которые подменой ссылки
// могли бы увести SYSTEM в чужое место, при этом не могут сделать ничего, чего пользователь не может сам.
func AsUser(tok windows.Token, fn func() error) error {
	runtime.LockOSThread()
	if r, _, e := procImpersonateLoggedOnUs.Call(uintptr(tok)); r == 0 {
		runtime.UnlockOSThread()
		return e
	}
	defer func() {
		if r, _, _ := procRevertToSelf.Call(); r != 0 {
			runtime.UnlockOSThread()
		}
		// Не вернулись к своей личности: поток не отдаём обратно, он завершится вместе с горутиной.
	}()
	return fn()
}
