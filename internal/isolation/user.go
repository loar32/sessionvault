package isolation

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/loar32/sessionvault/internal/i18n"
	"math/big"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	userPrivUser       = 1
	ufScript           = 0x0001
	ufPasswdCantChange = 0x0040
	ufDontExpirePasswd = 0x10000
	nerrUserExists     = 2224
	passwordLen        = 40
	passwordAlphabet   = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#%^*-_=+"
)

var ErrUserExists = errors.New("учётка уже существует")

var (
	netapi32             = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserAdd       = netapi32.NewProc("NetUserAdd")
	procNetUserGetGroups = netapi32.NewProc("NetUserGetLocalGroups")
	procNetUserDel       = netapi32.NewProc("NetUserDel")
)

type userInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

func GeneratePassword() (string, error) {
	out := make([]byte, passwordLen)
	max := big.NewInt(int64(len(passwordAlphabet)))
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = passwordAlphabet[n.Int64()]
	}
	return string(out), nil
}

func CreateUser(name, password string) error {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return err
	}
	info := userInfo1{
		Name:     n,
		Password: p,
		Priv:     userPrivUser,
		Flags:    ufScript | ufPasswdCantChange | ufDontExpirePasswd,
	}
	var parmErr uint32
	r, _, _ := procNetUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parmErr)))
	switch r {
	case 0:
		return nil
	case nerrUserExists:
		return ErrUserExists
	}
	return fmt.Errorf(i18n.T("NetUserAdd: код %d (параметр %d)"), r, parmErr)
}

func DeleteUser(name string) error {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	if r, _, _ := procNetUserDel.Call(0, uintptr(unsafe.Pointer(n))); r != 0 {
		return fmt.Errorf(i18n.T("NetUserDel: код %d"), r)
	}
	return nil
}

func HideFromLogon(name string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	return k.SetDWordValue(name, 0)
}

func UserExists(name string) bool {
	sid, _, _, err := windows.LookupSID("", name)
	return err == nil && sid != nil
}

// Состоит ли учётка в группе администраторов (в том числе через вложенные группы).
func IsAdminUser(name string) (bool, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, err
	}
	var buf *byte
	var read, total uint32
	const lgIncludeIndirect = 1
	r, _, _ := procNetUserGetGroups.Call(0, uintptr(unsafe.Pointer(n)), 0, lgIncludeIndirect,
		uintptr(unsafe.Pointer(&buf)), 0xFFFFFFFF, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)))
	if r != 0 {
		return false, fmt.Errorf(i18n.T("NetUserGetLocalGroups: код %d"), r)
	}
	defer func() { _ = windows.NetApiBufferFree(buf) }()

	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, err
	}
	groups := unsafe.Slice((**uint16)(unsafe.Pointer(buf)), read)
	for _, g := range groups {
		sid, _, _, err := windows.LookupSID("", windows.UTF16PtrToString(g))
		if err == nil && windows.EqualSid(sid, admins) {
			return true, nil
		}
	}
	return false, nil
}

// RemoveLegacyPassword удаляет пароль общей учётки vault, оставшийся от версий до v0.19.
func RemoveLegacyPassword() { _ = os.Remove(legacyPasswordFile()) }

func adminsAndSystem() (admins, system *windows.SID, err error) {
	if admins, err = windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid); err != nil {
		return
	}
	system, err = windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	return
}
