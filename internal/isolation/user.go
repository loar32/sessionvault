package isolation

import (
	"crypto/rand"
	"errors"
	"fmt"
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
	return fmt.Errorf("NetUserAdd: код %d (параметр %d)", r, parmErr)
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
		return false, fmt.Errorf("NetUserGetLocalGroups: код %d", r)
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

func SavePassword(password string) error {
	if err := os.WriteFile(passwordFile(), []byte(password), 0o600); err != nil {
		return err
	}
	admins, system, err := adminsAndSystem()
	if err != nil {
		return err
	}
	return Protect(passwordFile(), admins, system)
}

func LoadPassword() (string, error) {
	b, err := os.ReadFile(passwordFile())
	return string(b), err
}

func PasswordSaved() bool {
	_, err := os.Stat(passwordFile())
	return err == nil
}

func adminsAndSystem() (admins, system *windows.SID, err error) {
	if admins, err = windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid); err != nil {
		return
	}
	system, err = windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	return
}
