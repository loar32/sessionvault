package isolation

import (
	"fmt"
	"github.com/loar32/sessionvault/internal/i18n"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi                    = windows.NewLazySystemDLL("advapi32.dll")
	procLsaOpenPolicy         = advapi.NewProc("LsaOpenPolicy")
	procLsaClose              = advapi.NewProc("LsaClose")
	procLsaAddAccountRights   = advapi.NewProc("LsaAddAccountRights")
	procLsaRemoveAccountRight = advapi.NewProc("LsaRemoveAccountRights")
)

const (
	policyCreateAccount = 0x10
	policyLookupNames   = 0x800
)

// Пароль vault лежит только у SYSTEM, но учётке и незачем входить по сети или через удалённый стол: вход нужен лишь службе локально.
var denyRights = []string{"SeDenyNetworkLogonRight", "SeDenyRemoteInteractiveLogonRight"}

type lsaUnicode struct {
	Length, MaximumLength uint16
	Buffer                *uint16
}

type lsaObjectAttributes struct {
	Length                  uint32
	RootDirectory           windows.Handle
	ObjectName              *lsaUnicode
	Attributes              uint32
	SecurityDescriptor, QoS uintptr
}

func DenyRemoteLogon(user string) error { return changeRights(user, true) }

func AllowRemoteLogon(user string) error { return changeRights(user, false) }

func changeRights(user string, add bool) error {
	sid, _, _, err := windows.LookupSID("", user)
	if err != nil {
		return err
	}
	var attrs lsaObjectAttributes
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var policy windows.Handle
	if st, _, _ := procLsaOpenPolicy.Call(0, uintptr(unsafe.Pointer(&attrs)), policyCreateAccount|policyLookupNames, uintptr(unsafe.Pointer(&policy))); st != 0 {
		return fmt.Errorf(i18n.T("LsaOpenPolicy: статус %#x"), st)
	}
	defer func() { _, _, _ = procLsaClose.Call(uintptr(policy)) }()

	rights := make([]lsaUnicode, len(denyRights))
	for i, name := range denyRights {
		u, err := windows.NewNTUnicodeString(name)
		if err != nil {
			return err
		}
		rights[i] = lsaUnicode{Length: u.Length, MaximumLength: u.MaximumLength, Buffer: u.Buffer}
	}
	var st uintptr
	if add {
		st, _, _ = procLsaAddAccountRights.Call(uintptr(policy), uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&rights[0])), uintptr(len(rights)))
	} else {
		st, _, _ = procLsaRemoveAccountRight.Call(uintptr(policy), uintptr(unsafe.Pointer(sid)), 0, uintptr(unsafe.Pointer(&rights[0])), uintptr(len(rights)))
	}
	if st != 0 {
		return fmt.Errorf(i18n.T("LSA права %s: статус %#x"), user, st)
	}
	return nil
}
