package isolation

import (
	"io/fs"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procDeleteProfile = windows.NewLazySystemDLL("userenv.dll").NewProc("DeleteProfileW")
	procInitializeAcl = windows.NewLazySystemDLL("advapi32.dll").NewProc("InitializeAcl")
)

const aclRevision = 2

// Пустой (но не NULL) список доступа: NULL означал бы «разрешено всем» и не включает наследование.
func emptyACL() (*windows.ACL, error) {
	buf := make([]byte, 8)
	acl := (*windows.ACL)(unsafe.Pointer(&buf[0]))
	if r, _, e := procInitializeAcl.Call(uintptr(unsafe.Pointer(acl)), uintptr(len(buf)), aclRevision); r == 0 {
		return nil, e
	}
	return acl, nil
}

// Возврат файлов пользователю: он становится владельцем, а права снова наследуются от родительской папки
// (пустой DACL вместе с UNPROTECTED сбрасывает явные права и включает наследование).
func GiveToUser(root string, user *windows.SID) error {
	empty, err := emptyACL()
	if err != nil {
		return err
	}
	return filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
			user, nil, empty, nil)
	})
}

// Профиль vault (папка в C:\Users и ветка реестра) появляется при первом входе этой учётки; при удалении убираем и его.
func DeleteUserProfile(name string) error {
	sid, _, _, err := windows.LookupSID("", name)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(sid.String())
	if err != nil {
		return err
	}
	if r, _, e := procDeleteProfile.Call(uintptr(unsafe.Pointer(p)), 0, 0); r == 0 {
		return e
	}
	return nil
}
