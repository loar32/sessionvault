package isolation

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/sys/windows"
)

// Владелец — Administrators, а не прежний пользователь: владелец всегда может переписать DACL.
func Protect(root string, owner *windows.SID, allow ...*windows.SID) error {
	var paths []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			return nil
		}
		paths = append(paths, p)
		return nil
	})
	if err != nil {
		return err
	}
	// Сначала вложенное, корень последним: после закрытия корня обход невозможен.
	slices.Reverse(paths)
	for _, p := range paths {
		if err := protectOne(p, owner, allow); err != nil {
			return err
		}
	}
	return nil
}

func protectOne(path string, owner *windows.SID, allow []*windows.SID) error {
	var entries []windows.EXPLICIT_ACCESS
	for _, sid := range allow {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, acl, nil)
}

func EnablePrivileges(names ...string) error {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return err
	}
	defer func() { _ = token.Close() }()
	for _, n := range names {
		var luid windows.LUID
		if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(n), &luid); err != nil {
			return err
		}
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
		if err := windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil); err != nil {
			return err
		}
	}
	return nil
}

func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// SetupVaultDir создаёт папку хранения: полный доступ у vault, SYSTEM и Administrators, остальным — ничего.
func SetupVaultDir() error {
	if err := os.MkdirAll(VaultDir(), 0o755); err != nil {
		return err
	}
	return ProtectDir(VaultDir())
}

// Метаданные хранилища: vault не должен их ни читать, ни менять (иначе приложение откатит или подменит data.enc).
func ProtectDir(root string) error {
	admins, system, err := adminsAndSystem()
	if err != nil {
		return err
	}
	return Protect(root, admins, system, admins)
}

// Рабочая папка приложения: его учётка пишет и читает всё, но не запускает файлы и не меняет права; запуск разрешён только
// файлам, которые одобрил allowExec (им даются лишь чтение и запуск). Другие приложения доступа не имеют.
// Вызывается, пока приложение не запущено.
func ProtectWork(root, account string, allowExec func(path string) bool) error {
	vault, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return err
	}
	admins, system, err := adminsAndSystem()
	if err != nil {
		return err
	}
	return protectNoExec(root, allowExec, vault, []*windows.SID{system, admins}, nil, admins)
}
