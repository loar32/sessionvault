package isolation

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/windows"
)

// У vault есть всё, кроме запуска файлов, смены прав и смены владельца: иначе вредоносный код в приложении
// сохранил бы exe, дал бы себе право его запускать и запустил.
const (
	fileAllAccess = 0x1F01FF
	dirRights     = fileAllAccess &^ (windows.WRITE_DAC | windows.WRITE_OWNER)
	fileRights    = dirRights &^ windows.FILE_EXECUTE
)

// Владелец файла по умолчанию может менять его права. Файлы, созданные vault, принадлежат vault: ACE «Права владельца»
// оставляет владельцу только чтение прав.
func ownerRightsSID() (*windows.SID, error) { return windows.StringToSid("S-1-3-4") }

func entry(sid *windows.SID, rights uint32, inherit uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.ACCESS_MASK(rights),
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inherit,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

const (
	inheritAll   = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	inheritFiles = windows.OBJECT_INHERIT_ACE | windows.INHERIT_ONLY_ACE
)

// noExecACL — доступ vault к папке и вложенному: каталогам без смены прав, файлам ещё и без запуска (или с запуском,
// если папка в белом списке). Если указан extra, он получает полный доступ, кроме смены прав и владельца.
func noExecACL(isDir, allowExec bool, vault *windows.SID, full []*windows.SID, extra *windows.SID) (*windows.ACL, error) {
	owner, err := ownerRightsSID()
	if err != nil {
		return nil, err
	}
	var es []windows.EXPLICIT_ACCESS
	for _, sid := range full {
		es = append(es, entry(sid, windows.GENERIC_ALL, inheritAll))
	}
	es = append(es, entry(owner, windows.READ_CONTROL, inheritAll))
	vaultFiles := uint32(fileRights)
	if allowExec {
		vaultFiles = dirRights
	}
	add := func(sid *windows.SID, files uint32) {
		if isDir {
			es = append(es, entry(sid, dirRights, windows.CONTAINER_INHERIT_ACE), entry(sid, files, inheritFiles))
		} else {
			es = append(es, entry(sid, files, windows.NO_INHERITANCE))
		}
	}
	add(vault, vaultFiles)
	if extra != nil {
		add(extra, dirRights)
	}
	return windows.ACLFromEntries(es, nil)
}

// protectNoExec обходит папку и выставляет каждому объекту защищённый DACL. execDirs — папки (относительно root),
// где запуск файлов разрешён; ссылки и junction пропускаются: SYSTEM не должен менять права по чужому указателю.
func protectNoExec(root string, execDirs []string, vault *windows.SID, full []*windows.SID, extra *windows.SID, owner *windows.SID) error {
	type item struct {
		path      string
		dir, exec bool
	}
	var items []item
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			return nil
		}
		items = append(items, item{p, d.IsDir(), inExecDir(root, p, execDirs)})
		return nil
	})
	if err != nil {
		return err
	}
	// Сначала вложенное, корень последним: после закрытия корня обход невозможен.
	slices.Reverse(items)
	for _, it := range items {
		acl, err := noExecACL(it.dir, it.exec, vault, full, extra)
		if err != nil {
			return err
		}
		err = windows.SetNamedSecurityInfo(it.path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			owner, nil, acl, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

func inExecDir(root, path string, execDirs []string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	for _, d := range execDirs {
		if rel == d || strings.HasPrefix(rel, d+`\`) {
			return true
		}
	}
	return false
}

// ExchangeDir — общая папка: основная учётка и vault обмениваются файлами, запустить файл отсюда может только основная.
func ExchangeDir() string { return filepath.Join(BaseDir(), "exchange") }

// SetupExchange создаёт общую папку. Основная учётка читает и пишет, но не меняет права; vault — так же и без запуска.
func SetupExchange(mainUser string) error {
	user, _, _, err := windows.LookupSID("", mainUser)
	if err != nil {
		return err
	}
	vault, _, _, err := windows.LookupSID("", VaultUser)
	if err != nil {
		return err
	}
	admins, system, err := adminsAndSystem()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(ExchangeDir(), 0o755); err != nil {
		return err
	}
	return protectNoExec(ExchangeDir(), nil, vault, []*windows.SID{system, admins}, user, admins)
}
