package isolation

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"

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

// Файл из белого списка vault может только читать и запускать: переписать его и подсунуть свой код нельзя.
const execOnlyRights = 0x1200A9

// noExecACL — доступ vault к папке и вложенному: каталогам без смены прав, файлам ещё и без запуска (кроме файла из
// белого списка, fileExec). Если указан extra, он получает полный доступ, кроме смены прав и владельца.
func noExecACL(isDir, fileExec bool, vault *windows.SID, full []*windows.SID, extra *windows.SID) (*windows.ACL, error) {
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
	if fileExec && !isDir {
		vaultFiles = execOnlyRights
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

// protectNoExec обходит папку и выставляет каждому объекту защищённый DACL. allowExec решает, какому существующему
// файлу разрешён запуск (nil — никому); новые файлы запуска не получают. Ссылки и junction пропускаются: SYSTEM не
// должен менять права по чужому указателю.
func protectNoExec(root string, allowExec func(path string) bool, vault *windows.SID, full []*windows.SID, extra *windows.SID, owner *windows.SID) error {
	return protectTree(root, allowExec, vault, full, extra, owner, false)
}

// protectTree — то же; с tolerant файл, права которого сменить не удалось (например, загруженный куст NTUSER.DAT),
// пропускается, а не обрывает обход.
func protectTree(root string, allowExec func(path string) bool, vault *windows.SID, full []*windows.SID, extra *windows.SID, owner *windows.SID, tolerant bool) error {
	type item struct {
		path      string
		dir, exec bool
	}
	var items []item
	// Файл, которому разрешён запуск, держится открытым без права записи и удаления от проверки до выдачи прав:
	// иначе его можно было бы подменить между проверкой подписи и выдачей права на запуск.
	var pins []windows.Handle
	defer func() {
		for _, h := range pins {
			_ = windows.CloseHandle(h)
		}
	}()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if tolerant && d != nil {
				return nil
			}
			return err
		}
		if d.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			return nil
		}
		exec := false
		if !d.IsDir() && allowExec != nil {
			if h, err := pinFile(p); err == nil {
				pins = append(pins, h)
				exec = allowExec(p)
			}
		}
		items = append(items, item{p, d.IsDir(), exec})
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
		if err != nil && !tolerant {
			return err
		}
	}
	return nil
}

// ExchangeDir — общая папка: основная учётка и приложения обмениваются файлами, запустить файл отсюда может только основная.
func ExchangeDir() string { return filepath.Join(BaseDir(), "exchange") }

// SetupExchange создаёт общую папку. Основная учётка читает и пишет, но не меняет права; приложения (группа SessionVaultApps) — так же и без запуска.
func SetupExchange(mainUser string) error {
	user, _, _, err := windows.LookupSID("", mainUser)
	if err != nil {
		return err
	}
	vault, err := EnsureAppsGroup()
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

// CleanExchangeLinks убирает из общей папки ссылки и junction: приложение могло оставить их, чтобы пользователь или
// другое приложение, открыв папку, ушло по ссылке в чужое место. Удаляется сама ссылка, цель не затрагивается.
func CleanExchangeLinks() (removed int) {
	_ = filepath.WalkDir(ExchangeDir(), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			if os.Remove(p) == nil {
				removed++
			}
			if d.IsDir() {
				return fs.SkipDir
			}
		}
		return nil
	})
	return removed
}

// lockProfile закрывает запуск файлов и смену прав в профиле самой учётки приложения (Temp, Downloads и т. п.): иначе
// взломанное приложение сохранило бы там exe и запустило его. Профиль не нужен приложению для запуска кода: данные и
// кэш лежат в рабочей папке. Защита дополнительная: сбой не мешает запуску.
func lockProfile(tok windows.Token) {
	if EnablePrivileges("SeRestorePrivilege", "SeTakeOwnershipPrivilege") != nil {
		return
	}
	dir, err := tok.GetUserProfileDirectory()
	if err != nil {
		return
	}
	u, err := tok.GetTokenUser()
	if err != nil {
		return
	}
	admins, system, err := adminsAndSystem()
	if err != nil {
		return
	}
	_ = protectTree(dir, nil, u.User.Sid, []*windows.SID{system, admins}, nil, admins, true)
}
