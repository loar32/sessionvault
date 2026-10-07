package isolation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// У каждого защищённого приложения своя учётка Windows (sv-<имя>): взломанное приложение не читает данные соседа.
// Общие правила (общая папка, запрет интерпретаторов, брандмауэр) выдаются группе SessionVaultApps, в которую входят все такие учётки.
const (
	AppsGroup     = "SessionVaultApps"
	AccountPrefix = "sv-"
	maxAccountLen = 20 // предел имени учётки Windows
	hashedNameLen = 8  // сколько символов имени остаётся в сокращённой учётке
)

// AccountName — имя учётки приложения: sv-<имя>, а если оно длиннее 20 символов, то sv-<8 символов>-<6 символов хэша>.
func AccountName(profile string) string {
	n := AccountPrefix + profile
	if len(n) <= maxAccountLen {
		return n
	}
	h := sha256.Sum256([]byte(profile))
	return AccountPrefix + profile[:hashedNameLen] + "-" + hex.EncodeToString(h[:3])
}

const (
	errAliasExists   = 1379 // ERROR_ALIAS_EXISTS
	errMemberInAlias = 1378 // ERROR_MEMBER_IN_ALIAS
)

var (
	procNetLocalGroupAdd        = netapi32.NewProc("NetLocalGroupAdd")
	procNetLocalGroupDel        = netapi32.NewProc("NetLocalGroupDel")
	procNetLocalGroupAddMembers = netapi32.NewProc("NetLocalGroupAddMembers")
)

type localGroupInfo1 struct {
	Name    *uint16
	Comment *uint16
}

type localGroupMember3 struct{ DomainAndName *uint16 }

// EnsureAppsGroup создаёт группу приложений, если её нет, и возвращает её SID.
func EnsureAppsGroup() (*windows.SID, error) {
	n, err := windows.UTF16PtrFromString(AppsGroup)
	if err != nil {
		return nil, err
	}
	c, _ := windows.UTF16PtrFromString("Учётки защищённых приложений SessionVault")
	info := localGroupInfo1{Name: n, Comment: c}
	var parm uint32
	r, _, _ := procNetLocalGroupAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parm)))
	if r != 0 && r != errAliasExists {
		return nil, fmt.Errorf("NetLocalGroupAdd: код %d", r)
	}
	sid, _, _, err := windows.LookupSID("", AppsGroup)
	return sid, err
}

// AppsGroupSID — SID группы приложений; ошибка, если группы нет.
func AppsGroupSID() (*windows.SID, error) {
	sid, _, _, err := windows.LookupSID("", AppsGroup)
	return sid, err
}

func DeleteAppsGroup() error {
	n, err := windows.UTF16PtrFromString(AppsGroup)
	if err != nil {
		return err
	}
	if r, _, _ := procNetLocalGroupDel.Call(0, uintptr(unsafe.Pointer(n))); r != 0 {
		return fmt.Errorf("NetLocalGroupDel: код %d", r)
	}
	return nil
}

func addToAppsGroup(account string) error {
	host, err := windows.ComputerName()
	if err != nil {
		return err
	}
	g, err := windows.UTF16PtrFromString(AppsGroup)
	if err != nil {
		return err
	}
	m, err := windows.UTF16PtrFromString(host + `\` + account)
	if err != nil {
		return err
	}
	member := localGroupMember3{DomainAndName: m}
	r, _, _ := procNetLocalGroupAddMembers.Call(0, uintptr(unsafe.Pointer(g)), 3, uintptr(unsafe.Pointer(&member)), 1)
	if r != 0 && r != errMemberInAlias {
		return fmt.Errorf("NetLocalGroupAddMembers: код %d", r)
	}
	return nil
}

func accountsFile() string { return filepath.Join(BaseDir(), "accounts.json") }

// Читать, менять и записывать файл паролей можно только под accountsMu: два приложения запускаются одновременно,
// и без блокировки одно затёрло бы запись другого (учётка осталась бы без пароля и была бы пересоздана).
var accountsMu sync.Mutex

func loadAccounts() (map[string]string, error) {
	m := map[string]string{}
	b, err := os.ReadFile(accountsFile())
	if os.IsNotExist(err) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	for k, v := range m {
		pw, err := openPassword(v)
		if err != nil {
			return nil, fmt.Errorf("пароль учётки %s: %w", k, err)
		}
		m[k] = pw
	}
	return m, nil
}

// saveAccounts пишет временный файл с правами только для SYSTEM и администраторов и переименовывает его: сбой посреди записи
// не оставит обрезанный файл, из-за которого пропали бы все пароли.
func saveAccounts(m map[string]string) error {
	sealed := make(map[string]string, len(m))
	for k, v := range m {
		s, err := sealPassword(v)
		if err != nil {
			return fmt.Errorf("пароль учётки %s не зашифрован: %w", k, err)
		}
		sealed[k] = s
	}
	b, err := json.Marshal(sealed)
	if err != nil {
		return err
	}
	tmp := accountsFile() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	admins, system, err := adminsAndSystem()
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := Protect(tmp, admins, system); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, accountsFile())
}

// LoadAccountPassword — пароль учётки приложения (его читает только служба и помощник запуска от SYSTEM).
func LoadAccountPassword(account string) (string, error) {
	accountsMu.Lock()
	defer accountsMu.Unlock()
	m, err := loadAccounts()
	if err != nil {
		return "", err
	}
	pw, ok := m[account]
	if !ok {
		return "", fmt.Errorf("пароль учётки %s не сохранён", account)
	}
	return pw, nil
}

// AccountNames — учётки приложений, о которых знает SessionVault.
func AccountNames() []string {
	accountsMu.Lock()
	defer accountsMu.Unlock()
	m, _ := loadAccounts()
	out := make([]string, 0, len(m))
	for n := range m {
		out = append(out, n)
	}
	return out
}

// EnsureAppAccount создаёт учётку приложения (скрытую на экране входа, без удалённого входа, в группе приложений), если её нет.
// Учётка без сохранённого пароля пересоздаётся: пароль всё равно известен только нам, а профиль у неё пустой.
func EnsureAppAccount(profile string) (string, error) {
	account := AccountName(profile)
	if _, err := EnsureAppsGroup(); err != nil {
		return "", err
	}
	accountsMu.Lock()
	defer accountsMu.Unlock()
	m, err := loadAccounts()
	if err != nil {
		return "", err
	}
	if _, known := m[account]; known && UserExists(account) {
		return account, addToAppsGroup(account)
	}
	if UserExists(account) {
		_ = AllowRemoteLogon(account)
		_ = DeleteUserProfile(account)
		if err := DeleteUser(account); err != nil {
			return "", fmt.Errorf("%s: старая учётка без пароля не удалена: %w", account, err)
		}
	}
	pw, err := GeneratePassword()
	if err != nil {
		return "", err
	}
	if err := CreateUser(account, pw); err != nil {
		return "", err
	}
	// Любой сбой настройки откатывает учётку целиком: иначе при следующем запуске она сочлась бы готовой, оставшись видимой
	// на экране входа или с удалённым входом.
	rollback := func(err error) (string, error) {
		_ = DeleteUser(account)
		delete(m, account)
		_ = saveAccounts(m)
		return "", err
	}
	m[account] = pw
	if err := saveAccounts(m); err != nil {
		return rollback(err)
	}
	if err := HideFromLogon(account); err != nil {
		return rollback(err)
	}
	if err := DenyRemoteLogon(account); err != nil {
		return rollback(err)
	}
	if err := addToAppsGroup(account); err != nil {
		return rollback(err)
	}
	return account, nil
}

// DeleteAppAccount удаляет учётку приложения, её профиль и сохранённый пароль.
func DeleteAppAccount(account string) error {
	accountsMu.Lock()
	defer accountsMu.Unlock()
	var errs []error
	if UserExists(account) {
		_ = AllowRemoteLogon(account)
		_ = DeleteUserProfile(account)
		if err := DeleteUser(account); err != nil {
			errs = append(errs, err)
		}
		_ = os.RemoveAll(filepath.Join(usersRoot(), account)) // если штатное удаление профиля не справилось
		_ = unhideFromLogon(account)
	}
	if m, err := loadAccounts(); err == nil {
		delete(m, account)
		if err := saveAccounts(m); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func unhideFromLogon(name string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList`, registry.SET_VALUE)
	if err != nil {
		return nil
	}
	defer func() { _ = k.Close() }()
	return k.DeleteValue(name)
}

func usersRoot() string { return KnownDir(windows.FOLDERID_UserProfiles, `C:\Users`) }

// IsAppAccount — SID принадлежит учётке защищённого приложения: имя sv-* и запись в списке учёток, которые создала программа.
// Одного префикса мало: обычная учётка, названная sv-что-то, не должна считаться своей.
func IsAppAccount(sid *windows.SID) bool {
	name, _, _, err := sid.LookupAccount("")
	if err != nil || !strings.HasPrefix(strings.ToLower(name), AccountPrefix) {
		return false
	}
	for _, n := range AccountNames() {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}
