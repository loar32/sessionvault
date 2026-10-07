// Package lockdown закрывает защищённым приложениям лазейки через системные утилиты: взломанное приложение работает под
// учёткой vault и могло бы вынести данные через PowerShell, curl и подобное. Два слоя: правила брандмауэра (исходящая
// сеть этих утилит для vault и вся сеть самого SessionVault) и запрет запуска скриптовых интерпретаторов для vault (ACL на exe).
package lockdown

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Все правила брандмауэра SessionVault лежат в одной группе: так их находят и удаляют разом.
const Group = "SessionVault"

const fileExecute = 0x20 // FILE_EXECUTE

// Интерпретаторы: vault не может запустить их вообще (ACL) и, на случай сброса прав обновлением Windows, не может выйти ими в сеть.
var interpreters = []string{
	`WindowsPowerShell\v1.0\powershell.exe`,
	`WindowsPowerShell\v1.0\powershell_ise.exe`,
	`wscript.exe`,
	`cscript.exe`,
	`mshta.exe`,
	// Выполняют код из файла проекта или командной строки, а сеть у них не закрыта правилами по имени: запрещаем запуск.
	`wbem\WMIC.exe`,
	`cmstp.exe`,
	`pcalua.exe`,
	`scriptrunner.exe`,
	`wsl.exe`,
	`bash.exe`,
	// Запуск команд по шаблону, закрепление в планировщике и копирование файлов в обход прав: приложению ничего из этого не нужно.
	`forfiles.exe`,
	`schtasks.exe`,
	`at.exe`,
	`esentutl.exe`,
	`expand.exe`,
	`makecab.exe`,
	`extrac32.exe`,
}

// Интерпретаторы, которые ставит сам пользователь: путь зависит от версии, поэтому по маске (`*` в профиле — все пользователи).
var userInterpreters = []string{
	`Python*\python*.exe`,
	`nodejs\node.exe`,
	`Git\bin\bash.exe`,
	`Git\usr\bin\bash.exe`,
	`Git\usr\bin\perl.exe`,
}

func userInterpreterRoots() []string {
	pf, pf86, sd := os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("SystemDrive")
	if sd == "" {
		sd = "C:"
	}
	return []string{pf, pf86, sd + `\`, sd + `\Users\*\AppData\Local\Programs`}
}

// Компиляторы и хосты .NET Framework: MSBuild (inline tasks), csc/vbc/jsc, InstallUtil, RegAsm, RegSvcs выполняют код из файлов,
// которые vault может положить в рабочую папку.
var dotnetTools = []string{
	`msbuild.exe`, `csc.exe`, `vbc.exe`, `jsc.exe`, `installutil.exe`, `regasm.exe`, `regsvcs.exe`, `aspnet_compiler.exe`,
	`Microsoft.Workflow.Compiler.exe`,
}

// Утилиты Windows, которыми обычно выносят данные; запускать их vault может, но выхода в сеть у них нет.
var netTools = []string{
	`curl.exe`, `bitsadmin.exe`, `certutil.exe`, `regsvr32.exe`, `rundll32.exe`, `msiexec.exe`,
	`ftp.exe`, `tftp.exe`, `finger.exe`, `nslookup.exe`, `telnet.exe`,
	`OpenSSH\ssh.exe`, `OpenSSH\scp.exe`, `OpenSSH\sftp.exe`,
}

func windir() string {
	if d, err := windows.GetSystemWindowsDirectory(); err == nil && d != "" {
		return d
	}
	return `C:\Windows`
}

// existing — пути из списка, которые есть на диске в System32 и SysWOW64, плюс PowerShell 7, если он установлен.
func existing(rel []string, withPwsh bool) []string {
	var out []string
	for _, dir := range []string{"System32", "SysWOW64"} {
		for _, r := range rel {
			p := filepath.Join(windir(), dir, r)
			if _, err := os.Stat(p); err == nil {
				out = append(out, p)
			}
		}
	}
	if withPwsh {
		pf := os.Getenv("ProgramFiles")
		if pf == "" {
			pf = `C:\Program Files`
		}
		m, _ := filepath.Glob(filepath.Join(pf, `PowerShell\*\pwsh.exe`))
		out = append(out, m...)
	}
	return out
}

// Interpreters — интерпретаторы и сборщики, найденные на этом компьютере.
func Interpreters() []string {
	out := append(existing(interpreters, true), userInstalled()...)
	for _, fw := range []string{"Framework", "Framework64"} {
		m, _ := filepath.Glob(filepath.Join(windir(), "Microsoft.NET", fw, "v*"))
		for _, dir := range m {
			for _, t := range dotnetTools {
				if p := filepath.Join(dir, t); fileExists(p) {
					out = append(out, p)
				}
			}
		}
	}
	return out
}

// userInstalled — Python, Node.js, Git Bash и Perl, найденные по типичным путям установки.
func userInstalled() []string {
	var out []string
	for _, root := range userInterpreterRoots() {
		if root == "" {
			continue
		}
		for _, rel := range userInterpreters {
			m, _ := filepath.Glob(filepath.Join(root, rel))
			out = append(out, m...)
		}
	}
	if sd := os.Getenv("SystemDrive"); sd != "" {
		m, _ := filepath.Glob(filepath.Join(sd+`\`, `Strawberry\perl\bin\perl.exe`))
		out = append(out, m...)
	}
	return out
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// NetTools — всё, что закрывается правилами брандмауэра для vault.
func NetTools() []string { return append(Interpreters(), existing(netTools, false)...) }

func openForACL(path string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	// Backup-семантика и привилегия SeRestore разрешают менять DACL файлов TrustedInstaller, не меняя владельца.
	return windows.CreateFile(p, windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
}

func denyIndexes(acl *windows.ACL, sid *windows.SID) []uint32 {
	var idx []uint32
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil {
			continue
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE && ace.Mask&fileExecute != 0 &&
			windows.EqualSid((*windows.SID)(unsafe.Pointer(&ace.SidStart)), sid) {
			idx = append(idx, i)
		}
	}
	return idx
}

// DenyExec запрещает sid запуск файла; повторный вызов ничего не меняет.
func DenyExec(path string, sid *windows.SID) error {
	h, err := openForACL(path)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	old, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if old != nil && len(denyIndexes(old, sid)) > 0 {
		return nil
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: fileExecute,
		AccessMode:        windows.DENY_ACCESS,
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
	return windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

var procDeleteAce = windows.NewLazySystemDLL("advapi32.dll").NewProc("DeleteAce")

// AllowExec снимает запрет, поставленный DenyExec.
func AllowExec(path string, sid *windows.SID) error {
	h, err := openForACL(path)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return err
	}
	idx := denyIndexes(acl, sid)
	if len(idx) == 0 {
		return nil
	}
	for i := len(idx) - 1; i >= 0; i-- {
		if r, _, e := procDeleteAce.Call(uintptr(unsafe.Pointer(acl)), uintptr(idx[i])); r == 0 {
			return e
		}
	}
	return windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// IsDenied — у файла есть запрет запуска для sid.
func IsDenied(path string, sid *windows.SID) bool {
	h, err := openForACL(path)
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(h) }()
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	acl, _, err := sd.DACL()
	return err == nil && acl != nil && len(denyIndexes(acl, sid)) > 0
}

// DenyInterpreters ставит запрет запуска интерпретаторов для vault. Вызывается при установке и перед каждым запуском
// приложения: обновление Windows подменяет файлы и сбрасывает права. Возвращает ошибки по файлам, остальные обрабатываются.
func DenyInterpreters(vault *windows.SID) error {
	var errs []error
	for _, p := range Interpreters() {
		if err := DenyExec(p, vault); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
		}
	}
	return errors.Join(errs...)
}

func AllowInterpreters(vault *windows.SID) error {
	var errs []error
	for _, p := range Interpreters() {
		if err := AllowExec(p, vault); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
		}
	}
	return errors.Join(errs...)
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func powershell(script string) error {
	enc := utf16.Encode([]rune(script))
	b := make([]byte, 0, len(enc)*2)
	for _, u := range enc {
		b = append(b, byte(u), byte(u>>8))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	ps := filepath.Join(windir(), `System32\WindowsPowerShell\v1.0\powershell.exe`)
	out, err := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(b)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("powershell: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ApplyFirewall создаёт правила: исходящая сеть утилит для vault закрыта; sessionvault.exe закрыт для всех
// (принцип «ноль сети»: даже подменённая программа ничего не отправит). Прежние правила группы заменяются.
func ApplyFirewall(vault *windows.SID, selfExe, scriptDir string) error {
	var b strings.Builder
	b.WriteString("$ErrorActionPreference='Stop'\n")
	fmt.Fprintf(&b, "Remove-NetFirewallRule -Group %s -ErrorAction SilentlyContinue\n", psQuote(Group))
	fmt.Fprintf(&b, "$u=%s\n", psQuote("D:(A;;CC;;;"+vault.String()+")"))
	// New-NetFirewallRule тратит около 0,3 с на правило, COM-интерфейс брандмауэра — миллисекунды; правила получаются те же.
	b.WriteString("$fw=New-Object -ComObject HNetCfg.FwPolicy2\n")
	b.WriteString("function Add-Block($name,$prog,$user){$r=New-Object -ComObject HNetCfg.FWRule;$r.Name=$name;$r.Grouping='" + Group +
		"';$r.Direction=2;$r.Action=0;$r.Profiles=2147483647;$r.ApplicationName=$prog;if($user){$r.LocalUserAuthorizedList=$user};$r.Enabled=$true;$fw.Rules.Add($r)}\n")
	for _, p := range NetTools() {
		fmt.Fprintf(&b, "Add-Block %s %s $u\n",
			psQuote("SessionVault vault "+strings.TrimPrefix(strings.ToLower(p), strings.ToLower(windir())+`\`)), psQuote(p))
	}
	fmt.Fprintf(&b, "Add-Block 'SessionVault no network' %s $null\n", psQuote(selfExe))
	return powershellFile(scriptDir, b.String())
}

// Скрипт с десятками правил не помещается в командную строку (предел 32 КБ для -EncodedCommand), поэтому запускается из файла.
// scriptDir должен быть закрыт для обычных пользователей: файл исполняется от SYSTEM, подмена между записью и запуском дала бы им права SYSTEM.
func powershellFile(scriptDir, script string) error {
	f, err := os.CreateTemp(scriptDir, "lockdown-*.ps1")
	if err != nil {
		return err
	}
	path := f.Name()
	defer func() { _ = os.Remove(path) }()
	// BOM: без него Windows PowerShell читает файл в ANSI, а пути могут быть не ASCII.
	if _, err := f.WriteString("\ufeff" + script); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ps := filepath.Join(windir(), `System32\WindowsPowerShell\v1.0\powershell.exe`)
	out, err := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("powershell: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func RemoveFirewall() error {
	return powershell(fmt.Sprintf("Remove-NetFirewallRule -Group %s -ErrorAction SilentlyContinue", psQuote(Group)))
}

const rulesKey = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules`

// Rules считает правила группы в реестре (там их хранит брандмауэр), без запуска PowerShell; want — сколько их должно быть.
func Rules() (have, want int) {
	want = len(NetTools()) + 1
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, rulesKey, registry.QUERY_VALUE)
	if err != nil {
		return 0, want
	}
	defer func() { _ = k.Close() }()
	names, err := k.ReadValueNames(0)
	if err != nil {
		return 0, want
	}
	for _, n := range names {
		if v, _, err := k.GetStringValue(n); err == nil && strings.Contains(v, "|Active=TRUE|") && strings.Contains(v, "|EmbedCtxt="+Group+"|") {
			have++
		}
	}
	return have, want
}

// Denied считает интерпретаторы с запретом запуска для vault.
func Denied(vault *windows.SID) (have, want int) {
	for _, p := range Interpreters() {
		want++
		if IsDenied(p, vault) {
			have++
		}
	}
	return have, want
}
