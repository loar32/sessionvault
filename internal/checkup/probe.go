package checkup

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/loar32/sessionvault/internal/i18n"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// Все вопросы к системе, которых нет в реестре, задаются одним запуском PowerShell: BitLocker и его ключ восстановления,
// реальное состояние Defender, работающий сторонний антивирус и действует ли сейчас целостность памяти (а не только включена).
const probeScript = `$ErrorActionPreference='SilentlyContinue'
$r=@{}
$v=Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -Filter "DriveLetter='%s'"
if($v){$r.bl=[int]$v.ProtectionStatus;$ids=(Invoke-CimMethod -InputObject $v -MethodName GetKeyProtectors -Arguments @{KeyProtectorType=3}).VolumeKeyProtectorID;$r.rec=(@($ids).Count -gt 0)}
$d=Get-MpComputerStatus
if($d){$r.dk=$true;$r.rt=[bool]$d.RealTimeProtectionEnabled}
$r.av=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Where-Object {($_.productState -band 0x1000) -ne 0 -and $_.displayName -notmatch 'Defender'} | ForEach-Object {$_.displayName})
$g=Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard
if($g){$r.hk=$true;$r.hv=(@($g.SecurityServicesRunning) -contains 2)}
ConvertTo-Json -InputObject $r -Compress`

type probeReply struct {
	BL  *int            `json:"bl"`
	Rec bool            `json:"rec"`
	DK  bool            `json:"dk"`
	RT  bool            `json:"rt"`
	AV  json.RawMessage `json:"av"`
	HK  bool            `json:"hk"`
	HV  bool            `json:"hv"`
}

func (winSystem) probe() Probe {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return Probe{BitLocker: 2}
	}
	script := fmt.Sprintf(probeScript, filepath.VolumeName(dir))
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(dir, `WindowsPowerShell\v1.0\powershell.exe`), "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return Probe{BitLocker: 2}
	}
	return parseProbe(out)
}

func parseProbe(out []byte) Probe {
	var r probeReply
	if json.Unmarshal([]byte(strings.TrimSpace(string(out))), &r) != nil {
		return Probe{BitLocker: 2}
	}
	p := Probe{BitLocker: 2, BLRecovery: r.Rec, DefenderKnown: r.DK, DefenderRT: r.RT, HVCIKnown: r.HK, HVCIRunning: r.HV, OtherAV: avNames(r.AV)}
	if r.BL != nil {
		p.Known, p.BitLocker = true, *r.BL
	}
	return p
}

// PowerShell отдаёт один антивирус строкой, несколько — массивом.
func avNames(raw json.RawMessage) []string {
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	var one string
	if json.Unmarshal(raw, &one) == nil && one != "" {
		return []string{one}
	}
	return nil
}

const (
	eventLogKey    = `SYSTEM\CurrentControlSet\Services\EventLog\Security`
	eventLogPolicy = `SOFTWARE\Policies\Microsoft\Windows\EventLog\Security`
	firewallKey    = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\`
	fwPolicyKey    = `SOFTWARE\Policies\Microsoft\WindowsFirewall\`
	minJournal     = 20 << 20 // размер по умолчанию: меньше — записи приманки быстрее вытесняются
)

// Профили брандмауэра, в которых он выключен (локально или политикой): правила сетевого заслона там не действуют.
func firewallOff(sys system) []string {
	var off []string
	for _, p := range []struct{ key, name string }{{"StandardProfile", i18n.T("частная")}, {"PublicProfile", i18n.T("общедоступная")}, {"DomainProfile", i18n.T("доменная")}} {
		v, ok := sys.regInt(firewallKey+p.key, "EnableFirewall")
		if pv, pok := sys.regInt(fwPolicyKey+p.key, "EnableFirewall"); pok {
			v, ok = pv, true
		}
		if ok && v == 0 {
			off = append(off, p.name)
		}
	}
	return off
}

// Журнал безопасности хранит события аудита: сжатый до малого размера, он вытесняет их быстрее. Только справка.
func journalItem(sys system) Item {
	title := i18n.T("Журнал безопасности Windows")
	size, ok := sys.regInt(eventLogKey, "MaxSize")
	if pol, pok := sys.regInt(eventLogPolicy, "MaxSize"); pok {
		size, ok = pol<<10, true // политика задаёт килобайты
	}
	switch {
	case !ok:
		return Item{"journal", title, Info, i18n.T("размер по умолчанию"), ""}
	case size < minJournal:
		return Item{"journal", title, Info, fmt.Sprintf(i18n.T("размер %d МБ, меньше стандартных 20 МБ"), size>>20),
			i18n.T("Журнал заполняется быстрее: Просмотр событий → Журналы Windows → Безопасность → Свойства → максимальный размер")}
	}
	return Item{"journal", title, OK, fmt.Sprintf(i18n.T("размер %d МБ"), size>>20), ""}
}

// Копия приложения под учёткой sv-* не обновляется сама: после обновления приложения её нужно обновить командой refresh.
func copiesItem(in Input) Item {
	title := i18n.T("Копии приложений")
	switch {
	case in.Copies == 0:
		return Item{"copies", title, Info, i18n.T("нет приложений с копией в каталоге программы"), ""}
	case len(in.StaleCopies) == 0:
		return Item{"copies", title, OK, i18n.T("актуальны"), ""}
	}
	return Item{"copies", title, Info, i18n.T("устарели: ") + strings.Join(in.StaleCopies, ", "),
		i18n.T("Приложение обновилось, а защищённая копия нет. От администратора: sessionvault refresh <приложение> (приложение должно быть закрыто)")}
}
