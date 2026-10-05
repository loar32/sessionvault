// Package checkup проверяет, какие системные меры защиты на компьютере включены. Только чтение: ничего не меняет,
// работает по запросу (старт службы и команда check), без таймеров.
package checkup

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type Level string

const (
	OK   Level = "ok"
	Warn Level = "warn"
	Bad  Level = "bad"
	Info Level = "info" // справка, на итог не влияет
)

type Item struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Level  Level  `json:"level"`
	Detail string `json:"detail"`
	Hint   string `json:"hint,omitempty"`
}

type Report struct {
	Time    time.Time `json:"time"`
	Overall Level     `json:"overall"`
	Items   []Item    `json:"items"`
}

// Input — то, что знает сама служба: её меры и состояние основной учётки.
type Input struct {
	MainUserAdmin   bool
	MainUserUnknown bool // учётку проверить не удалось: зелёным это показывать нельзя
	Audit           bool
	Hardened        bool
	Hello           bool
}

// Реестр и BitLocker за интерфейсом: в тестах подменяются.
type system interface {
	regInt(key, value string) (int64, bool)
	regStr(key, value string) (string, bool)
	bitlocker() (int, error) // ProtectionStatus системного тома: 0 выкл., 1 вкл., 2 неизвестно
}

const (
	ntVersion   = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	defPolicy   = `SOFTWARE\Policies\Microsoft\Windows Defender`
	defRealtime = `SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`
	hvciKey     = `SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`
	secureBoot  = `SYSTEM\CurrentControlSet\Control\SecureBoot\State`
	ciConfig    = `SYSTEM\CurrentControlSet\Control\CI\Config`

	// С этой сборки (Windows 11 22H2) блоклист уязвимых драйверов включён по умолчанию.
	blocklistDefaultBuild = 22621
	minBuild              = 19045 // Windows 10 22H2: ниже обновления безопасности уже не выходят
)

// Run собирает отчёт; BitLocker спрашивается у PowerShell (до 15 с), остальное — чтение реестра.
func Run(in Input) Report { return run(winSystem{}, in, time.Now()) }

func run(sys system, in Input, now time.Time) Report {
	items := []Item{
		userItem(in),
		windowsItem(sys),
		defenderItem(sys),
		bitlockerItem(sys),
		hvciItem(sys),
		secureBootItem(sys),
		blocklistItem(sys),
		auditItem(in),
		hardenItem(in),
		helloItem(in),
		{ID: "telegram", Title: "Код-пароль Telegram", Level: Info,
			Detail: "включается в самом Telegram",
			Hint:   "Настройки → Конфиденциальность → Код-пароль: без него украденные файлы tdata открываются сразу"},
	}
	overall := OK
	for _, it := range items {
		if it.Level == Bad || (it.Level == Warn && overall == OK) {
			overall = it.Level
		}
	}
	return Report{Time: now, Overall: overall, Items: items}
}

func userItem(in Input) Item {
	if in.MainUserUnknown {
		return Item{"user", "Основная учётка", Warn, "состав групп определить не удалось", "Проверьте вручную, что основная учётка не в группе «Администраторы»"}
	}
	if in.MainUserAdmin {
		return Item{"user", "Основная учётка", Bad, "состоит в администраторах",
			"Защита не работает против процессов администратора: заведите обычную учётку для повседневной работы"}
	}
	return Item{"user", "Основная учётка", OK, "обычная, не администратор", ""}
}

func build(sys system) int {
	s, _ := sys.regStr(ntVersion, "CurrentBuild")
	n, _ := strconv.Atoi(s)
	return n
}

func windowsItem(sys system) Item {
	name, _ := sys.regStr(ntVersion, "ProductName")
	ver, _ := sys.regStr(ntVersion, "DisplayVersion")
	ed, _ := sys.regStr(ntVersion, "EditionID")
	b := build(sys)
	// В реестре Windows 11 по-прежнему называется «Windows 10».
	if b >= 22000 {
		name = strings.Replace(name, "Windows 10", "Windows 11", 1)
	}
	detail := strings.TrimSpace(fmt.Sprintf("%s %s, сборка %d", name, ver, b))
	switch {
	case b == 0:
		return Item{"windows", "Windows", Warn, "версию определить не удалось", ""}
	case b < minBuild:
		return Item{"windows", "Windows", Warn, detail, "Эта сборка больше не получает обновления безопасности: обновите Windows"}
	case strings.HasPrefix(ed, "Core"):
		return Item{"windows", "Windows", Warn, detail + " (Home)", "В Home нет AppLocker и части защит; запрет запуска файлов будет через SRP"}
	}
	return Item{"windows", "Windows", OK, detail, ""}
}

func defenderItem(sys system) Item {
	off := false
	for _, c := range [][2]string{{defPolicy, "DisableAntiSpyware"}, {defPolicy + `\Real-Time Protection`, "DisableRealtimeMonitoring"}, {defRealtime, "DisableRealtimeMonitoring"}} {
		if v, ok := sys.regInt(c[0], c[1]); ok && v == 1 {
			off = true
		}
	}
	if off {
		return Item{"defender", "Microsoft Defender", Bad, "отключён или без защиты в реальном времени",
			"Если нет другого антивируса, включите Defender: Безопасность Windows → Защита от вирусов"}
	}
	return Item{"defender", "Microsoft Defender", OK, "не отключён", ""}
}

func bitlockerItem(sys system) Item {
	st, err := sys.bitlocker()
	switch {
	case err != nil || st == 2:
		return Item{"bitlocker", "BitLocker", Warn, "состояние определить не удалось",
			"Проверьте вручную: Параметры → Конфиденциальность и защита → Шифрование устройства"}
	case st == 0:
		return Item{"bitlocker", "BitLocker", Warn, "системный диск не зашифрован",
			"Без шифрования диска файл подкачки и временные данные читаются с выключенного компьютера"}
	}
	return Item{"bitlocker", "BitLocker", OK, "системный диск зашифрован", ""}
}

func hvciItem(sys system) Item {
	if v, ok := sys.regInt(hvciKey, "Enabled"); ok && v == 1 {
		return Item{"hvci", "Целостность памяти (HVCI)", OK, "включена", ""}
	}
	return Item{"hvci", "Целостность памяти (HVCI)", Warn, "выключена",
		"Безопасность Windows → Безопасность устройства → Изоляция ядра → Целостность памяти"}
}

func secureBootItem(sys system) Item {
	v, ok := sys.regInt(secureBoot, "UEFISecureBootEnabled")
	switch {
	case !ok:
		return Item{"secureboot", "Безопасная загрузка", Warn, "не поддерживается (старый BIOS)", "Включить можно только на UEFI-компьютере"}
	case v != 1:
		return Item{"secureboot", "Безопасная загрузка", Warn, "выключена", "Включается в настройках UEFI (BIOS)"}
	}
	return Item{"secureboot", "Безопасная загрузка", OK, "включена", ""}
}

func blocklistItem(sys system) Item {
	v, ok := sys.regInt(ciConfig, "VulnerableDriverBlocklistEnable")
	if v == 1 || (!ok && build(sys) >= blocklistDefaultBuild) {
		return Item{"blocklist", "Блоклист уязвимых драйверов", OK, "включён", ""}
	}
	return Item{"blocklist", "Блоклист уязвимых драйверов", Warn, "выключен",
		"Безопасность Windows → Изоляция ядра → Блок-список уязвимых драйверов Майкрософт"}
}

func auditItem(in Input) Item {
	if in.Audit {
		return Item{"audit", "Аудит чтения файлов (приманка)", OK, "работает", ""}
	}
	return Item{"audit", "Аудит чтения файлов (приманка)", Bad, "не работает",
		"Приманка не сработает; возможно, групповая политика отключила аудит. Подробности: sessionvault alerts"}
}

func hardenItem(in Input) Item {
	if in.Hardened {
		return Item{"harden", "Меры harden", OK, "подкачка шифруется, гибернация и дампы отключены", ""}
	}
	return Item{"harden", "Меры harden", Warn, "не действуют (не включены или возвращены)", "От администратора: sessionvault harden (откат: harden -off)"}
}

func helloItem(in Input) Item {
	if in.Hello {
		return Item{"hello", "Windows Hello", OK, "вход в хранилище через Hello включён", ""}
	}
	return Item{"hello", "Windows Hello", Warn, "не включён ни для одного профиля",
		"Без Hello мастер-пароль вводится в окне на обычном рабочем столе; включается пунктом меню в трее"}
}

type winSystem struct{}

func (winSystem) regInt(key, value string) (int64, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE)
	if err != nil {
		return 0, false
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetIntegerValue(value)
	return int64(v), err == nil
}

func (winSystem) regStr(key, value string) (string, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetStringValue(value)
	return v, err == nil
}

func (winSystem) bitlocker() (int, error) {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return 2, err
	}
	drive := filepath.VolumeName(dir)
	script := `(Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -Filter "DriveLetter='` + drive + `'").ProtectionStatus`
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(dir, `WindowsPowerShell\v1.0\powershell.exe`), "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return 2, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 2, errors.New("неожиданный ответ PowerShell")
	}
	return n, nil
}
