// Package checkwin показывает итог проверки защиты в системном окне: по пункту трея и один раз после установки.
package checkwin

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/loar32/sessionvault/internal/checkup"
	"github.com/loar32/sessionvault/internal/ipc"
	"github.com/loar32/sessionvault/internal/isolation"
	"golang.org/x/sys/windows"
)

var procMessageBox = windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW")

const (
	Title    = "SessionVault: проверка защиты"
	mbSetFg  = 0x10000
	mbTop    = 0x40000
	mbIconOK = 0x40
	mbIconWn = 0x30
	mbIconEr = 0x10
	mbYesNo  = 0x4
	idYes    = 6
)

// Fetch берёт свежий отчёт у службы; проверка может идти до 15 с (BitLocker спрашивается у PowerShell).
func Fetch() (checkup.Report, error) {
	var r checkup.Report
	raw, err := ipc.CallMax(ipc.CommandPipe, "check", 40*time.Second, ipc.MaxCheck)
	if err != nil {
		return r, err
	}
	return r, json.Unmarshal([]byte(raw), &r)
}

// Text — содержимое окна: итог, жёлтые и красные пункты с подсказками, число остальных и справка про ClickFix.
// Полный отчёт остаётся в `sessionvault check`.
func Text(r checkup.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Итог: %s\n", checkup.Verdict(r.Overall))
	ok, total := 0, 0
	for _, it := range r.Items {
		if it.Level != checkup.Info {
			total++
		}
		switch it.Level {
		case checkup.OK:
			ok++
		case checkup.Warn, checkup.Bad:
			fmt.Fprintf(&b, "\n%s %s: %s\n", checkup.Mark(it.Level), it.Title, it.Detail)
			if it.Hint != "" {
				fmt.Fprintf(&b, "    %s\n", it.Hint)
			}
		}
	}
	if ok > 0 {
		fmt.Fprintf(&b, "\nВ порядке: %d из %d пунктов.\n", ok, total)
	}
	fmt.Fprintf(&b, "\n%s\n\nПолный отчёт: sessionvault check", checkup.ClickFixText)
	return b.String()
}

// Show блокирует вызывающую горутину, пока окно открыто. Если есть что улучшить, окно спрашивает, открыть ли «Безопасность Windows»:
// почти все жёлтые и красные пункты (Defender, HVCI, BitLocker, брандмауэр) включаются там.
func Show(r checkup.Report) {
	icon := uintptr(mbIconOK)
	switch r.Overall {
	case checkup.Warn:
		icon = mbIconWn
	case checkup.Bad:
		icon = mbIconEr
	}
	body, buttons := Text(r), uintptr(0)
	if r.Overall != checkup.OK {
		body += "\n\nОткрыть «Безопасность Windows»?"
		buttons = mbYesNo
	}
	text, _ := windows.UTF16PtrFromString(body)
	title, _ := windows.UTF16PtrFromString(Title)
	ans, _, _ := procMessageBox.Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), icon|buttons|mbSetFg|mbTop)
	if ans == idYes {
		_ = windows.ShellExecute(0, windows.StringToUTF16Ptr("open"), windows.StringToUTF16Ptr("windowsdefender:"), nil, nil, windows.SW_SHOWNORMAL)
	}
}

func flagPath() string {
	dir := isolation.KnownDir(windows.FOLDERID_LocalAppData, os.Getenv("LOCALAPPDATA"))
	return filepath.Join(dir, "SessionVault", "check-shown")
}

// AutoCheck: один раз за учётку после установки спрашивает отчёт и показывает окно только при красных пунктах.
// Флаг ставится при любом результате, чтобы позже окно само не всплывало; если служба недоступна — флага нет, повтор
// будет при следующем запуске трея.
func AutoCheck() { autoCheck(Fetch, Show, flagPath()) }

func autoCheck(fetch func() (checkup.Report, error), show func(checkup.Report), flag string) {
	if _, err := os.Stat(flag); err == nil || !errors.Is(err, os.ErrNotExist) {
		return
	}
	r, err := fetch()
	if err != nil {
		return
	}
	if os.MkdirAll(filepath.Dir(flag), 0o700) != nil || os.WriteFile(flag, nil, 0o600) != nil {
		return
	}
	if r.Overall == checkup.Bad {
		show(r)
	}
}
