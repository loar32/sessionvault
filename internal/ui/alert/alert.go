// Package alert показывает окно тревоги. Его запускает служба от SYSTEM в сессии пользователя, поэтому процесс
// пользователя не может закрыть окно или подменить его.
package alert

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32          = windows.NewLazySystemDLL("user32.dll")
	procMessageBox  = user32.NewProc("MessageBoxW")
	procMessageBeep = user32.NewProc("MessageBeep")
)

const (
	mbIconWarning = 0x30
	mbSystemModal = 0x1000
	mbSetFg       = 0x10000
	mbTopmost     = 0x40000
	mbIconHand    = 0x10
)

type Info struct {
	Process string    `json:"process"`
	PID     uint32    `json:"pid"`
	SHA256  string    `json:"sha256"`
	Object  string    `json:"object"`
	Time    time.Time `json:"time"`
}

// Encode упаковывает данные в один аргумент командной строки без кавычек и пробелов.
func Encode(i Info) (string, error) {
	b, err := json.Marshal(i)
	return hex.EncodeToString(b), err
}

func Decode(s string) (Info, error) {
	var i Info
	b, err := hex.DecodeString(s)
	if err != nil {
		return i, err
	}
	return i, json.Unmarshal(b, &i)
}

func Run(arg string) error {
	i, err := Decode(arg)
	if err != nil {
		return err
	}
	go func() {
		for range 3 {
			_, _, _ = procMessageBeep.Call(mbIconHand)
			time.Sleep(700 * time.Millisecond)
		}
	}()
	text := fmt.Sprintf("Приманка с данными приложения прочитана посторонним процессом.\n"+
		"Защищённые приложения закрыты, данные зашифрованы, хранилище заблокировано.\n\n"+
		"Процесс: %s (PID %d)\nSHA-256: %s\nВремя: %s",
		i.Process, i.PID, i.SHA256, i.Time.Format("15:04:05 02.01.2006"))
	text = strings.ReplaceAll(text, "\x00", "")
	t, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return err
	}
	title, _ := windows.UTF16PtrFromString("SessionVault: тревога")
	_, _, _ = procMessageBox.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(title)),
		mbIconWarning|mbSystemModal|mbSetFg|mbTopmost)
	return nil
}
