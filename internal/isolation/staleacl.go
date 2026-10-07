package isolation

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
)

// Права на рабочий стол и каталог имён выдаются logon-SID приложения и снимаются после его выхода. Если помощник убит
// (тревога, остановка службы), снять некому: SID записан в файл заранее, и служба при старте и после тревоги просит
// помощника в сеансе пользователя снять права по списку.
var grantedMu sync.Mutex

func grantedFile() string { return filepath.Join(BaseDir(), "granted-sids.txt") }

func readGranted() []string {
	b, err := os.ReadFile(grantedFile())
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func writeGranted(sids []string) error {
	if len(sids) == 0 {
		err := os.Remove(grantedFile())
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return os.WriteFile(grantedFile(), []byte(strings.Join(sids, "\n")+"\n"), 0o600)
}

func noteGranted(sid string) error {
	grantedMu.Lock()
	defer grantedMu.Unlock()
	return writeGranted(append(readGranted(), sid))
}

func forgetGranted(sid string) {
	grantedMu.Lock()
	defer grantedMu.Unlock()
	var keep []string
	for _, s := range readGranted() {
		if s != sid {
			keep = append(keep, s)
		}
	}
	_ = writeGranted(keep)
}

// HasStaleACL — есть ли записанные, но не снятые права.
func HasStaleACL() bool { return len(readGranted()) > 0 }

// PurgeStaleACL снимает записанные права; вызывается помощником в сеансе пользователя, когда приложений нет.
func PurgeStaleACL() error {
	var first error
	for _, s := range readGranted() {
		sid, err := windows.StringToSid(s)
		if err != nil {
			forgetGranted(s)
			continue
		}
		e1 := setNamedObjectAccess(sid, windows.REVOKE_ACCESS)
		e2 := setDesktopAccess(sid, windows.REVOKE_ACCESS)
		if e1 == nil && e2 == nil {
			forgetGranted(s)
		} else if first == nil {
			first = e1
			if first == nil {
				first = e2
			}
		}
	}
	return first
}
