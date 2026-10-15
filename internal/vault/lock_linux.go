package vault

import (
	"errors"
	"os"

	"github.com/loar32/sessionvault/internal/i18n"
	"golang.org/x/sys/unix"
)

// flock держит запущенный экземпляр; при падении процесса ядро снимает блокировку само.
func (v Vault) Lock() (release func(), err error) {
	f, err := os.OpenFile(v.path("running.lock"), os.O_WRONLY|os.O_CREATE|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New(i18n.T("уже запущено (или не завершено): running.lock занят"))
	}
	return func() { _ = f.Close() }, nil
}
