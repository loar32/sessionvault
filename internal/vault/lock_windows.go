package vault

import (
	"errors"

	"github.com/loar32/sessionvault/internal/i18n"
	"golang.org/x/sys/windows"
)

// Эксклюзивно открытый файл держит запущенный экземпляр; при падении процесса система снимает блокировку сама.
func (v Vault) Lock() (release func(), err error) {
	name, err := windows.UTF16PtrFromString(v.path("running.lock"))
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, errors.New(i18n.T("уже запущено (или не завершено): running.lock занят"))
	}
	return func() { _ = windows.CloseHandle(h) }, nil
}
