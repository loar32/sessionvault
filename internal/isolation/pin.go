package isolation

import (
	"errors"
	"github.com/loar32/sessionvault/internal/i18n"
	"path/filepath"

	"github.com/loar32/sessionvault/internal/audit"
	"golang.org/x/sys/windows"
)

// PinParent закрепляет папку, в которой лежит path: пока дескриптор открыт без FILE_SHARE_DELETE, ни её, ни любого её
// родителя нельзя переименовать, удалить или подменить junction. Путь проверен по дескриптору: на нём нет ссылок.
// Администратор переносит и удаляет файлы по путям из профиля пользователя; закрепление не оставляет окна между
// проверкой пути и операцией, в которое процесс пользователя мог бы увести её в чужую папку.
func PinParent(path string) (release func(), err error) {
	h, err := audit.OpenDirChecked(filepath.Dir(path), windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES, audit.SharePin)
	if err != nil {
		return nil, err
	}
	return func() { _ = windows.CloseHandle(h) }, nil
}

// pinFile открывает обычный файл так, что писать в него и удалять его, пока дескриптор открыт, нельзя.
func pinFile(path string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, err
	}
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil || fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(h)
		return 0, errors.New(i18n.T("не обычный файл: ") + path)
	}
	return h, nil
}
