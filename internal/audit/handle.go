package audit

import (
	"errors"
	"github.com/loar32/sessionvault/internal/i18n"
	"io/fs"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// FileKey однозначно называет файл или папку на диске независимо от пути: жёсткая ссылка и переименование его не меняют.
type FileKey struct {
	Volume uint32
	ID     uint64
}

// Без FILE_FLAG_OPEN_REPARSE_POINT открытие прошло бы по ссылке или junction в чужое место.
func openNoFollow(path string, access, share uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(p, access, share, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

func keyOf(h windows.Handle) (FileKey, uint32, error) {
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return FileKey{}, 0, err
	}
	return FileKey{fi.VolumeSerialNumber, uint64(fi.FileIndexHigh)<<32 | uint64(fi.FileIndexLow)}, fi.FileAttributes, nil
}

// FileID возвращает ключ файла по пути (ссылку не разворачивает: ключ самой ссылки).
func FileID(path string) (FileKey, error) {
	h, err := openNoFollow(path, windows.FILE_READ_ATTRIBUTES, ShareAll)
	if err != nil {
		return FileKey{}, err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	k, _, err := keyOf(h)
	return k, err
}

// finalPath — настоящий путь, на который указывает дескриптор, без префикса \\?\.
func finalPath(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
	if err != nil {
		return "", err
	}
	if int(n) >= len(buf) {
		return "", errors.New(i18n.T("слишком длинный путь"))
	}
	return strings.TrimPrefix(windows.UTF16ToString(buf[:n]), `\\?\`), nil
}

// OpenDirChecked открывает папку и проверяет по дескриптору, что это обычная папка по именно этому пути:
// ни она сама, ни любой родитель не подменены ссылкой или junction. Дальше работа идёт с дескриптором,
// а не с путём, поэтому подмена после проверки ничего не меняет.
func OpenDirChecked(path string, access, share uint32) (windows.Handle, error) {
	h, err := openNoFollow(path, access, share)
	if err != nil {
		return 0, err
	}
	_, attr, err := keyOf(h)
	if err == nil && attr&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		err = errors.New(i18n.T("на пути ссылка или junction: ") + path)
	}
	if err == nil && attr&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		err = errors.New(i18n.T("не папка: ") + path)
	}
	if err == nil {
		var real string
		if real, err = finalPath(h); err == nil && !strings.EqualFold(real, filepath.Clean(path)) && !sameLong(real, path) {
			err = errors.New(i18n.T("путь ведёт в другое место: ") + path + " → " + real)
		}
	}
	if err != nil {
		_ = windows.CloseHandle(h)
		return 0, err
	}
	return h, nil
}

// Путь мог быть записан в коротком виде (ADMINI~1): сравниваем с развёрнутым.
func sameLong(real, path string) bool {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(p, &buf[0], uint32(len(buf)))
	return err == nil && n > 0 && int(n) < len(buf) && strings.EqualFold(real, windows.UTF16ToString(buf[:n]))
}

// TreeKeys — ключи папки и всего, что в ней лежит (для узнавания приманки по FileId).
func TreeKeys(root string) (map[FileKey]bool, error) {
	keys := map[FileKey]bool{}
	err := filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		k, err := FileID(p)
		if err != nil {
			return err
		}
		keys[k] = true
		return nil
	})
	return keys, err
}

// DOSPath переводит путь формата устройства из журнала (\Device\HarddiskVolume3\...) в путь с буквой диска.
func DOSPath(nt string) (string, bool) {
	// Журнал пишет объект то в формате устройства, то уже с буквой диска.
	if len(nt) > 3 && nt[1] == ':' && nt[2] == '\\' {
		return nt, true
	}
	for c := 'A'; c <= 'Z'; c++ {
		drive := string(c) + ":"
		dev, err := NTPath(drive)
		if err != nil || dev == "" {
			continue
		}
		if len(nt) > len(dev) && strings.EqualFold(nt[:len(dev)], dev) && nt[len(dev)] == '\\' {
			return drive + nt[len(dev):], true
		}
	}
	return "", false
}

// Режимы совместного доступа: SharePin без FILE_SHARE_DELETE не даёт переименовать или удалить открытую папку,
// а вместе с ней и любого её родителя.
const (
	ShareAll = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
	SharePin = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE
)
