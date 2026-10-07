package service

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

const (
	notifyDirName    = 0x2 // FILE_NOTIFY_CHANGE_DIR_NAME: создание, удаление и переименование папок
	notifyAttributes = 0x4 // FILE_NOTIFY_CHANGE_ATTRIBUTES: junction ставится через атрибуты точки повторной обработки
)

// Подмену папки приманки (удаление, переименование, junction на её месте) видно как изменение родительской папки:
// следим за ней событием ОС и проверяем приманки сразу, а не ждём пятиминутной проверки.
func (s *Service) watchParent(origin string) {
	parent := filepath.Dir(origin)
	s.trapMu.Lock()
	if s.parents == nil {
		s.parents = map[string]bool{}
	}
	if s.parents[parent] {
		s.trapMu.Unlock()
		return
	}
	s.parents[parent] = true
	s.trapMu.Unlock()

	h, err := windows.FindFirstChangeNotification(parent, false, notifyDirName|notifyAttributes)
	if err != nil {
		s.log.Printf("слежение за %s: %v", parent, err)
		s.trapMu.Lock()
		delete(s.parents, parent)
		s.trapMu.Unlock()
		return
	}
	go func() {
		defer func() { _ = windows.FindCloseChangeNotification(h) }()
		for {
			r, _ := windows.WaitForMultipleObjects([]windows.Handle{h, s.stopEvt}, false, windows.INFINITE)
			if r != windows.WAIT_OBJECT_0 {
				return
			}
			select {
			case s.nudge <- struct{}{}:
			default:
			}
			if windows.FindNextChangeNotification(h) != nil {
				return
			}
		}
	}()
}
