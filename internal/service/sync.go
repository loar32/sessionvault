package service

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Событие, которым администратор просит службу проверить приманки сразу (после protect и import-tdata), не дожидаясь
// пятиминутной проверки. Pipe для этого не годится: он закрыт для администратора, а само событие открыто только SYSTEM
// и администраторам и ничего не передаёт, кроме «проверь сейчас». Служба ждёт его без опроса.
const syncEventName = `Global\SessionVaultSync`

func (s *Service) watchSync() {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		s.log.Println("событие синхронизации:", err)
		return
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, err := windows.UTF16PtrFromString(syncEventName)
	if err != nil {
		return
	}
	ev, err := windows.CreateEvent(sa, 0, 0, name)
	if err != nil {
		s.log.Println("событие синхронизации:", err)
		return
	}
	s.syncEvent = ev
	go func() {
		defer func() { _ = windows.CloseHandle(ev) }()
		for {
			if r, _ := windows.WaitForSingleObject(ev, windows.INFINITE); r != windows.WAIT_OBJECT_0 {
				return
			}
			select {
			case <-s.quit:
				return
			default:
			}
			select {
			case s.nudge <- struct{}{}:
			default:
			}
		}
	}()
}

// SyncService будит службу из командной строки администратора; без запущенной службы ничего не делает.
func SyncService() {
	name, err := windows.UTF16PtrFromString(syncEventName)
	if err != nil {
		return
	}
	ev, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, name)
	if err != nil {
		return
	}
	_ = windows.SetEvent(ev)
	_ = windows.CloseHandle(ev)
}
