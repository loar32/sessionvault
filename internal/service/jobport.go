package service

import (
	"unsafe"

	"github.com/loar32/sessionvault/internal/audit"
	"golang.org/x/sys/windows"
)

const (
	jobObjectAssociateCompletionPort = 7
	jobMsgActiveProcessZero          = 4
	jobMsgExitProcess                = 7
	jobMsgAbnormalExit               = 8
	jobMsgNewProcess                 = 6
	portQuitKey                      = 1
)

type jobCompletionPort struct {
	Key  uintptr
	Port windows.Handle
}

// Job-объект сам сообщает порту завершения о каждом новом процессе (в том числе потомке защищённого приложения) и о выходе:
// аудит чтения памяти ставится сразу при появлении процесса, а не при ближайшем опросе, и без таймера.
func (s *Service) attachJob(job windows.Handle) {
	if s.port == 0 {
		return
	}
	info := jobCompletionPort{Key: 0, Port: s.port}
	if _, err := windows.SetInformationJobObject(job, jobObjectAssociateCompletionPort, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		s.log.Println("порт завершения job:", err)
	}
}

func (s *Service) jobPortWorker() {
	for {
		var msg uint32
		var key uintptr
		var ov *windows.Overlapped
		if err := windows.GetQueuedCompletionStatus(s.port, &msg, &key, &ov, windows.INFINITE); err != nil && ov == nil {
			return
		}
		if key == portQuitKey {
			return
		}
		pid := uint32(uintptr(unsafe.Pointer(ov)))
		switch msg {
		case jobMsgNewProcess:
			s.watchPID(pid)
		case jobMsgExitProcess, jobMsgAbnormalExit:
			s.mu.Lock()
			delete(s.memWatched, pid)
			delete(s.memFailed, pid)
			s.mu.Unlock()
		}
	}
}

func (s *Service) watchPID(pid uint32) {
	s.mu.Lock()
	if s.memWatched[pid] {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	sid := s.mainUserSID()
	if sid == nil {
		return
	}
	err := audit.WatchProcess(pid, sid)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		if s.memFailed == nil {
			s.memFailed = map[uint32]bool{}
		}
		if !s.memFailed[pid] {
			s.log.Printf("аудит процесса %d: %v", pid, err)
		}
		s.memFailed[pid] = true
		return
	}
	if s.memWatched == nil {
		s.memWatched = map[uint32]bool{}
	}
	s.memWatched[pid] = true
}

func (s *Service) mainUserSID() *windows.SID {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mainSID == nil {
		if sid, _, _, err := windows.LookupSID("", s.cfg.MainUser); err == nil {
			s.mainSID = sid
		}
	}
	return s.mainSID
}
