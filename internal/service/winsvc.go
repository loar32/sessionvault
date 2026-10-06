package service

import (
	"os"
	"time"

	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"golang.org/x/sys/windows/svc"
)

const Name = "SessionVault"

const (
	wtsConsoleDisconnect = 2 // WTS_CONSOLE_DISCONNECT: смена пользователя
	wtsRemoteDisconnect  = 4 // WTS_REMOTE_DISCONNECT
	wtsSessionLogoff     = 6 // WTS_SESSION_LOGOFF
	wtsSessionLock       = 7 // WTS_SESSION_LOCK
	pbtApmSuspend        = 4 // PBT_APMSUSPEND
)

type handler struct{ s *Service }

func (h handler) Execute(_ []string, r <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	go h.s.Serve()
	go h.s.StartTraps()
	go h.s.startCheck()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPreShutdown | svc.AcceptSessionChange | svc.AcceptPowerEvent}
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			st <- c.CurrentStatus
		case svc.SessionChange:
			switch c.EventType {
			case wtsSessionLogoff, wtsSessionLock, wtsConsoleDisconnect, wtsRemoteDisconnect:
				h.s.lockRequested()
			}
		case svc.PowerEvent:
			if c.EventType == pbtApmSuspend {
				h.s.lockRequested()
			}
		case svc.Stop, svc.Shutdown, svc.PreShutdown:
			// Шифрование открытых данных при остановке может занять до stopWait: без WaitHint система выключилась бы раньше.
			st <- svc.Status{State: svc.StopPending, WaitHint: uint32((stopWait + 5*time.Second).Milliseconds())}
			h.s.Stop()
			return false, 0
		}
	}
	return false, 0
}

// Вызывается из режима `sessionvault service`, когда процесс запущен менеджером служб.
func RunService() error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// Первый запуск после обновления до подписи профилей: подписываем то, что лежит в каталоге (его пишет только администратор).
	if !profiles.HasKey(isolation.ProfilesDir()) {
		_ = profiles.Resign(isolation.ProfilesDir())
	}
	lg, closeLog, err := OpenLog()
	if err != nil {
		return err
	}
	defer closeLog()
	s, err := New(cfg, exe, lg)
	if err != nil {
		return err
	}
	if err := s.Listen(); err != nil {
		lg.Println("pipe:", err)
		return err
	}
	return svc.Run(Name, handler{s})
}
