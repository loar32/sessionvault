package service

import (
	"os"

	"golang.org/x/sys/windows/svc"
)

const Name = "SessionVault"

type handler struct{ s *Service }

func (h handler) Execute(_ []string, r <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	go h.s.Serve()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			st <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			st <- svc.Status{State: svc.StopPending}
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
