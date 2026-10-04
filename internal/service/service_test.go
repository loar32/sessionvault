package service

import (
	"io"
	"log"
	"os"
	"testing"
	"time"

	"github.com/loar32/sessionvault/internal/profiles"
)

func testService(idle time.Duration) *Service {
	return &Service{
		idleAfter: idle,
		log:       log.New(io.Discard, "", 0),
		keys:      map[string][]byte{"telegram": make([]byte, 32)},
		running:   map[string]bool{},
	}
}

func keysCount(s *Service) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.keys)
}

func TestIdleLocks(t *testing.T) {
	s := testService(50 * time.Millisecond)
	s.mu.Lock()
	s.resetIdle()
	s.mu.Unlock()
	time.Sleep(300 * time.Millisecond)
	if keysCount(s) != 0 {
		t.Fatal("ключи не стёрты по бездействию")
	}
	if s.state() != "locked" {
		t.Fatal("статус не locked")
	}
}

// Ключ нужен для шифрования при выходе приложения: пока оно запущено, блокировать нельзя.
func TestIdleDoesNotLockWhileRunning(t *testing.T) {
	s := testService(50 * time.Millisecond)
	s.mu.Lock()
	s.running["telegram"] = true
	s.resetIdle()
	s.mu.Unlock()
	time.Sleep(300 * time.Millisecond)
	if keysCount(s) != 1 {
		t.Fatal("ключи стёрты при работающем приложении")
	}
	s.finish("telegram")
	time.Sleep(300 * time.Millisecond)
	if keysCount(s) != 0 {
		t.Fatal("после выхода приложения блокировка не сработала")
	}
}

func TestStartingRunCancelsIdle(t *testing.T) {
	s := testService(100 * time.Millisecond)
	s.mu.Lock()
	s.resetIdle()
	s.stopIdle()
	s.mu.Unlock()
	time.Sleep(300 * time.Millisecond)
	if keysCount(s) != 1 {
		t.Fatal("отменённый таймер всё равно сработал")
	}
}

func TestVerifyPublisherSkipsMissingExe(t *testing.T) {
	p := profiles.Profile{Exe: `C:\нет\такого.exe`, Publisher: "Telegram FZ-LLC"}
	if err := verifyPublisher(p); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyPublisherRejectsUnsigned(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPublisher(profiles.Profile{Exe: exe, Publisher: "Telegram FZ-LLC"}); err == nil {
		t.Fatal("неподписанный exe должен отклоняться")
	}
}
