package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/loar32/sessionvault/internal/audit"
	"github.com/loar32/sessionvault/internal/checkup"
	"github.com/loar32/sessionvault/internal/hardening"
	"github.com/loar32/sessionvault/internal/ipc"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/vault"
)

var (
	checkMu   sync.Mutex
	lastCheck string
	lastAt    time.Time
)

// Отчёт не старше этого отдаётся из памяти: каждый запуск проверки — это PowerShell от SYSTEM, и процесс сеанса не должен
// мочь гонять его без конца.
const checkCacheTTL = 10 * time.Second

func CheckPath() string { return filepath.Join(isolation.BaseDir(), "check.json") }

// Проверка защиты при старте службы: единственная, остальные — только по команде check.
func (s *Service) startCheck() {
	if s.check() == ipc.Failed {
		return
	}
	s.log.Println("проверка защиты выполнена, отчёт в check.json")
}

// Собирает отчёт, пишет check.json (читают администраторы) и отдаёт его же одной строкой.
func (s *Service) check() string {
	checkMu.Lock()
	defer checkMu.Unlock()
	if lastCheck != "" && time.Since(lastAt) < checkCacheTTL {
		return lastCheck
	}
	cfg, err := LoadConfig()
	if err != nil {
		cfg = s.cfg
	}
	admin, adminErr := isolation.IsAdminUser(cfg.MainUser)
	in := checkup.Input{MainUserAdmin: admin, MainUserUnknown: adminErr != nil, Audit: audit.IsEnabled(), Hardened: hardening.Applied(), Hello: s.helloEnabled()}
	b, err := json.Marshal(checkup.Run(in))
	if err != nil {
		return ipc.Failed
	}
	tmp := CheckPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		s.log.Println("check.json:", err)
	} else if err := os.Rename(tmp, CheckPath()); err != nil {
		s.log.Println("check.json:", err)
	}
	lastCheck, lastAt = string(b), time.Now()
	return lastCheck
}

func (s *Service) helloEnabled() bool {
	entries, err := os.ReadDir(isolation.VaultDir())
	if err != nil {
		return false
	}
	for _, e := range entries {
		v := vault.Vault{Dir: isolation.DataPath(e.Name()), DataName: workDataName}
		if _, _, ok := v.HelloInfo(); ok {
			return true
		}
	}
	return false
}
