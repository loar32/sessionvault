package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/loar32/sessionvault/internal/asr"
	"github.com/loar32/sessionvault/internal/audit"
	"github.com/loar32/sessionvault/internal/checkup"
	"github.com/loar32/sessionvault/internal/decoy"
	"github.com/loar32/sessionvault/internal/extscan"
	"github.com/loar32/sessionvault/internal/hardening"
	"github.com/loar32/sessionvault/internal/ipc"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
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
	ext, scanned := s.extensionsState()
	memReads, memLast := s.memoryState()
	in := checkup.Input{MemAudit: audit.MemoryAuditEnabled(), MemReads: memReads, MemLast: memLast, ASRActive: asr.Active(), ASRTotal: len(asr.Rules), ExtScanned: scanned, ExtRisky: ext, MainUserAdmin: admin, MainUserUnknown: adminErr != nil, Audit: audit.IsEnabled(), Hardened: hardening.Applied(), Hello: s.helloEnabled()}
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

// Расширения Chromium проверяются, когда защищённый браузер запускается и его профиль уже расшифрован: только тогда
// служба видит их файлы. Результат живёт в памяти до следующего запуска браузера или перезапуска службы.
func (s *Service) scanExtensions(p profiles.Profile) {
	if p.Decoy != "chromium" {
		return
	}
	dir := filepath.Join(isolation.WorkPath(p.Name), p.DataDir)
	// Профиль принадлежит приложению под vault, а читает его служба с высокими правами: подменённый каталог не сканируем.
	if err := decoy.NoReparse(dir); err != nil {
		s.log.Printf("%s: расширения не проверены: %v", p.Name, err)
		return
	}
	res := extscan.Scan(dir)
	s.mu.Lock()
	if s.ext == nil {
		s.ext = map[string]extscan.Result{}
	}
	s.ext[p.Name] = res
	s.mu.Unlock()
	checkMu.Lock()
	lastCheck = "" // отчёт должен учесть свежий результат, а не кеш
	checkMu.Unlock()
	s.log.Printf("%s: расширений проверено %d, с доступом к cookies и ко всем сайтам %d", p.Name, res.Checked, len(res.Risky))
}

// Проверенные браузеры и «Название (браузер)» для расширений с доступом к cookies и ко всем сайтам.
func (s *Service) extensionsState() (risky, scanned []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for browser, res := range s.ext {
		scanned = append(scanned, browser)
		for _, f := range res.Risky {
			risky = append(risky, f.Name+" ("+browser+")")
		}
	}
	sort.Strings(scanned)
	sort.Strings(risky)
	return risky, scanned
}
