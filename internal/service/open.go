package service

import (
	"fmt"
	"strings"
	"time"

	"github.com/loar32/sessionvault/internal/ipc"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"golang.org/x/sys/windows"
)

// Порядок выбора браузера для ссылок, если в config.json не задан link_profile.
var linkOrder = []string{"chrome", "edge", "brave"}

func launchLine(exe, name, link string) string {
	if link == "" {
		return fmt.Sprintf(`"%s" launch %s`, exe, name)
	}
	return fmt.Sprintf(`"%s" launch %s %s`, exe, name, link)
}

// Браузер для ссылок: профиль из config.json или первый защищённый из linkOrder. Подходит только Chromium-профиль:
// остальные приложения ссылку открывать не умеют.
func (s *Service) linkProfile() (string, bool) {
	cfg, _ := LoadConfig()
	have := map[string]bool{}
	for _, n := range strings.Split(s.list(), ",") {
		have[n] = true
	}
	for _, n := range append([]string{cfg.LinkProfile}, linkOrder...) {
		if !have[n] {
			continue
		}
		if p, err := profiles.Load(isolation.ProfilesDir(), n); err == nil && p.Decoy == "chromium" {
			return n, true
		}
	}
	return "", false
}

// Ссылка открывается в защищённом браузере: заперто — окно разблокировки, уже запущен — Chromium сам откроет вкладку
// в работающем экземпляре того же профиля. Ссылка проверена ipc.ValidURL и попадает только в командную строку браузера.
func (s *Service) open(c *ipc.Conn) string {
	link, err := c.ReadLine(5*time.Second, ipc.MaxURL)
	if err != nil || ipc.ValidURL(link) != nil {
		return ipc.Failed
	}
	name, ok := s.linkProfile()
	if !ok {
		s.logRunFailure("open: нет защищённого браузера")
		return ipc.Failed
	}
	s.mu.Lock()
	running := s.running[name]
	s.mu.Unlock()
	if !running {
		return s.run(c, name, link)
	}
	session, err := c.ClientSession()
	if err != nil || session == 0 {
		return ipc.Failed
	}
	s.mu.Lock()
	ok = time.Since(s.lastOpen) >= runGap
	if ok {
		s.lastOpen = time.Now()
	}
	s.mu.Unlock()
	if !ok {
		return ipc.Busy
	}
	_, proc, _, err := isolation.StartInSession(session, launchLine(s.exe, name, link), false)
	if err != nil {
		s.log.Printf("open %s: %v", name, err)
		return ipc.Failed
	}
	_ = windows.CloseHandle(proc)
	return ipc.Ok
}
