package service

import (
	"fmt"
	"sort"
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
	running, closing := s.running[name], s.closing[name]
	s.mu.Unlock()
	if closing {
		return ipc.Busy
	}
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

// runningList — имена запущенных защищённых приложений: по ним трей показывает пункты «Закрыть».
func (s *Service) runningList() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var names []string
	for n := range s.running {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// closeApp завершает процессы приложения: данные шифруются, как при обычном выходе. Нужно, например, Discord, который
// при закрытии окна уходит в трей и держит данные расшифрованными. Закрывать приложение может основная учётка — она его и запускает.
func (s *Service) closeApp(name string) string {
	s.mu.Lock()
	up := s.running[name]
	s.mu.Unlock()
	if !up {
		return ipc.Failed
	}
	n, err := isolation.KillAccountProcesses(isolation.AccountName(name))
	if err != nil || n == 0 {
		s.log.Printf("закрытие %s: процессов %d, %v", name, n, err)
		return ipc.Failed
	}
	s.log.Printf("%s закрыто по запросу пользователя (процессов: %d)", name, n)
	return ipc.Ok
}
