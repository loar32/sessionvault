package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/loar32/sessionvault/internal/isolation"
	"golang.org/x/sys/windows"
)

type Config struct {
	MainUser    string `json:"main_user"`
	IdleMinutes int    `json:"idle_minutes"`
	// Откуда импортирована папка данных профиля: при удалении данные возвращаются туда.
	Origins map[string]string `json:"origins,omitempty"`
	// Аудит файловой системы включила служба (а не он уже был): при удалении возвращаем как было.
	AuditByUs  bool    `json:"audit_by_us,omitempty"`
	DecoyAllow []Allow `json:"decoy_allow,omitempty"`
	// Профиль браузера для ссылок (sessionvault open); по умолчанию первый из chrome, edge, brave.
	LinkProfile string `json:"link_profile,omitempty"`
	// Прежние значения системных мер (hardening): при удалении они возвращаются.
	Hardening map[string]int64 `json:"hardening,omitempty"`
}

// Блокировка по бездействию — страховка на случай, если событие Windows (блокировка сеанса, сон) не пришло.
// Отрицательное значение в config.json выключает таймер.
const defaultIdleMinutes = 240

func idleDuration(minutes int) time.Duration {
	if minutes < 0 {
		return 0
	}
	return time.Duration(minutes) * time.Minute
}

func LoadConfig() (Config, error) {
	var c Config
	b, err := os.ReadFile(isolation.ConfigPath())
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF}) // BOM, который добавляют некоторые редакторы и PowerShell
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if c.IdleMinutes == 0 {
		c.IdleMinutes = defaultIdleMinutes
	}
	return c, nil
}

// Запись через временный файл: читающий видит либо старый config.json целиком, либо новый.
func SaveConfig(c Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := isolation.ConfigPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, isolation.ConfigPath())
}

// Читает, меняет и пишет config.json под эксклюзивной блокировкой: служба и import-tdata — разные процессы
// и без неё затёрли бы изменения друг друга.
func UpdateConfig(change func(*Config)) error {
	release, err := lockConfig()
	if err != nil {
		return err
	}
	defer release()
	c, err := LoadConfig()
	if err != nil {
		return err
	}
	change(&c)
	return SaveConfig(c)
}

func lockConfig() (func(), error) {
	name, err := windows.UTF16PtrFromString(isolation.ConfigPath() + ".lock")
	if err != nil {
		return nil, err
	}
	for range 100 {
		h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err == nil {
			return func() { _ = windows.CloseHandle(h) }, nil
		}
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return nil, err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, errors.New("config.json занят другим процессом")
}
