package service

import (
	"encoding/json"
	"os"

	"github.com/loar32/sessionvault/internal/isolation"
)

type Config struct {
	MainUser    string `json:"main_user"`
	IdleMinutes int    `json:"idle_minutes"`
	// Откуда импортирована папка данных профиля: при удалении данные возвращаются туда.
	Origins map[string]string `json:"origins,omitempty"`
}

const defaultIdleMinutes = 15

func LoadConfig() (Config, error) {
	var c Config
	b, err := os.ReadFile(isolation.ConfigPath())
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if c.IdleMinutes <= 0 {
		c.IdleMinutes = defaultIdleMinutes
	}
	return c, nil
}

func SaveConfig(c Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(isolation.ConfigPath(), b, 0o644)
}
