//go:build linux

// Package daemon — SessionVault для Linux: служба systemd от root, которая держит ключи хранилищ, запускает защищённые
// приложения под их учётками sv-<имя> в песочнице bubblewrap и следит за приманками.
package daemon

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"

	"github.com/loar32/sessionvault/internal/i18n"
)

const (
	BaseDir    = "/var/lib/sessionvault"
	RunDir     = "/run/sessionvault"
	SocketPath = RunDir + "/sock"
	BinPath    = "/usr/local/bin/sessionvault"
	UnitPath   = "/etc/systemd/system/sessionvault.service"

	homeName = "home" // расшифрованный дом приложения внутри его папки, он же DataName хранилища
)

func AppsDir() string           { return filepath.Join(BaseDir, "apps") }
func AppDir(name string) string { return filepath.Join(AppsDir(), name) }
func ExchangeDir() string       { return filepath.Join(BaseDir, "exchange") }
func ConfigPath() string        { return filepath.Join(BaseDir, "config.json") }
func LogPath() string           { return filepath.Join(BaseDir, "service.log") }
func AlertsPath() string        { return filepath.Join(BaseDir, "alerts.log") }
func DecoysPath() string        { return filepath.Join(BaseDir, "decoys.json") }

// Launcher — команда-ярлык приложения: по имени вызова sessionvault понимает, какое приложение запускать
// (веб-приложения Omarchy берут из ярлыка браузера только первое слово команды).
func Launcher(name string) string { return BinPath + "-" + name }

type Config struct {
	Owner       int    `json:"owner"` // uid основной учётки: только её процессам (и root) открыт сокет
	OwnerName   string `json:"owner_name"`
	OwnerHome   string `json:"owner_home"`
	IdleMinutes int    `json:"idle_minutes,omitempty"`
	Language    string `json:"language,omitempty"`
	// Исполняемые файлы, которым разрешено читать приманку без тревоги (например, программа резервного копирования).
	DecoyAllow []string `json:"decoy_allow,omitempty"`
}

func LoadConfig() (Config, error) {
	var c Config
	b, err := os.ReadFile(ConfigPath())
	if errors.Is(err, os.ErrNotExist) {
		return c, errors.New(i18n.T("SessionVault не установлен: выполните sudo sessionvault install"))
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if c.Owner <= 0 || c.OwnerHome == "" {
		return c, errors.New(i18n.T("config.json повреждён: нет основной учётки"))
	}
	return c, nil
}

func SaveConfig(c Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(ConfigPath(), b, 0o600)
}

func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".tmp." + strconv.Itoa(os.Getpid())
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
