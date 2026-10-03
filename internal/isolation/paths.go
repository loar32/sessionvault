package isolation

import (
	"os"
	"path/filepath"
)

const VaultUser = "vault"

func BaseDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "SessionVault")
}

func VaultDir() string { return filepath.Join(BaseDir(), "vault") }

// Каталог профиля: метаданные хранилища, доступ только админам и SYSTEM.
func DataPath(profile string) string { return filepath.Join(VaultDir(), profile) }

// Рабочая папка приложения (-workdir): единственное место, куда у vault есть доступ.
func WorkPath(profile string) string { return filepath.Join(DataPath(profile), "work") }

func ProfilesDir() string { return filepath.Join(BaseDir(), "profiles") }

func ConfigPath() string { return filepath.Join(BaseDir(), "config.json") }

func passwordFile() string { return filepath.Join(BaseDir(), "vault.pwd") }
