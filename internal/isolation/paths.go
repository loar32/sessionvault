package isolation

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Общая учётка приложений до v0.19: при обновлении заменяется учётками sv-<имя> и удаляется.
const LegacyVaultUser = "vault"

// ProgramData, если задан, подменяет системный каталог: только для тестов, которые не должны трогать настоящий.
var ProgramData string

// Системные каталоги берём у Windows, а не из переменных окружения: служба и установщик работают с высокими правами.
func KnownDir(id *windows.KNOWNFOLDERID, fallback string) string {
	if p, err := windows.KnownFolderPath(id, windows.KF_FLAG_DEFAULT); err == nil && p != "" {
		return p
	}
	return fallback
}

func BaseDir() string {
	pd := ProgramData
	if pd == "" {
		pd = KnownDir(windows.FOLDERID_ProgramData, `C:\ProgramData`)
	}
	return filepath.Join(pd, "SessionVault")
}

func VaultDir() string { return filepath.Join(BaseDir(), "vault") }

// Каталог профиля: метаданные хранилища, доступ только админам и SYSTEM.
func DataPath(profile string) string { return filepath.Join(VaultDir(), profile) }

// Рабочая папка приложения (-workdir): единственное место, куда есть доступ у его учётки.
func WorkPath(profile string) string { return filepath.Join(DataPath(profile), "work") }

func ProfilesDir() string { return filepath.Join(BaseDir(), "profiles") }

func ConfigPath() string { return filepath.Join(BaseDir(), "config.json") }

func legacyPasswordFile() string { return filepath.Join(BaseDir(), "vault.pwd") }
