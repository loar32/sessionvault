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

func DataPath(profile string) string { return filepath.Join(VaultDir(), profile) }

func passwordFile() string { return filepath.Join(BaseDir(), "vault.pwd") }
