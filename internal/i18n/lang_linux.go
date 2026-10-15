package i18n

import (
	"os"
	"path/filepath"
	"strings"
)

func userLanguageFile() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		dir = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(dir, "sessionvault", "language")
}

// Язык из переменных локали в порядке их силы: LC_ALL, LC_MESSAGES, LANG.
func russianSystem() bool {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" {
			return strings.HasPrefix(v, "ru") || strings.HasPrefix(v, "uk") || strings.HasPrefix(v, "be")
		}
	}
	return false
}
