package i18n

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func userLanguageFile() string {
	return filepath.Join(os.Getenv("LOCALAPPDATA"), "SessionVault", "language")
}

func russianSystem() bool {
	id, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetUserDefaultUILanguage").Call()
	switch id & 0x3ff { // основной язык: 0x19 русский, 0x22 украинский, 0x23 белорусский
	case 0x19, 0x22, 0x23:
		return true
	}
	return false
}
