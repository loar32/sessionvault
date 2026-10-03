package service

import (
	"os"
	"path/filepath"

	"github.com/loar32/sessionvault/internal/isolation"
)

// Установлена ли программа: пока конфига нет, удалять нечего.
func Installed() bool {
	_, err := os.Stat(isolation.ConfigPath())
	return err == nil
}

// Где Telegram Desktop хранит сессию по умолчанию.
func UserTdata(user string) string {
	return filepath.Join(usersDir(), user, `AppData\Roaming\Telegram Desktop\tdata`)
}
