// Package i18n — перевод интерфейса. Исходный язык — русский: T возвращает строку как есть, а при английском
// интерфейсе берёт перевод из таблицы en; строки без перевода остаются русскими, поэтому недостающий перевод ничего не ломает.
package i18n

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
)

var english atomic.Bool

// Init выбирает язык ("ru" или "en"): файл %LOCALAPPDATA%\SessionVault\language (его читают трей и окна в сеансе пользователя:
// config.json им закрыт), затем поле language в config.json (служба и администратор), иначе язык интерфейса Windows
// (русский, украинский, белорусский — русский, остальные — английский). Без вызова Init (например, в тестах) интерфейс русский.
func Init(configPath string) {
	if b, err := os.ReadFile(userLanguageFile()); err == nil && set(string(b)) {
		return
	}
	if b, err := os.ReadFile(configPath); err == nil {
		var c struct {
			Language string `json:"language"`
		}
		if json.Unmarshal(bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF}), &c) == nil && set(c.Language) {
			return
		}
	}
	english.Store(!russianSystem())
}

func set(lang string) bool {
	switch strings.ToLower(strings.TrimSpace(lang)) {
	case "ru":
		english.Store(false)
		return true
	case "en":
		english.Store(true)
		return true
	}
	return false
}

// English — интерфейс сейчас английский.
func English() bool { return english.Load() }

// SetEnglish включает английский интерфейс (для тестов и принудительного выбора).
func SetEnglish(on bool) { english.Store(on) }

// T возвращает перевод строки; при русском интерфейсе или отсутствии перевода — саму строку.
func T(ru string) string {
	if english.Load() {
		if s, ok := en[ru]; ok {
			return s
		}
	}
	return ru
}

// Tf — T с форматированием: перевод хранится в той же форме с %-подстановками.
func Tf(ru string, a ...any) string { return fmt.Sprintf(T(ru), a...) }
