//go:build linux

package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/loar32/sessionvault/internal/i18n"
)

// App — приложение, которое умеет защищать Linux-версия. Внутри песочницы дом приложения смонтирован на место домашнего
// каталога владельца, поэтому данные лежат по тем же относительным путям, что и раньше (Origin).
type App struct {
	Name  string
	Title string
	// Пути запуска по порядку; берётся первый существующий. Все они ставятся пакетами в каталоги root.
	Exe []string
	// Исполняемые файлы процессов приложения: им разрешено открывать свою приманку (браузер, запущенный в обход
	// SessionVault, это делает) без тревоги.
	Images  []string
	Origin  string   // каталог сессии относительно домашнего каталога владельца
	Args    []string // аргументы запуска в песочнице
	Flags   string   // файл флагов браузера в ~/.config: из него берутся только безопасные флаги
	Desktop []string // ярлыки приложения в /usr/share/applications, которые подменяются ярлыком SessionVault
	Decoy   string   // раскладка приманки
	Browser bool     // открывает ссылки и веб-приложения (--app=)
	// Пути внутри дома приложения, которые не шифруются (кэши): при закрытии приложения они удаляются.
	Exclude []string
}

// Кэши Chromium пересоздаются сами; архив держится в памяти целиком, поэтому они в него не попадают.
// Шаблоны считаются от каталога данных (Origin); `*/` — любой профиль браузера (Default, Profile 1, ...).
var chromiumExclude = []string{
	"*/Cache", "*/Code Cache", "*/GPUCache", "*/DawnCache", "*/DawnGraphiteCache", "*/DawnWebGPUCache", "*/Media Cache",
	"*/Service Worker/CacheStorage",
	"GrShaderCache", "ShaderCache", "GraphiteDawnCache", "Crash Reports", "BrowserMetrics", "DeferredBrowserMetrics",
	"component_crx_cache", "extensions_crx_cache", "optimization_guide_model_store",
}

// Без --disable-background-mode браузер остаётся в фоне после закрытия окон, и данные остаются расшифрованными.
// Пароли и куки браузер шифрует ключом из связки ключей сеанса; в песочнице её нет (нет шины сеанса), поэтому basic:
// на диске профиль и так зашифрован SessionVault, а читать его может только учётка приложения.
var browserArgs = []string{"--ozone-platform=wayland", "--password-store=basic", "--disable-background-mode", "--no-default-browser-check"}

var Apps = []App{
	{
		Name: "telegram", Title: "Telegram",
		Exe:     []string{"/usr/bin/telegram-desktop", "/opt/telegram/Telegram"},
		Images:  []string{"/usr/bin/telegram-desktop", "/opt/telegram/Telegram"},
		Origin:  ".local/share/TelegramDesktop",
		Desktop: []string{"org.telegram.desktop.desktop", "telegramdesktop.desktop"},
		Decoy:   "telegram",
		Exclude: []string{"tdata/user_data/cache", "tdata/user_data/media_cache", "tdata/emoji"},
	},
	{
		Name: "chromium", Title: "Chromium",
		Exe:     []string{"/usr/bin/chromium"},
		Images:  []string{"/usr/lib/chromium/chromium"},
		Origin:  ".config/chromium",
		Args:    browserArgs,
		Flags:   "chromium-flags.conf",
		Desktop: []string{"chromium.desktop"},
		Decoy:   "chromium",
		Browser: true,
		Exclude: chromiumExclude,
	},
	{
		Name: "brave", Title: "Brave",
		Exe:     []string{"/usr/bin/brave", "/usr/bin/brave-browser", "/opt/brave-bin/brave", "/opt/brave.com/brave/brave-browser"},
		Images:  []string{"/opt/brave-bin/brave", "/opt/brave.com/brave/brave", "/usr/lib/brave-browser/brave"},
		Origin:  ".config/BraveSoftware/Brave-Browser",
		Args:    browserArgs,
		Flags:   "brave-flags.conf",
		Desktop: []string{"brave-browser.desktop", "com.brave.Browser.desktop"},
		Decoy:   "chromium",
		Browser: true,
		Exclude: chromiumExclude,
	},
	{
		Name: "chrome", Title: "Google Chrome",
		Exe:     []string{"/usr/bin/google-chrome-stable", "/opt/google/chrome/google-chrome"},
		Images:  []string{"/opt/google/chrome/chrome"},
		Origin:  ".config/google-chrome",
		Args:    browserArgs,
		Flags:   "chrome-flags.conf",
		Desktop: []string{"google-chrome.desktop"},
		Decoy:   "chromium",
		Browser: true,
		Exclude: chromiumExclude,
	},
	{
		Name: "discord", Title: "Discord",
		Exe:     []string{"/usr/bin/discord", "/opt/discord/Discord"},
		Images:  []string{"/opt/discord/Discord", "/usr/lib/discord/Discord", "/usr/share/discord/Discord"},
		Origin:  ".config/discord",
		Args:    []string{"--ozone-platform=wayland"},
		Desktop: []string{"discord.desktop"},
		Decoy:   "discord",
		Exclude: []string{
			"Cache", "Code Cache", "GPUCache", "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache", "Crashpad",
			"Service Worker/CacheStorage", "blob_storage", "VideoDecodeStats",
		},
	},
}

// HomeExclude — исключения от корня дома приложения: кэши, которые программы кладут вне своих данных.
func (a App) HomeExclude() []string {
	out := []string{".cache", "Downloads"}
	for _, x := range a.Exclude {
		out = append(out, filepath.Join(a.Origin, x))
	}
	return out
}

func FindApp(name string) (App, bool) {
	for _, a := range Apps {
		if a.Name == name {
			return a, true
		}
	}
	return App{}, false
}

// AppNames — имена через запятую, для сообщений.
func AppNames() string {
	var n []string
	for _, a := range Apps {
		n = append(n, a.Name)
	}
	return strings.Join(n, ", ")
}

// FindExe — первый установленный путь запуска. Файл и все каталоги над ним должны принадлежать root и не быть открытыми
// на запись другим: иначе процесс основной учётки подменил бы программу, которая получит расшифрованные данные.
func (a App) FindExe() (string, error) {
	for _, p := range a.Exe {
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			continue
		}
		if err := rootOwned(real); err != nil {
			return "", fmt.Errorf("%s: %w", p, err)
		}
		return p, nil
	}
	return "", fmt.Errorf(i18n.T("%s не установлен (искал: %s)"), a.Title, strings.Join(a.Exe, ", "))
}

func rootOwned(path string) error {
	for p := path; ; p = filepath.Dir(p) {
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || (fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0) {
			return errors.New(i18n.T("файл или каталог над ним может изменить не только root"))
		}
		if p == "/" {
			return nil
		}
	}
}

// Protected — приложения, у которых есть хранилище.
func Protected() []App {
	var out []App
	for _, a := range Apps {
		if _, err := os.Stat(filepath.Join(AppDir(a.Name), "vault.json")); err == nil {
			out = append(out, a)
		}
	}
	return out
}
