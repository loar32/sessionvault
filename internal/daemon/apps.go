//go:build linux

package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"

	"github.com/loar32/sessionvault/internal/i18n"
	"github.com/loar32/sessionvault/internal/profiles"
)

// App — приложение, которое защищает Linux-версия. Внутри песочницы дом приложения смонтирован на место домашнего
// каталога владельца, поэтому данные лежат по тем же относительным путям, что и раньше (Dirs).
type App struct {
	Name  string `json:"name"`
	Title string `json:"title"`
	// Пути запуска по порядку; берётся первый существующий. Все они принадлежат root (пакет или копия SessionVault).
	Exe []string `json:"exe"`
	// Исполняемые файлы процессов приложения: им разрешено открывать свою приманку (браузер, запущенный в обход
	// SessionVault, это делает) без тревоги.
	Images []string `json:"images,omitempty"`
	Dirs   []string `json:"dirs"`           // папки данных относительно домашнего каталога владельца
	Args   []string `json:"args,omitempty"` // аргументы запуска в песочнице
	Flags  string   `json:"-"`              // файл флагов браузера в ~/.config: из него берутся только безопасные флаги
	// Ярлыки в /usr/share/applications, которые подменяются ярлыком SessionVault.
	Desktop []string `json:"desktop,omitempty"`
	Decoy   string   `json:"decoy"`             // раскладка приманки
	Browser bool     `json:"browser,omitempty"` // открывает ссылки и веб-приложения
	// Браузер на Chromium: веб-приложения открываются через --app=, в песочнице свои флаги (browserArgs).
	Chromium bool `json:"chromium,omitempty"`
	// Схемы ссылок, которые приложение открывает само (tg://, discord://), кроме http и https у браузеров.
	Schemes []string `json:"schemes,omitempty"`
	// Пути внутри каждой папки данных, которые не шифруются (кэши): при закрытии приложения они удаляются.
	Exclude []string `json:"exclude,omitempty"`

	Custom bool   `json:"custom,omitempty"` // добавлено командой add
	Source string `json:"source,omitempty"` // откуда скопирована программа (sessionvault refresh копирует заново)
	Kind   string `json:"kind,omitempty"`   // как скопирована: file, dir или appimage
	Icon   string `json:"icon,omitempty"`
	// Имена, по которым находятся папки данных приложения (папки, созданные после первого запуска, тоже).
	Match []string `json:"match,omitempty"`
	// Папки владельца, открытые приложению (абсолютные пути); у встроенных хранятся в том же app.json.
	Shares []string `json:"shares,omitempty"`
	// Ярлыки владельца (в ~/.local/share/applications, ~/.config/autostart), переписанные на SessionVault.
	Rewritten []string `json:"rewritten,omitempty"`
}

// Кэши Chromium пересоздаются сами и в хранилище не попадают.
// Шаблоны считаются от папки данных; `*/` — любой профиль браузера (Default, Profile 1, ...).
var chromiumExclude = []string{
	"*/Cache", "*/Code Cache", "*/GPUCache", "*/DawnCache", "*/DawnGraphiteCache", "*/DawnWebGPUCache", "*/Media Cache",
	"*/Service Worker/CacheStorage",
	"GrShaderCache", "ShaderCache", "GraphiteDawnCache", "Crash Reports", "BrowserMetrics", "DeferredBrowserMetrics",
	"component_crx_cache", "extensions_crx_cache", "optimization_guide_model_store",
}

// Кэши Electron (Discord и добавленные приложения на Electron).
var electronExclude = []string{
	"Cache", "Code Cache", "GPUCache", "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache", "Crashpad",
	"Service Worker/CacheStorage", "blob_storage", "VideoDecodeStats",
}

// Без --disable-background-mode браузер остаётся в фоне после закрытия окон, и данные остаются расшифрованными.
// Хранилище паролей и кук (--password-store) берётся из файла флагов владельца: ключ лежит в его связке ключей, и шина
// в песочнице её пропускает — входы на сайтах после защиты сохраняются.
var browserArgs = []string{"--ozone-platform=wayland", "--disable-background-mode", "--no-default-browser-check"}

var Apps = []App{
	{
		Name: "telegram", Title: "Telegram",
		Exe:     []string{"/usr/bin/telegram-desktop", "/opt/telegram/Telegram"},
		Images:  []string{"/usr/bin/telegram-desktop", "/opt/telegram/Telegram"},
		Dirs:    []string{".local/share/TelegramDesktop"},
		Desktop: []string{"org.telegram.desktop.desktop", "telegramdesktop.desktop"},
		Decoy:   "telegram",
		Schemes: []string{"tg"},
		Exclude: []string{"tdata/user_data/cache", "tdata/user_data/media_cache", "tdata/emoji"},
	},
	{
		Name: "chromium", Title: "Chromium",
		Exe:     []string{"/usr/bin/chromium"},
		Images:  []string{"/usr/lib/chromium/chromium"},
		Dirs:    []string{".config/chromium"},
		Args:    browserArgs,
		Flags:   "chromium-flags.conf",
		Desktop: []string{"chromium.desktop"},
		Decoy:   "chromium",
		Browser: true, Chromium: true,
		Exclude: chromiumExclude,
	},
	{
		Name: "brave", Title: "Brave",
		Exe:     []string{"/usr/bin/brave", "/usr/bin/brave-browser", "/opt/brave-bin/brave", "/opt/brave.com/brave/brave-browser"},
		Images:  []string{"/opt/brave-bin/brave", "/opt/brave.com/brave/brave", "/usr/lib/brave-browser/brave"},
		Dirs:    []string{".config/BraveSoftware/Brave-Browser"},
		Args:    browserArgs,
		Flags:   "brave-flags.conf",
		Desktop: []string{"brave-browser.desktop", "com.brave.Browser.desktop"},
		Decoy:   "chromium",
		Browser: true, Chromium: true,
		Exclude: chromiumExclude,
	},
	{
		Name: "chrome", Title: "Google Chrome",
		Exe:     []string{"/usr/bin/google-chrome-stable", "/opt/google/chrome/google-chrome"},
		Images:  []string{"/opt/google/chrome/chrome"},
		Dirs:    []string{".config/google-chrome"},
		Args:    browserArgs,
		Flags:   "chrome-flags.conf",
		Desktop: []string{"google-chrome.desktop"},
		Decoy:   "chromium",
		Browser: true, Chromium: true,
		Exclude: chromiumExclude,
	},
	{
		Name: "discord", Title: "Discord",
		Exe:     []string{"/usr/bin/discord", "/opt/discord/Discord"},
		Images:  []string{"/opt/discord/Discord", "/usr/lib/discord/Discord", "/usr/share/discord/Discord"},
		Dirs:    []string{".config/discord"},
		Args:    []string{"--ozone-platform=wayland"},
		Desktop: []string{"discord.desktop"},
		Decoy:   "discord",
		Schemes: []string{"discord"},
		Exclude: electronExclude,
	},
}

func appFile(name string) string { return filepath.Join(AppDir(name), "app.json") }

// HomeExclude — исключения от корня дома приложения: кэши, которые программы кладут вне своих данных, и кэши в каждой
// папке данных.
func (a App) HomeExclude() []string {
	out := []string{".cache", "Downloads"}
	for _, d := range a.Dirs {
		for _, x := range a.Exclude {
			out = append(out, filepath.Join(d, x))
		}
	}
	return out
}

func builtin(name string) (App, bool) {
	for _, a := range Apps {
		if a.Name == name {
			return a, true
		}
	}
	return App{}, false
}

// loadApp читает app.json. Файл пишет только root, каталог приложения закрыт от записи: подменить его владелец не может.
func loadApp(name string) (App, bool) {
	b, err := os.ReadFile(appFile(name))
	if err != nil {
		return App{}, false
	}
	var a App
	if json.Unmarshal(b, &a) != nil || a.Name != name {
		return App{}, false
	}
	return a, true
}

// FindApp — встроенное приложение (с папками, открытыми ему через share) или добавленное командой add.
func FindApp(name string) (App, bool) {
	if !profiles.ValidName(name) {
		return App{}, false
	}
	if a, ok := builtin(name); ok {
		if saved, ok := loadApp(name); ok {
			a.Shares, a.Rewritten = saved.Shares, saved.Rewritten
		}
		return a, true
	}
	a, ok := loadApp(name)
	if !ok || !a.Custom || len(a.Exe) == 0 {
		return App{}, false
	}
	return a, true
}

// SaveApp записывает app.json: у добавленного приложения — описание целиком, у встроенного — только его настройки.
func SaveApp(a App) error {
	if !a.Custom {
		a = App{Name: a.Name, Shares: a.Shares, Rewritten: a.Rewritten}
	}
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(appFile(a.Name), b, 0o644)
}

// AllApps — встроенные и добавленные (у которых есть описание).
func AllApps() []App {
	out := slices.Clone(Apps)
	entries, _ := os.ReadDir(AppsDir())
	for _, e := range entries {
		if _, ok := builtin(e.Name()); ok {
			continue
		}
		if a, ok := FindApp(e.Name()); ok {
			out = append(out, a)
		}
	}
	return out
}

// AppNames — имена встроенных приложений через запятую, для сообщений.
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

// Protected — приложения, у которых есть хранилище, по имени.
func Protected() []App {
	var out []App
	for _, a := range AllApps() {
		if _, err := os.Stat(filepath.Join(AppDir(a.Name), "vault.json")); err == nil {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ProgramDir — копия программы добавленного приложения (её монтирует песочница), если она есть.
func (a App) ProgramDir() string {
	if !a.Custom || a.Kind == "" {
		return ""
	}
	return filepath.Join(AppDir(a.Name), "app")
}
