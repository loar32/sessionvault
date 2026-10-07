package profiles

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/loar32/sessionvault/internal/i18n"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

type Profile struct {
	Name       string   `json:"name"`
	Exe        string   `json:"exe"`
	DataDir    string   `json:"data_dir"` // папка сессии внутри рабочей папки приложения
	LaunchArgs []string `json:"launch_args"`
	// Издатель в подписи Authenticode: установщик не примет exe с другой подписью.
	Publisher string `json:"publisher,omitempty"`
	Title     string `json:"title,omitempty"` // название в меню трея
	// Прежнее место данных относительно профиля пользователя: там лежит приманка, туда возвращаются данные при удалении.
	Origin string `json:"origin,omitempty"`
	// Пути внутри DataDir, которые не шифруются (кэши): при закрытии приложения они удаляются.
	Exclude []string `json:"exclude,omitempty"`
	// Имена файлов (без пути), которые vault разрешено запускать из рабочей папки, если они подписаны ExecSigner;
	// всё остальное запускать нельзя.
	ExecFiles  []string `json:"exec_files,omitempty"`
	ExecSigner string   `json:"exec_signer,omitempty"`
	// Раскладка приманки: telegram, chromium или discord.
	Decoy string `json:"decoy,omitempty"`
	// Подпись профиля (HMAC); ставится при записи, проверяется при чтении.
	Sig string `json:"sig,omitempty"`
	// Каталог установки, из которого скопирован exe (приложение лежит в профиле пользователя, где у vault доступа нет):
	// `refresh` копирует его заново после обновления приложения.
	Source string `json:"source,omitempty"`
	// Профиль добавлен администратором командой add, а не взят из встроенных шаблонов.
	Custom bool `json:"custom,omitempty"`
	// Приложение (Steam), которое остаётся в учётке пользователя и держит сессию в его же папках: пока оно закрыто, эти
	// места пусты (приманка), данные лежат в хранилище; при запуске службой они возвращаются на место, при выходе убираются.
	Places []Place `json:"places,omitempty"`
}

// Place — одно место сессии в профиле пользователя или каталоге приложения.
type Place struct {
	Path string `json:"path"` // абсолютный путь
	// Шаблоны имён файлов прямо в Path (ssfn*); пусто — место целиком (вся папка Path).
	Files   []string `json:"files,omitempty"`
	Decoy   string   `json:"decoy,omitempty"`   // раскладка приманки на месте папки; у файлов приманки нет
	Exclude []string `json:"exclude,omitempty"` // пути внутри Path, которые не шифруются (кэши)
}

// Steam: сессия лежит в каталоге клиента (config, ssfn*) и в %LOCALAPPDATA%\Steam (htmlcache). Клиент и игры остаются в
// учётке пользователя, поэтому места и путь к exe служба находит при защите (protect steam).
var Steam = Profile{
	Name:      "steam",
	DataDir:   "places",
	Publisher: "Valve Corp.",
	Title:     "Steam",
}

// Шаблон, который установщик записывает в ProgramData; службе нужен только файл оттуда.
var Telegram = Profile{
	Name:       "telegram",
	Exe:        `C:\Program Files\Telegram Desktop\Telegram.exe`,
	DataDir:    "tdata",
	LaunchArgs: []string{"-workdir", "{data_path}"},
	Publisher:  "Telegram FZ-LLC",
	Title:      "Telegram",
	Origin:     `AppData\Roaming\Telegram Desktop\tdata`,
	Decoy:      "telegram",
}

// Discord ставится в профиль пользователя (%LOCALAPPDATA%\Discord\app-<версия>): путь к exe находит служба при защите,
// каталог копируется под vault. Это Electron: папку данных задаёт --user-data-dir. Токен лежит в Local Storage и зашифрован ключом
// DPAPI учётки, поэтому профиль новый (вход заново), как у браузеров.
var Discord = Profile{
	Name:       "discord",
	DataDir:    "discord",
	LaunchArgs: []string{`--user-data-dir={data_path}\discord`},
	Publisher:  "Discord Inc.",
	Title:      "Discord",
	Origin:     `AppData\Roaming\discord`,
	Decoy:      "discord",
	Exclude: []string{
		"Cache", "Code Cache", "GPUCache", "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache", "Crashpad",
		`Service Worker\CacheStorage`, "blob_storage", "VideoDecodeStats",
	},
}

var (
	chromiumExecFiles  = []string{"widevinecdm.dll"}
	chromiumExecSigner = "Google LLC"
)

// Кэши Chromium пересоздаются сами: шифровать их незачем, а архив держится в памяти целиком.
// `*\` — в любом профиле браузера (Default, Profile 1, ...).
var chromiumExclude = []string{
	`*\Cache`, `*\Code Cache`, `*\GPUCache`, `*\DawnCache`, `*\DawnGraphiteCache`, `*\DawnWebGPUCache`, `*\Media Cache`,
	`*\Service Worker\CacheStorage`,
	`GrShaderCache`, `ShaderCache`, `GraphiteDawnCache`, `Crashpad`, `BrowserMetrics`, `DeferredBrowserMetrics`,
	`component_crx_cache`, `extensions_crx_cache`, `optimization_guide_model_store`,
}

// Браузер ставится и в Program Files, и в Program Files (x86); x86 — где его обычно ждут. Берём тот путь, где файл есть.
func chromium(name, title, exe, publisher, origin string, x86 bool) Profile {
	pf64 := knownDir(windows.FOLDERID_ProgramFiles, `C:\Program Files`)
	pf86 := knownDir(windows.FOLDERID_ProgramFilesX86, `C:\Program Files (x86)`)
	first, second := pf64, pf86
	if x86 {
		first, second = pf86, pf64
	}
	pf := first
	if _, err := os.Stat(filepath.Join(first, exe)); err != nil {
		if _, err := os.Stat(filepath.Join(second, exe)); err == nil {
			pf = second
		}
	}
	return Profile{
		Name:    name,
		Title:   title,
		Exe:     filepath.Join(pf, exe),
		DataDir: "User Data",
		// Без --disable-background-mode браузер остаётся в фоне после закрытия окон, и данные остаются расшифрованными.
		LaunchArgs: []string{`--user-data-dir={data_path}\User Data`, "--disable-background-mode", "--no-default-browser-check"},
		Publisher:  publisher,
		Origin:     origin,
		Exclude:    chromiumExclude,
		// Модуль видео с защитой от копирования (Widevine) лежит в профиле и грузится оттуда.
		ExecFiles:  chromiumExecFiles,
		ExecSigner: chromiumExecSigner,
		Decoy:      "chromium",
	}
}

func knownDir(id *windows.KNOWNFOLDERID, fallback string) string {
	if p, err := windows.KnownFolderPath(id, windows.KF_FLAG_DEFAULT); err == nil && p != "" {
		return p
	}
	return fallback
}

// Template — шаблон защищаемого приложения по имени; false, если такого нет.
func Template(name string) (Profile, bool) {
	switch name {
	case "telegram":
		return Telegram, true
	case "chrome":
		return chromium(name, "Google Chrome", `Google\Chrome\Application\chrome.exe`, "Google LLC",
			`AppData\Local\Google\Chrome\User Data`, false), true
	case "edge":
		return chromium(name, "Microsoft Edge", `Microsoft\Edge\Application\msedge.exe`, "Microsoft Corporation",
			`AppData\Local\Microsoft\Edge\User Data`, true), true
	case "discord":
		return Discord, true
	case "steam":
		return Steam, true
	case "brave":
		return chromium(name, "Brave", `BraveSoftware\Brave-Browser\Application\brave.exe`, "Brave Software, Inc.",
			`AppData\Local\BraveSoftware\Brave-Browser\User Data`, false), true
	}
	return Profile{}, false
}

// TemplateNames — имена всех шаблонов.
func TemplateNames() []string {
	return []string{"telegram", "chrome", "edge", "brave", "discord", "steam"}
}

var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func ValidName(name string) bool { return validName.MatchString(name) }

func Load(dir, name string) (Profile, error) {
	p, err := load(dir, name)
	if err != nil {
		return Profile{}, err
	}
	if RequireSignature {
		if err := p.verify(dir); err != nil {
			return Profile{}, fmt.Errorf(i18n.T("профиль %q: %w"), name, err)
		}
	}
	return p.withDefaults(), nil
}

// load читает и проверяет профиль без проверки подписи и без дополнений для прежних версий: подпись считается по тому, что в файле.
func load(dir, name string) (Profile, error) {
	if !ValidName(name) {
		return Profile{}, fmt.Errorf(i18n.T("недопустимое имя профиля %q"), name)
	}
	b, err := os.ReadFile(filepath.Join(dir, name+".json"))
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF}) // BOM, который добавляют некоторые редакторы и PowerShell
	if err != nil {
		return Profile{}, fmt.Errorf(i18n.T("неизвестный профиль %q"), name)
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		return Profile{}, fmt.Errorf(i18n.T("профиль %q повреждён: %w"), name, err)
	}
	if p.Name != name || !filepath.IsAbs(p.Exe) || !filepath.IsLocal(p.DataDir) || (p.Origin != "" && !filepath.IsLocal(p.Origin)) {
		return Profile{}, fmt.Errorf(i18n.T("профиль %q повреждён"), name)
	}
	if p.Decoy != "" && p.Decoy != "telegram" && p.Decoy != "chromium" && p.Decoy != "discord" && p.Decoy != "generic" {
		return Profile{}, fmt.Errorf(i18n.T("профиль %q: неизвестная раскладка приманки %q"), name, p.Decoy)
	}
	for _, x := range p.Exclude {
		if !filepath.IsLocal(x) {
			return Profile{}, fmt.Errorf(i18n.T("профиль %q: недопустимый путь исключения %q"), name, x)
		}
	}
	for _, pl := range p.Places {
		if !filepath.IsAbs(pl.Path) || (pl.Decoy != "" && pl.Decoy != "steamconfig" && pl.Decoy != "steamlocal") {
			return Profile{}, fmt.Errorf(i18n.T("профиль %q повреждён"), name)
		}
		for _, x := range append(slices.Clone(pl.Files), pl.Exclude...) {
			if x == "" || !filepath.IsLocal(x) {
				return Profile{}, fmt.Errorf(i18n.T("профиль %q: недопустимый путь исключения %q"), name, x)
			}
		}
	}
	for _, x := range p.ExecFiles {
		if x == "" || filepath.Base(x) != x {
			return Profile{}, fmt.Errorf(i18n.T("профиль %q: недопустимое имя файла %q"), name, x)
		}
	}
	return p, nil
}

func (p Profile) withDefaults() Profile {
	// Браузер, защищённый до v0.13, не знает про исключение для Widevine.
	if p.Decoy == "chromium" && p.ExecFiles == nil {
		p.ExecFiles, p.ExecSigner = chromiumExecFiles, chromiumExecSigner
	}
	// Профиль Telegram, записанный до появления этих полей.
	if p.Name == Telegram.Name && p.Origin == "" {
		p.Origin, p.Decoy = Telegram.Origin, Telegram.Decoy
		if p.Title == "" {
			p.Title = Telegram.Title
		}
	}
	if p.Title == "" {
		p.Title = p.Name
	}
	return p
}

// Save подписывает профиль и записывает его; создаёт ключ подписи при первой записи.
func Save(dir string, p Profile) error {
	key, err := loadKey(dir, true)
	if err != nil {
		return err
	}
	p.Sig = p.signature(key)
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, p.Name+".json"), b, 0o644)
}

// Командная строка собирается только из профиля; ссылку для браузера (ipc.ValidURL) добавляет вызывающий.
func (p Profile) CommandLine(workDir string) string {
	parts := []string{syscall.EscapeArg(p.Exe)}
	for _, a := range p.LaunchArgs {
		parts = append(parts, syscall.EscapeArg(strings.ReplaceAll(a, "{data_path}", workDir)))
	}
	return strings.Join(parts, " ")
}
