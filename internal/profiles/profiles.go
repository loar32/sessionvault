package profiles

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	// Раскладка приманки: telegram или chromium.
	Decoy string `json:"decoy,omitempty"`
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

// Кэши Chromium пересоздаются сами: шифровать их незачем, а архив держится в памяти целиком.
var chromiumExclude = []string{
	`Default\Cache`, `Default\Code Cache`, `Default\GPUCache`, `Default\Service Worker\CacheStorage`,
	`GrShaderCache`, `ShaderCache`, `GraphiteDawnCache`, `Crashpad`,
}

func chromium(name, title, exe, publisher, origin string, x86 bool) Profile {
	pf := knownDir(windows.FOLDERID_ProgramFiles, `C:\Program Files`)
	if x86 {
		pf = knownDir(windows.FOLDERID_ProgramFilesX86, `C:\Program Files (x86)`)
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
	case "brave":
		return chromium(name, "Brave", `BraveSoftware\Brave-Browser\Application\brave.exe`, "Brave Software, Inc.",
			`AppData\Local\BraveSoftware\Brave-Browser\User Data`, false), true
	}
	return Profile{}, false
}

// TemplateNames — имена всех шаблонов.
func TemplateNames() []string { return []string{"telegram", "chrome", "edge", "brave"} }

var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func ValidName(name string) bool { return validName.MatchString(name) }

func Load(dir, name string) (Profile, error) {
	if !ValidName(name) {
		return Profile{}, fmt.Errorf("недопустимое имя профиля %q", name)
	}
	b, err := os.ReadFile(filepath.Join(dir, name+".json"))
	if err != nil {
		return Profile{}, fmt.Errorf("неизвестный профиль %q", name)
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		return Profile{}, fmt.Errorf("профиль %q повреждён: %w", name, err)
	}
	if p.Name != name || !filepath.IsAbs(p.Exe) || !filepath.IsLocal(p.DataDir) || (p.Origin != "" && !filepath.IsLocal(p.Origin)) {
		return Profile{}, fmt.Errorf("профиль %q повреждён", name)
	}
	if p.Decoy != "" && p.Decoy != "telegram" && p.Decoy != "chromium" {
		return Profile{}, fmt.Errorf("профиль %q: неизвестная раскладка приманки %q", name, p.Decoy)
	}
	for _, x := range p.Exclude {
		if !filepath.IsLocal(x) {
			return Profile{}, fmt.Errorf("профиль %q: недопустимый путь исключения %q", name, x)
		}
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
	return p, nil
}

func Save(dir string, p Profile) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, p.Name+".json"), b, 0o644)
}

// Командная строка собирается только из профиля: аргументы извне не принимаются.
func (p Profile) CommandLine(workDir string) string {
	parts := []string{syscall.EscapeArg(p.Exe)}
	for _, a := range p.LaunchArgs {
		parts = append(parts, syscall.EscapeArg(strings.ReplaceAll(a, "{data_path}", workDir)))
	}
	return strings.Join(parts, " ")
}
