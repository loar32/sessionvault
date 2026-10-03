package profiles

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

type Profile struct {
	Name       string   `json:"name"`
	Exe        string   `json:"exe"`
	DataDir    string   `json:"data_dir"` // папка сессии внутри рабочей папки приложения
	LaunchArgs []string `json:"launch_args"`
}

// Шаблон, который установщик записывает в ProgramData; службе нужен только файл оттуда.
var Telegram = Profile{
	Name:       "telegram",
	Exe:        `C:\Program Files\Telegram Desktop\Telegram.exe`,
	DataDir:    "tdata",
	LaunchArgs: []string{"-workdir", "{data_path}"},
}

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
	if p.Name != name || !filepath.IsAbs(p.Exe) || !filepath.IsLocal(p.DataDir) {
		return Profile{}, fmt.Errorf("профиль %q повреждён", name)
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
