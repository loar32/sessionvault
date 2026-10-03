package profiles

import (
	"fmt"
	"strings"
	"syscall"
)

type Profile struct {
	Name       string
	Exe        string
	DataDir    string
	LaunchArgs []string
}

var Telegram = Profile{
	Name:       "telegram",
	Exe:        `C:\Program Files\Telegram Desktop\Telegram.exe`,
	DataDir:    "tdata",
	LaunchArgs: []string{"-workdir", "{data_path}"},
}

func Get(name string) (Profile, error) {
	if name == Telegram.Name {
		return Telegram, nil
	}
	return Profile{}, fmt.Errorf("неизвестный профиль %q", name)
}

// Командная строка собирается только из профиля: аргументы извне не принимаются.
func (p Profile) CommandLine(exe, dataPath string) string {
	parts := []string{syscall.EscapeArg(exe)}
	for _, a := range p.LaunchArgs {
		parts = append(parts, syscall.EscapeArg(strings.ReplaceAll(a, "{data_path}", dataPath)))
	}
	return strings.Join(parts, " ")
}
