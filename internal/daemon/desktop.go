//go:build linux

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Ярлык приложения в ~/.local/share/applications с тем же именем, что у системного, перекрывает его: лаунчер Omarchy,
// ссылки (xdg-open), браузер по умолчанию и веб-приложения (они берут первое слово Exec ярлыка браузера) запускают
// приложение через SessionVault.

func appsDir(cfg Config) string {
	return filepath.Join(cfg.OwnerHome, ".local", "share", "applications")
}

// overrideDesktop — системный ярлык с заменённой командой; если системного нет (приложение из архива), простой свой.
func overrideDesktop(a App) (name string, content []byte) {
	for _, n := range a.Desktop {
		b, err := os.ReadFile(filepath.Join("/usr/share/applications", n))
		if err != nil {
			continue
		}
		var out []string
		for _, line := range strings.Split(string(b), "\n") {
			switch {
			case strings.HasPrefix(line, "Exec="):
				_, rest, _ := strings.Cut(strings.TrimPrefix(line, "Exec="), " ")
				line = "Exec=" + Launcher(a.Name)
				if rest != "" {
					line += " " + rest
				}
			// Запуск через D-Bus и проверка TryExec обошли бы команду ярлыка.
			case strings.HasPrefix(line, "TryExec="), strings.HasPrefix(line, "DBusActivatable="):
				continue
			}
			out = append(out, line)
			if line == "[Desktop Entry]" {
				out = append(out, desktopMarker)
			}
		}
		return n, []byte(strings.Join(out, "\n"))
	}
	return a.Desktop[0], []byte(fmt.Sprintf("[Desktop Entry]\n%s\nType=Application\nName=%s\nExec=%s %%U\nIcon=%s\nTerminal=false\nCategories=Network;\n",
		desktopMarker, a.Title, Launcher(a.Name), a.Name))
}

func menuDesktop() []byte {
	return []byte(fmt.Sprintf("[Desktop Entry]\n%s\nType=Application\nName=SessionVault\nComment=%s\nExec=%s menu\nIcon=security-high\nTerminal=false\nCategories=System;Security;\n",
		desktopMarker, "Protected app sessions", BinPath))
}

func installDesktop(cfg Config, a App) error {
	name, content := overrideDesktop(a)
	if _, err := asOwner(cfg, content, "put", filepath.Join(appsDir(cfg), name)); err != nil {
		return err
	}
	// Ярлык-команда: имя вызова говорит, какое приложение запускать.
	_ = os.Remove(Launcher(a.Name))
	return os.Symlink(BinPath, Launcher(a.Name))
}

func removeDesktop(cfg Config, a App) {
	for _, n := range a.Desktop {
		_, _ = asOwner(cfg, nil, "del", filepath.Join(appsDir(cfg), n))
	}
	if fi, err := os.Lstat(Launcher(a.Name)); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		_ = os.Remove(Launcher(a.Name))
	}
}
