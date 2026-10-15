//go:build linux

package daemon

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Ярлык приложения в ~/.local/share/applications с тем же именем, что у системного, перекрывает его: лаунчер Omarchy,
// ссылки (xdg-open), браузер по умолчанию и веб-приложения (они берут первое слово Exec ярлыка браузера) запускают
// приложение через SessionVault. Ярлыки самого владельца (свои и автозапуска), которые ведут к программе, переписываются
// на месте; прежний файл хранится в каталоге приложения и возвращается при снятии защиты.

func appsDir(cfg Config) string {
	return filepath.Join(cfg.OwnerHome, ".local", "share", "applications")
}
func autostartDir(cfg Config) string { return filepath.Join(cfg.OwnerHome, ".config", "autostart") }

// DesktopEntry — то, что SessionVault берёт из ярлыка (группа [Desktop Entry]).
type DesktopEntry struct {
	ID        string // имя файла
	Name      string
	Exec      string
	Icon      string
	WMClass   string
	MimeTypes []string
	Terminal  bool
	NoDisplay bool
	Type      string
}

func ParseDesktop(id string, b []byte) DesktopEntry {
	e := DesktopEntry{ID: id}
	in := false
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			in = line == "[Desktop Entry]"
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !in || !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "Name":
			e.Name = v
		case "Exec":
			e.Exec = v
		case "Icon":
			e.Icon = v
		case "StartupWMClass":
			e.WMClass = v
		case "MimeType":
			for _, m := range strings.Split(v, ";") {
				if m != "" {
					e.MimeTypes = append(e.MimeTypes, m)
				}
			}
		case "Terminal":
			e.Terminal = v == "true"
		case "NoDisplay", "Hidden":
			e.NoDisplay = e.NoDisplay || v == "true"
		case "Type":
			e.Type = v
		}
	}
	return e
}

// ExecArgv разбирает строку Exec по спецификации: кавычки, экранирование, коды полей (%u, %F и т. п.) убираются.
func ExecArgv(s string) []string {
	var out []string
	var cur strings.Builder
	have, quoted := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quoted && c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		case c == '"':
			quoted, have = !quoted, true
		case !quoted && (c == ' ' || c == '\t'):
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		case c == '%' && i+1 < len(s):
			i++
			if s[i] == '%' {
				cur.WriteByte('%')
				have = true
			}
		default:
			cur.WriteByte(c)
			have = true
		}
	}
	if have {
		out = append(out, cur.String())
	}
	return out
}

// execProgram — программа и её аргументы без «env VAR=значение».
func execProgram(argv []string) (string, []string) {
	if len(argv) > 0 && filepath.Base(argv[0]) == "env" {
		argv = argv[1:]
		for len(argv) > 0 && strings.Contains(argv[0], "=") && !strings.HasPrefix(argv[0], "-") {
			argv = argv[1:]
		}
	}
	if len(argv) == 0 {
		return "", nil
	}
	return argv[0], argv[1:]
}

// resolveProgram — настоящий путь программы из Exec (имя ищется в системных каталогах).
func resolveProgram(prog string) string {
	if !filepath.IsAbs(prog) {
		for _, d := range []string{"/usr/local/bin", "/usr/bin"} {
			if _, err := os.Stat(filepath.Join(d, prog)); err == nil {
				prog = filepath.Join(d, prog)
				break
			}
		}
	}
	if real, err := filepath.EvalSymlinks(prog); err == nil {
		return real
	}
	return prog
}

// launches — ярлык запускает программу этого приложения.
func launches(a App, e DesktopEntry) bool {
	prog, _ := execProgram(ExecArgv(e.Exec))
	if prog == "" || strings.HasPrefix(filepath.Base(prog), "sessionvault") {
		return false
	}
	real := resolveProgram(prog)
	for _, p := range append(append(slices.Clone(a.Exe), a.Images...), a.Source) {
		if p != "" && (p == prog || resolveProgram(p) == real) {
			return true
		}
	}
	return false
}

// rewriteDesktop заменяет программу во всех строках Exec (в том числе в действиях «Новое окно» и т. п.) на launcher.
func rewriteDesktop(b []byte, launcher string) []byte {
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(line, "Exec="):
			orig := strings.TrimPrefix(line, "Exec=")
			_, rest := execProgram(ExecArgv(orig))
			line = "Exec=" + launcher
			for _, arg := range rest {
				line += " " + quoteExec(arg)
			}
			if code := fieldCode(orig); code != "" {
				line += " " + code
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
	return []byte(strings.Join(out, "\n"))
}

// fieldCode — код, которым ярлык получает ссылку или файл: он сохраняется, остальные аргументы служба всё равно не берёт.
func fieldCode(exec string) string {
	for _, c := range []string{"%u", "%U", "%f", "%F"} {
		if strings.Contains(exec, c) {
			return c
		}
	}
	return ""
}

func quoteExec(s string) string {
	if !strings.ContainsAny(s, " \t\"\\$`'") {
		return strings.ReplaceAll(s, "%", "%%")
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`", `$`, `\$`, "%", "%%")
	return `"` + r.Replace(s) + `"`
}

func menuDesktop() []byte {
	return []byte(fmt.Sprintf("[Desktop Entry]\n%s\nType=Application\nName=SessionVault\nComment=%s\nExec=%s menu\nIcon=security-high\nTerminal=false\nCategories=System;Security;\n",
		desktopMarker, "Protected app sessions", BinPath))
}

func ownDesktop(a App) []byte {
	icon := a.Icon
	if icon == "" {
		icon = a.Name
	}
	// Схемы ссылок (tg://, у браузера http и https): так xdg-open находит приложение и без системного ярлыка.
	var mime strings.Builder
	schemes := a.Schemes
	if a.Browser {
		schemes = append([]string{"http", "https"}, schemes...)
	}
	for _, s := range schemes {
		mime.WriteString("x-scheme-handler/" + s + ";")
	}
	return []byte(fmt.Sprintf("[Desktop Entry]\n%s\nType=Application\nName=%s\nExec=%s %%U\nIcon=%s\nTerminal=false\nCategories=Network;\nMimeType=%s\n",
		desktopMarker, a.Title, Launcher(a.Name), icon, mime.String()))
}

// updateDesktopDB обновляет кэш ярлыков владельца: по нему xdg-open ищет программу для ссылки, у которой нет выбора по
// умолчанию.
func updateDesktopDB(cfg Config) {
	_, _ = asOwner(cfg, nil, "update-db", appsDir(cfg))
}

func ownDesktopName(a App) string {
	if !a.Custom && len(a.Desktop) > 0 {
		return a.Desktop[0]
	}
	return "sessionvault-" + a.Name + ".desktop"
}

func backupName(path string) string {
	return filepath.Base(filepath.Dir(path)) + "--" + filepath.Base(path)
}

// rewriteOwner переписывает ярлык владельца на SessionVault, сохранив прежний файл в каталоге приложения.
func rewriteOwner(cfg Config, a *App, path string, orig []byte) error {
	dir := filepath.Join(AppDir(a.Name), "desktop-backup")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, backupName(path)), orig, 0o600); err != nil {
		return err
	}
	if _, err := asOwner(cfg, rewriteDesktop(orig, Launcher(a.Name)), "replace", path); err != nil {
		return err
	}
	if !slices.Contains(a.Rewritten, path) {
		a.Rewritten = append(a.Rewritten, path)
	}
	return nil
}

func ownerDesktops(cfg Config, dir string) []string {
	b, err := asOwner(cfg, nil, "list", dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, n := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.HasSuffix(n, ".desktop") {
			out = append(out, filepath.Join(dir, n))
		}
	}
	return out
}

func installDesktop(cfg Config, a *App) error {
	launcher := Launcher(a.Name)
	done := false
	var firstErr error
	keep := func(err error) {
		if err == nil {
			done = true
		} else if firstErr == nil {
			firstErr = err
		}
	}
	for _, n := range a.Desktop {
		user := filepath.Join(appsDir(cfg), n)
		if b, err := asOwner(cfg, nil, "read", user); err == nil {
			// Свой ярлык владельца с тем же именем перекрывает системный: переписывается он.
			if !bytes.Contains(b, []byte(desktopMarker)) {
				keep(rewriteOwner(cfg, a, user, b))
			} else {
				done = true
			}
			continue
		}
		if b, err := os.ReadFile(filepath.Join("/usr/share/applications", n)); err == nil {
			_, err := asOwner(cfg, rewriteDesktop(b, launcher), "put", user)
			keep(err)
		}
	}
	for _, dir := range []string{appsDir(cfg), autostartDir(cfg)} {
		for _, p := range ownerDesktops(cfg, dir) {
			if slices.Contains(a.Desktop, filepath.Base(p)) && dir == appsDir(cfg) {
				continue
			}
			b, err := asOwner(cfg, nil, "read", p)
			if err != nil || bytes.Contains(b, []byte(desktopMarker)) {
				continue
			}
			if launches(*a, ParseDesktop(filepath.Base(p), b)) {
				err := rewriteOwner(cfg, a, p, b)
				if dir == appsDir(cfg) {
					keep(err)
				}
			}
		}
	}
	if !done {
		_, err := asOwner(cfg, ownDesktop(*a), "put", filepath.Join(appsDir(cfg), ownDesktopName(*a)))
		keep(err)
	}
	updateDesktopDB(cfg)
	// Ярлык-команда: имя вызова говорит, какое приложение запускать.
	_ = os.Remove(launcher)
	if err := os.Symlink(BinPath, launcher); err != nil {
		return err
	}
	if !done {
		return firstErr
	}
	return nil
}

func removeDesktop(cfg Config, a App) {
	for _, n := range append(slices.Clone(a.Desktop), ownDesktopName(a)) {
		_, _ = asOwner(cfg, nil, "del", filepath.Join(appsDir(cfg), n))
	}
	_, _ = asOwner(cfg, nil, "del", filepath.Join(autostartDir(cfg), "sessionvault-"+a.Name+".desktop"))
	for _, p := range a.Rewritten {
		orig, err := os.ReadFile(filepath.Join(AppDir(a.Name), "desktop-backup", backupName(p)))
		if err != nil {
			continue
		}
		// Файл, который владелец успел заменить своим, не трогается.
		if cur, err := asOwner(cfg, nil, "read", p); err == nil && !bytes.Contains(cur, []byte(desktopMarker)) {
			continue
		}
		_, _ = asOwner(cfg, orig, "replace", p)
	}
	updateDesktopDB(cfg)
	if fi, err := os.Lstat(Launcher(a.Name)); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		_ = os.Remove(Launcher(a.Name))
	}
}

// syncAutostart: приложение, у которого внутри песочницы включён автозапуск (ярлык в ~/.config/autostart его дома),
// получает автозапуск у владельца — через SessionVault. Выключили — ярлык убирается.
func syncAutostart(cfg Config, a App) {
	for _, p := range a.Rewritten {
		if filepath.Dir(p) == autostartDir(cfg) {
			return // прежний автозапуск владельца уже идёт через SessionVault
		}
	}
	want := false
	if entries, err := os.ReadDir(filepath.Join(AppDir(a.Name), homeName, ".config", "autostart")); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".desktop") && e.Type().IsRegular() {
				want = true
			}
		}
	}
	path := filepath.Join(autostartDir(cfg), "sessionvault-"+a.Name+".desktop")
	if !want {
		_, _ = asOwner(cfg, nil, "del", path)
		return
	}
	content := fmt.Sprintf("[Desktop Entry]\n%s\nType=Application\nName=%s\nExec=%s\nTerminal=false\n", desktopMarker, a.Title, Launcher(a.Name))
	_, _ = asOwner(cfg, []byte(content), "put", path)
}
