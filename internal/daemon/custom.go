//go:build linux

package daemon

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/loar32/sessionvault/internal/i18n"
	"github.com/loar32/sessionvault/internal/profiles"
)

// Добавление своего приложения (sudo sessionvault add): описание берётся из ярлыка или программы, папки данных находятся
// по именам приложения, программа из места, которое может изменить не только root, копируется в каталог SessionVault.

type AddRequest struct {
	Target  string // ярлык (.desktop или его имя), путь к программе или AppImage, имя команды
	Name    string
	Dirs    []string // папки данных; пусто — найденные
	Args    []string
	ArgsSet bool
	Shares  []string
}

type AddPlan struct {
	App     App
	Desktop string // ярлык, из которого взято описание
	Builtin string // это встроенное приложение: защищается командой protect
}

var (
	slugBad = regexp.MustCompile(`[^a-z0-9]+`)
	version = regexp.MustCompile(`[-_. ]v?[0-9][0-9.]*.*$`)
)

func slug(s string) string {
	s = strings.Trim(slugBad.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(s) > 29 { // sv-<имя> не длиннее 32 символов: предел useradd
		s = strings.Trim(s[:29], "-")
	}
	return s
}

func norm(s string) string { return slugBad.ReplaceAllString(strings.ToLower(s), "") }

// Слова, по которым папку чужого приложения не отличить: их нет среди имён для поиска.
var genericWords = map[string]bool{"desktop": true, "app": true, "bin": true, "electron": true, "appimage": true,
	"launcher": true, "org": true, "com": true, "net": true, "io": true, "github": true, "x86": true, "x8664": true, "linux": true}

func matchNames(e DesktopEntry, exe, name string) []string {
	var out []string
	add := func(s string) {
		if n := norm(s); len(n) >= 3 && !genericWords[n] && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	add(name)
	add(e.Name)
	add(e.WMClass)
	id := strings.TrimSuffix(e.ID, ".desktop")
	add(id)
	if parts := strings.Split(id, "."); len(parts) >= 3 {
		add(parts[len(parts)-1])
	}
	base := strings.TrimSuffix(filepath.Base(exe), filepath.Ext(exe))
	add(version.ReplaceAllString(base, ""))
	return out
}

// matchesDir — папка данных принадлежит приложению: имя совпадает с одним из имён или содержит его отдельным словом
// (org.localsend.localsend_app).
func matchesDir(dir string, names []string) bool {
	n := norm(dir)
	tokens := strings.FieldsFunc(strings.ToLower(dir), func(r rune) bool { return strings.ContainsRune("._- ", r) })
	for _, m := range names {
		if n == m {
			return true
		}
		for _, t := range tokens {
			if len(m) >= 4 && norm(t) == m {
				return true
			}
		}
	}
	return false
}

// Корни, где программы держат данные; в самом доме — только скрытые папки.
var dataRoots = []string{".config", ".local/share", ".local/state", "."}

var skipHomeDirs = map[string]bool{".config": true, ".local": true, ".cache": true, ".var": true, ".ssh": true, ".gnupg": true}

// findDirs ищет папки данных по именам в доме home; list возвращает имена в каталоге, isDir проверяет папку.
func findDirs(names []string, list func(string) []string, isDir func(string) bool) []string {
	var out []string
	for _, root := range dataRoots {
		for _, n := range list(root) {
			if root == "." && (!strings.HasPrefix(n, ".") || skipHomeDirs[n]) {
				continue
			}
			rel := filepath.Join(root, n)
			if matchesDir(n, names) && isDir(rel) {
				out = append(out, rel)
			}
		}
	}
	return out
}

func detectDirs(cfg Config, names []string) []string {
	taken := takenDirs()
	dirs := findDirs(names, func(root string) []string {
		return ownerList(cfg, filepath.Join(cfg.OwnerHome, root))
	}, func(rel string) bool {
		fi, err := os.Lstat(filepath.Join(cfg.OwnerHome, rel))
		return err == nil && fi.IsDir()
	})
	var out []string
	for _, d := range dirs {
		if !taken[d] {
			out = append(out, d)
		}
	}
	return out
}

// takenDirs — папки данных уже защищённых приложений: у них на месте приманки, второй раз их не берём.
func takenDirs() map[string]bool {
	m := map[string]bool{}
	for _, a := range Protected() {
		for _, d := range a.Dirs {
			m[d] = true
		}
	}
	return m
}

// NormalizeDirs переводит папки данных пользователя в пути относительно его дома.
func NormalizeDirs(cfg Config, dirs []string) ([]string, error) {
	taken := takenDirs()
	var out []string
	for _, d := range dirs {
		p, err := ownerPath(cfg, d)
		if err != nil {
			return nil, err
		}
		rel, _ := filepath.Rel(cfg.OwnerHome, p)
		if rel == "." || rel == "SessionVault" || strings.HasPrefix(rel, "SessionVault/") {
			return nil, fmt.Errorf(i18n.T("%s не может быть папкой данных"), p)
		}
		if taken[rel] {
			return nil, fmt.Errorf(i18n.T("%s уже защищена другим приложением"), p)
		}
		for _, o := range out {
			if o == rel || strings.HasPrefix(rel, o+"/") || strings.HasPrefix(o, rel+"/") {
				return nil, fmt.Errorf(i18n.T("папки данных %s и %s вложены друг в друга"), o, rel)
			}
		}
		out = append(out, rel)
	}
	return out, nil
}

func findDesktop(cfg Config, id string) string {
	if filepath.IsAbs(id) {
		return id
	}
	if !strings.HasSuffix(id, ".desktop") {
		id += ".desktop"
	}
	for _, d := range []string{appsDir(cfg), "/usr/local/share/applications", "/usr/share/applications"} {
		p := filepath.Join(d, id)
		if _, err := os.Lstat(p); err == nil {
			return p
		}
	}
	return ""
}

func ownerFile(cfg Config, path string) bool {
	rel, err := filepath.Rel(cfg.OwnerHome, path)
	return err == nil && filepath.IsLocal(rel)
}

// readAny — файл владельца читается его помощником (через ссылки в его доме root не ходит), системный — напрямую.
func readAny(cfg Config, path string) ([]byte, error) {
	if ownerFile(cfg, path) {
		return asOwner(cfg, nil, "read", path)
	}
	return os.ReadFile(path)
}

func ownerMagic(cfg Config, path string) []byte {
	if ownerFile(cfg, path) {
		b, _ := asOwner(cfg, nil, "magic", path)
		m, _ := hex.DecodeString(strings.TrimSpace(string(b)))
		return m
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	m := make([]byte, 16)
	n, _ := io.ReadFull(f, m)
	return m[:n]
}

func isAppImage(magic []byte) bool {
	return len(magic) >= 11 && magic[8] == 'A' && magic[9] == 'I' && (magic[10] == 1 || magic[10] == 2)
}

// Признаки того, что рядом с программой лежат её части (библиотеки, ресурсы): тогда копируется весь каталог.
var bundleMarks = []string{"*.so", "*.so.*", "lib", "libs", "lib64", "resources", "locales", "plugins", "*.pak", "*.asar",
	"*.dat", "chrome-sandbox", "data", "share", "Qt*"}

func programKind(cfg Config, real string) string {
	if isAppImage(ownerMagic(cfg, real)) {
		return "appimage"
	}
	dir := filepath.Dir(real)
	for _, g := range []string{"", ".local/bin", "bin", "Downloads", "Desktop", "Documents", ".local/share/applications"} {
		if dir == filepath.Join(cfg.OwnerHome, g) {
			return "file"
		}
	}
	var names []string
	if ownerFile(cfg, dir) {
		names = ownerList(cfg, dir)
	} else if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			names = append(names, e.Name())
		}
	}
	for _, n := range names {
		for _, m := range bundleMarks {
			if ok, _ := filepath.Match(m, n); ok {
				return "dir"
			}
		}
	}
	return "file"
}

// PlanAdd разбирает, что будет добавлено, ничего не меняя.
func PlanAdd(req AddRequest) (AddPlan, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return AddPlan{}, err
	}
	var e DesktopEntry
	var plan AddPlan
	exe := req.Target
	var args []string
	if desk := findDesktop(cfg, req.Target); strings.HasSuffix(req.Target, ".desktop") || (desk != "" && !strings.Contains(req.Target, "/")) {
		if desk == "" {
			return plan, fmt.Errorf(i18n.T("ярлык %s не найден"), req.Target)
		}
		b, err := readAny(cfg, desk)
		if err != nil {
			return plan, err
		}
		if bytes.Contains(b, []byte(desktopMarker)) {
			return plan, errors.New(i18n.T("это ярлык SessionVault: приложение уже защищено"))
		}
		e = ParseDesktop(filepath.Base(desk), b)
		plan.Desktop = desk
		if e.Type != "" && e.Type != "Application" {
			return plan, errors.New(i18n.T("ярлык не запускает приложение"))
		}
		if e.Terminal {
			return plan, errors.New(i18n.T("консольные программы не защищаются: у них нет окна, которое запускала бы служба"))
		}
		exe, args = execProgram(ExecArgv(e.Exec))
		if exe == "" {
			return plan, errors.New(i18n.T("в ярлыке нет команды запуска"))
		}
	}
	base := filepath.Base(exe)
	switch {
	case base == "flatpak":
		return plan, errors.New(i18n.T("приложения Flatpak уже работают в своей песочнице и не защищаются SessionVault"))
	case base == "xdg-terminal-exec":
		return plan, errors.New(i18n.T("консольные программы не защищаются: у них нет окна, которое запускала бы служба"))
	case strings.HasPrefix(base, "omarchy-launch-") || slices.ContainsFunc(args, func(s string) bool { return strings.HasPrefix(s, "--app=") }):
		return plan, errors.New(i18n.T("это веб-приложение: оно открывается браузером, защитите браузер (sudo sessionvault protect chromium)"))
	}
	if !filepath.IsAbs(exe) {
		exe = resolveProgram(exe)
		if !filepath.IsAbs(exe) {
			return plan, fmt.Errorf(i18n.T("%s не найден"), req.Target)
		}
	}
	for _, b := range Apps {
		if slices.Contains(b.Desktop, e.ID) || launches(b, DesktopEntry{Exec: exe}) {
			plan.Builtin = b.Name
			return plan, nil
		}
	}
	real, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return plan, fmt.Errorf(i18n.T("%s не найден"), exe)
	}
	if fi, err := os.Stat(real); err != nil || !fi.Mode().IsRegular() {
		return plan, fmt.Errorf(i18n.T("%s не программа"), real)
	}
	a := App{Custom: true, Args: args, Icon: e.Icon}
	if req.ArgsSet {
		a.Args = req.Args
	}
	name := req.Name
	if name == "" {
		for _, s := range []string{e.Name, strings.TrimSuffix(e.ID, ".desktop"), version.ReplaceAllString(strings.TrimSuffix(base, filepath.Ext(base)), "")} {
			if name = slug(s); name != "" {
				break
			}
		}
	}
	if !profiles.ValidName(name) || len(name) > 29 {
		return plan, errors.New(i18n.T("имя: до 29 символов, строчные латинские буквы, цифры и дефис (укажите -name)"))
	}
	if _, ok := builtin(name); ok {
		return plan, fmt.Errorf(i18n.T("имя %s занято встроенным приложением: укажите другое (-name)"), name)
	}
	if _, err := os.Stat(AppDir(name)); err == nil {
		if _, ok := FindApp(name); ok {
			return plan, fmt.Errorf(i18n.T("приложение %s уже есть: укажите другое имя (-name)"), name)
		}
	}
	a.Name, a.Title = name, e.Name
	if a.Title == "" {
		a.Title = name
	}
	if err := rootOwned(real); err == nil {
		a.Exe, a.Images = []string{exe}, []string{real}
	} else {
		a.Kind = programKind(cfg, real)
		a.Source = real
		prog := filepath.Join(AppDir(name), "app")
		switch a.Kind {
		case "appimage":
			a.Exe = []string{filepath.Join(prog, "AppRun")}
		case "dir":
			a.Source = filepath.Dir(real)
			a.Exe = []string{filepath.Join(prog, filepath.Base(real))}
		default:
			a.Exe = []string{filepath.Join(prog, filepath.Base(real))}
		}
		a.Images = slices.Clone(a.Exe)
	}
	applyMime(&a, e.MimeTypes, real)
	a.Match = matchNames(e, real, name)
	if len(req.Dirs) > 0 {
		if a.Dirs, err = NormalizeDirs(cfg, req.Dirs); err != nil {
			return plan, err
		}
	} else {
		a.Dirs = detectDirs(cfg, a.Match)
	}
	a.Exclude = electronExclude
	if a.Shares, err = CheckShares(cfg, req.Shares); err != nil {
		return plan, err
	}
	if plan.Desktop != "" && !ownerFile(cfg, plan.Desktop) {
		a.Desktop = []string{e.ID}
	}
	plan.App = a
	return plan, nil
}

// applyMime: ссылки http(s) делают приложение браузером, свои схемы (obsidian://, slack://) приложение получает само.
func applyMime(a *App, mime []string, real string) {
	for _, m := range mime {
		s, ok := strings.CutPrefix(m, "x-scheme-handler/")
		if !ok {
			continue
		}
		switch {
		case s == "http" || s == "https":
			a.Browser = true
		case validScheme(s) && !slices.Contains(a.Schemes, s):
			a.Schemes = append(a.Schemes, s)
		}
	}
	if a.Browser && chromiumBased(real) {
		a.Chromium = true
		for _, f := range browserArgs {
			if !slices.Contains(a.Args, f) {
				a.Args = append(a.Args, f)
			}
		}
	}
}

func chromiumBased(real string) bool {
	for _, n := range []string{"chrome-sandbox", "chrome_crashpad_handler", "resources.pak", "chrome_100_percent.pak"} {
		if _, err := os.Lstat(filepath.Join(filepath.Dir(real), n)); err == nil {
			return true
		}
	}
	return false
}

// Add добавляет приложение по плану: учётка, копия программы, хранилище, приманки, ярлыки.
func Add(a App, password []byte, out io.Writer) error {
	if err := needRoot(); err != nil {
		return err
	}
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	if _, ok := FindApp(a.Name); ok {
		return fmt.Errorf(i18n.T("приложение %s уже есть: укажите другое имя (-name)"), a.Name)
	}
	dir := AppDir(a.Name)
	_ = os.RemoveAll(dir) // остаток прерванного добавления: описания и хранилища в нём нет
	if err := os.MkdirAll(dir, 0o711); err != nil {
		return err
	}
	fail := func(err error) error {
		_ = os.RemoveAll(dir)
		_ = deleteAccount(a.Name)
		return err
	}
	acc, err := ensureAccount(a.Name)
	if err != nil {
		return fail(err)
	}
	if a.Kind != "" {
		_, _ = fmt.Fprintln(out, i18n.T("Копирую программу…"))
		if err := copyProgram(cfg, acc, &a); err != nil {
			return fail(err)
		}
	}
	if _, err := a.FindExe(); err != nil {
		return fail(err)
	}
	if err := protectApp(cfg, a, password, out); err != nil {
		return fail(err)
	}
	return nil
}

// copyProgram копирует программу в каталог приложения. Архив пишет помощник владельца, распаковывает помощник учётки
// приложения во временную папку, затем root отдаёт копию себе: только root может её изменить.
func copyProgram(cfg Config, acc account, a *App) error {
	dir := AppDir(a.Name)
	stage := filepath.Join(dir, "stage")
	_ = os.RemoveAll(stage)
	if err := os.Mkdir(stage, 0o700); err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stage) }()
	if err := os.Chown(stage, acc.uid, acc.gid); err != nil {
		return err
	}
	ownerOp, svOp, root := "packprog", "untar", filepath.Join(stage, "root")
	if a.Kind == "appimage" {
		ownerOp, svOp, root = "read", "appimage", filepath.Join(stage, "squashfs-root")
	}
	target := root
	if a.Kind == "appimage" {
		target = stage
	}
	if err := pipeHelpers(cfg, acc, stage, []string{ownerOp, a.Source}, []string{svOp, target}); err != nil {
		return err
	}
	killUID(acc.uid)
	if err := sealProgram(root); err != nil {
		return err
	}
	dst := filepath.Join(dir, "app")
	_ = os.RemoveAll(dst)
	if err := os.Rename(root, dst); err != nil {
		return err
	}
	if a.Kind == "appimage" {
		describeAppImage(a, dst)
	}
	if real, err := filepath.EvalSymlinks(a.Exe[0]); err == nil && !slices.Contains(a.Images, real) {
		a.Images = append(a.Images, real)
	}
	return nil
}

// pipeHelpers: вывод помощника владельца идёт на вход помощника учётки приложения.
func pipeHelpers(cfg Config, acc account, home string, ownerArgs, svArgs []string) error {
	cred, err := ownerCred(cfg)
	if err != nil {
		return err
	}
	src := helperCmd(cred, cfg.OwnerHome, ownerArgs...)
	dst := helperCmd(&syscall.Credential{Uid: uint32(acc.uid), Gid: uint32(acc.gid), Groups: []uint32{}},
		home, svArgs...)
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	var srcErr, dstErr bytes.Buffer
	src.Stdout, src.Stderr = pw, &srcErr
	dst.Stdin, dst.Stderr = pr, &dstErr
	if err := src.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return err
	}
	if err := dst.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		_ = src.Process.Kill()
		_ = src.Wait()
		return err
	}
	_ = pr.Close()
	_ = pw.Close()
	serr, derr := src.Wait(), dst.Wait()
	if serr != nil {
		return helperErr(serr, &srcErr)
	}
	if derr != nil {
		return helperErr(derr, &dstErr)
	}
	return nil
}

// sealProgram отдаёт копию root: владелец root, без записи для группы и всех, без setuid/setgid. Ссылки не трогаются
// (Lchown), за них не ходим.
func sealProgram(root string) error {
	return filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if err := os.Lchown(p, 0, 0); err != nil {
			return err
		}
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			return nil
		case fi.IsDir():
			return os.Chmod(p, 0o755)
		case fi.Mode()&0o111 != 0:
			return os.Chmod(p, 0o755)
		}
		return os.Chmod(p, 0o644)
	})
}

// describeAppImage берёт имя, значок и схемы ссылок из ярлыка внутри AppImage, если их не дал ярлык снаружи.
func describeAppImage(a *App, dir string) {
	matches, _ := filepath.Glob(filepath.Join(dir, "*.desktop"))
	if len(matches) > 0 {
		if b, err := os.ReadFile(matches[0]); err == nil {
			e := ParseDesktop(filepath.Base(matches[0]), b)
			if e.Name != "" && (a.Title == a.Name || a.Title == "") {
				a.Title = e.Name
			}
			applyMime(a, e.MimeTypes, a.Exe[0])
			if prog, _ := execProgram(ExecArgv(e.Exec)); prog != "" {
				for _, p := range []string{filepath.Join(dir, prog), filepath.Join(dir, "usr", "bin", prog)} {
					if real, err := filepath.EvalSymlinks(p); err == nil && strings.HasPrefix(real, dir+"/") {
						a.Images = append(a.Images, real)
						break
					}
				}
			}
			for _, w := range matchNames(e, "", a.Name) {
				if !slices.Contains(a.Match, w) {
					a.Match = append(a.Match, w)
				}
			}
		}
	}
	if icon, err := filepath.EvalSymlinks(filepath.Join(dir, ".DirIcon")); err == nil && strings.HasPrefix(icon, dir+"/") {
		a.Icon = icon
	}
}

// Refresh копирует программу заново (после её обновления). Приложение должно быть закрыто.
func Refresh(name string, out io.Writer) error {
	if err := needRoot(); err != nil {
		return err
	}
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	a, ok := FindApp(name)
	if !ok || !a.Custom {
		return fmt.Errorf(i18n.T("%s не добавлено командой add"), name)
	}
	if a.Kind == "" {
		return fmt.Errorf(i18n.T("%s запускается на месте (из пакета): обновлять нечего"), a.Title)
	}
	unlock, err := appVault(a).Lock()
	if err != nil {
		return fmt.Errorf(i18n.T("закройте %s и повторите"), a.Title)
	}
	defer unlock()
	acc, err := lookupAccount(a.Name)
	if err != nil {
		return err
	}
	a.Images = slices.Clone(a.Exe)
	if err := copyProgram(cfg, acc, &a); err != nil {
		return err
	}
	if err := SaveApp(a); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, i18n.T("Копия %s обновлена из %s.\n"), a.Title, a.Source)
	return nil
}

// Share открывает приложению папку владельца (или закрывает, если open=false). Работающее приложение увидит изменение
// со следующего запуска.
func Share(name, dir string, open bool, out io.Writer) error {
	if err := needRoot(); err != nil {
		return err
	}
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	a, ok := FindApp(name)
	if !ok || !appVault(a).Exists() {
		return fmt.Errorf(i18n.T("%s не защищён"), name)
	}
	acc, err := lookupAccount(a.Name)
	if err != nil {
		return err
	}
	u, o := strconv.Itoa(acc.uid), strconv.Itoa(cfg.Owner)
	if open {
		dirs, err := CheckShares(cfg, []string{dir})
		if err != nil {
			return err
		}
		if _, err := asOwner(cfg, nil, "acl", dirs[0], "grant", u, o); err != nil {
			return err
		}
		if !slices.Contains(a.Shares, dirs[0]) {
			a.Shares = append(a.Shares, dirs[0])
		}
		_, _ = fmt.Fprintf(out, i18n.T("%s видит папку %s (со следующего запуска).\n"), a.Title, dirs[0])
	} else {
		p, err := ownerPath(cfg, dir)
		if err != nil {
			return err
		}
		if !slices.Contains(a.Shares, p) {
			return fmt.Errorf(i18n.T("папка %s не открыта приложению %s"), p, a.Title)
		}
		_, _ = asOwner(cfg, nil, "acl", p, "revoke", u, o)
		a.Shares = slices.DeleteFunc(a.Shares, func(s string) bool { return s == p })
		_, _ = fmt.Fprintf(out, i18n.T("Папка %s закрыта для %s (со следующего запуска).\n"), p, a.Title)
	}
	return SaveApp(a)
}

// Candidate — программа из лаунчера, которую можно защитить (для меню «Добавить приложение»).
type Candidate struct {
	ID    string
	Title string
}

// Candidates — программы лаунчера без защиты: свои ярлыки владельца перекрывают системные с тем же именем. Вызывается
// владельцем (меню), читает только ярлыки.
func Candidates(home string) []Candidate {
	seen := map[string]bool{}
	var out []Candidate
	protected := Protected()
	for _, dir := range []string{filepath.Join(home, ".local", "share", "applications"), "/usr/local/share/applications", "/usr/share/applications"} {
		entries, _ := os.ReadDir(dir)
		for _, f := range entries {
			if !strings.HasSuffix(f.Name(), ".desktop") || seen[f.Name()] {
				continue
			}
			seen[f.Name()] = true
			b, err := os.ReadFile(filepath.Join(dir, f.Name()))
			if err != nil || bytes.Contains(b, []byte(desktopMarker)) {
				continue
			}
			e := ParseDesktop(f.Name(), b)
			prog, args := execProgram(ExecArgv(e.Exec))
			if e.NoDisplay || e.Terminal || e.Name == "" || prog == "" || (e.Type != "" && e.Type != "Application") ||
				filepath.Base(prog) == "flatpak" || filepath.Base(prog) == "xdg-terminal-exec" || strings.HasPrefix(filepath.Base(prog), "omarchy-") ||
				slices.ContainsFunc(args, func(s string) bool { return strings.HasPrefix(s, "--app=") }) {
				continue
			}
			if slices.ContainsFunc(protected, func(a App) bool { return slices.Contains(a.Desktop, e.ID) || launches(a, e) }) {
				continue
			}
			out = append(out, Candidate{ID: f.Name(), Title: e.Name})
		}
	}
	slices.SortFunc(out, func(x, y Candidate) int { return strings.Compare(strings.ToLower(x.Title), strings.ToLower(y.Title)) })
	return out
}

// learnDirs: после закрытия добавленного приложения в его доме ищутся новые папки данных с его именем (приложение
// создало их при первом запуске); на их место у владельца ставится приманка, если там пусто.
func learnDirs(cfg Config, a App, l interface{ Printf(string, ...any) }) {
	if !a.Custom || len(a.Match) == 0 {
		return
	}
	home := filepath.Join(AppDir(a.Name), homeName)
	taken := takenDirs()
	found := findDirs(a.Match, func(root string) []string {
		entries, _ := os.ReadDir(filepath.Join(home, root))
		var n []string
		for _, e := range entries {
			n = append(n, e.Name())
		}
		return n
	}, func(rel string) bool {
		fi, err := os.Lstat(filepath.Join(home, rel))
		return err == nil && fi.IsDir()
	})
	changed := false
	for _, d := range found {
		if slices.Contains(a.Dirs, d) || taken[d] || slices.ContainsFunc(a.Dirs, func(o string) bool { return strings.HasPrefix(d, o+"/") }) {
			continue
		}
		origin := filepath.Join(cfg.OwnerHome, d)
		if _, err := os.Lstat(origin); err == nil {
			continue // у владельца там свои данные: приманку поверх не ставим
		}
		a.Dirs = append(a.Dirs, d)
		changed = true
		if err := placeDecoy(cfg, a.Name, origin, decoyLayout(a, filepath.Join(home, d))); err != nil {
			l.Printf("%s: приманка %s: %v", a.Name, origin, err)
		}
	}
	if changed {
		if err := SaveApp(a); err != nil {
			l.Printf("%s: app.json: %v", a.Name, err)
		}
		l.Printf("%s: новые папки данных: %s", a.Name, strings.Join(a.Dirs, ", "))
	}
}
