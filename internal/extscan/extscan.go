// Package extscan ищет в расшифрованном профиле Chromium расширения, у которых есть доступ к cookies и ко всем сайтам:
// такое расширение может забрать входы независимо от защиты файлов. Только чтение; вызывается, когда профиль
// браузера уже расшифрован для запуска.
package extscan

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

type Finding struct{ ID, Name string }

type Result struct {
	Checked int // уникальных расширений
	Risky   []Finding
}

const (
	maxExtensions = 500
	maxManifest   = 1 << 20
	maxNameRunes  = 60
)

var allSites = map[string]bool{"<all_urls>": true, "*://*/*": true, "http://*/*": true, "https://*/*": true}

type manifest struct {
	Name        string `json:"name"`
	Permissions []any  `json:"permissions"`
	HostPerms   []any  `json:"host_permissions"`
}

// Scan обходит <userData>\<профиль>\Extensions\<id>\<версия>\manifest.json строго по этой раскладке. Каталог профиля
// принадлежит приложению под vault, а читает его служба с высокими правами: ссылки и junction не открываются.
func Scan(userData string) Result {
	var res Result
	seen := map[string]bool{}
	for _, prof := range plainDirs(userData) {
		exts := filepath.Join(userData, prof, "Extensions")
		for _, id := range plainDirs(exts) {
			if seen[id] || len(seen) >= maxExtensions {
				continue
			}
			seen[id] = true
			res.Checked++
			vers := plainDirs(filepath.Join(exts, id))
			if len(vers) == 0 {
				continue
			}
			m, ok := read(filepath.Join(exts, id, vers[len(vers)-1], "manifest.json"))
			if ok && risky(m) {
				res.Risky = append(res.Risky, Finding{ID: clean(id), Name: displayName(m.Name, id)})
			}
		}
	}
	return res
}

// Обычные каталоги: ссылки (в Go их тип не каталог) пропускаются.
func plainDirs(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsDir() {
			names = append(names, e.Name())
		}
	}
	return names
}

func read(path string) (manifest, bool) {
	var m manifest
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
		return m, false
	}
	f, err := os.Open(path)
	if err != nil {
		return m, false
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxManifest+1))
	if err != nil || len(b) > maxManifest {
		return m, false
	}
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF}) // Chromium допускает BOM
	return m, json.Unmarshal(b, &m) == nil
}

// Доступ к cookies и ко всем сайтам: в MV3 сайты в host_permissions, в MV2 — среди permissions. Необязательные
// (optional_*) разрешения не считаются: их ещё не выдали.
func risky(m manifest) bool {
	cookies, all := false, false
	for _, list := range [][]any{m.Permissions, m.HostPerms} {
		for _, p := range list {
			s, _ := p.(string)
			cookies = cookies || s == "cookies"
			all = all || allSites[s]
		}
	}
	return cookies && all
}

// Имя берётся из файла расширения, то есть может быть чем угодно: управляющие символы убираются, длина ограничена.
func displayName(name, id string) string {
	if name == "" || strings.HasPrefix(name, "__MSG_") {
		return clean(id)
	}
	return clean(name)
}

func clean(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			continue
		}
		if n++; n > maxNameRunes {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}
