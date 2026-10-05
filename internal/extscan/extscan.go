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
	"sort"
	"strconv"
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
	maxProfiles   = 50
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
	seen, flagged := map[string]bool{}, map[string]bool{}
	for i, prof := range plainDirs(userData) {
		if i >= maxProfiles {
			break
		}
		exts := filepath.Join(userData, prof, "Extensions")
		for _, id := range plainDirs(exts) {
			if !seen[id] {
				if len(seen) >= maxExtensions {
					continue
				}
				seen[id] = true
				res.Checked++
			}
			// Разрешения одного расширения в разных профилях могут отличаться: смотрим каждый профиль.
			vers := plainDirs(filepath.Join(exts, id))
			if len(vers) == 0 || flagged[id] {
				continue
			}
			sort.Slice(vers, func(a, b int) bool { return versionLess(vers[a], vers[b]) })
			m, ok := read(filepath.Join(exts, id, vers[len(vers)-1], "manifest.json"))
			if ok && risky(m) {
				flagged[id] = true
				res.Risky = append(res.Risky, Finding{ID: clean(id), Name: displayName(m.Name, id)})
			}
		}
	}
	return res
}

// Версии каталогов вида 1.10_0 сравниваются по числам: по строкам 1.9_0 оказалась бы новее 1.10_0.
func versionLess(a, b string) bool {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	if len(pa) != len(pb) {
		return len(pa) < len(pb)
	}
	return a < b
}

func versionParts(s string) []int {
	var out []int
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r < '0' || r > '9' }) {
		n, err := strconv.Atoi(f)
		if err != nil {
			n = 0
		}
		out = append(out, n)
	}
	return out
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
