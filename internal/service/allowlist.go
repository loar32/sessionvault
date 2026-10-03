package service

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/loar32/sessionvault/internal/audit"
)

// Allow — процесс, которому законно читать приманку (антивирус, поиск). Шаблон пути: `*` заменяет один каталог целиком.
// Publisher — имя издателя в подписи exe; без него запись принимается только внутри каталогов, куда обычная учётка не пишет.
type Allow struct {
	Path      string `json:"path"`
	Publisher string `json:"publisher,omitempty"`
}

func defaultAllow() []Allow {
	sys := os.Getenv("SystemRoot")
	pd := os.Getenv("ProgramData")
	pf := os.Getenv("ProgramFiles")
	return []Allow{
		{Path: filepath.Join(sys, `System32\SearchIndexer.exe`)},
		{Path: filepath.Join(pd, `Microsoft\Windows Defender\Platform\*\MsMpEng.exe`)},
		{Path: filepath.Join(pd, `Microsoft\Windows Defender\Platform\*\MpCopyAccelerator.exe`)},
		{Path: filepath.Join(pf, `Windows Defender\MsMpEng.exe`)},
	}
}

// Каталоги, где нет записи у обычной учётки: exe оттуда нельзя подменить без прав администратора.
func protectedRoots() []string {
	var r []string
	for _, e := range []string{"SystemRoot", "ProgramFiles", "ProgramFiles(x86)"} {
		if v := os.Getenv(e); v != "" {
			r = append(r, v)
		}
	}
	return r
}

type allowlist struct {
	entries []Allow
	signer  func(string) (string, error)
}

func newAllowlist(extra []Allow, log func(string, ...any)) allowlist {
	a := allowlist{entries: defaultAllow(), signer: audit.Signer}
	for _, e := range extra {
		if e.Path == "" || (e.Publisher == "" && !within(e.Path, protectedRoots())) {
			log("белый список: запись %q отклонена (нужен издатель или каталог Windows/Program Files)", e.Path)
			continue
		}
		a.entries = append(a.entries, e)
	}
	return a
}

// Allowed — процесс из белого списка. Имя «System» — само ядро (чтение по сети, антивирусный фильтр).
func (a allowlist) allowed(process string, pid uint32) bool {
	if pid == 4 && process == "System" {
		return true
	}
	for _, e := range a.entries {
		if !matchPath(e.Path, process) {
			continue
		}
		if e.Publisher == "" {
			return true
		}
		if name, err := a.signer(process); err == nil && strings.EqualFold(name, e.Publisher) {
			return true
		}
	}
	return false
}

func within(path string, roots []string) bool {
	p := strings.ToLower(filepath.Clean(path))
	for _, r := range roots {
		if strings.HasPrefix(p, strings.ToLower(filepath.Clean(r))+`\`) {
			return true
		}
	}
	return false
}

func matchPath(pattern, path string) bool {
	ps := strings.Split(strings.ToLower(filepath.Clean(pattern)), `\`)
	xs := strings.Split(strings.ToLower(filepath.Clean(path)), `\`)
	if len(ps) != len(xs) {
		return false
	}
	for i := range ps {
		if ps[i] != "*" && ps[i] != xs[i] {
			return false
		}
	}
	return true
}
