package service

import (
	"path/filepath"
	"strings"

	"github.com/loar32/sessionvault/internal/audit"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"golang.org/x/sys/windows"
)

// Allow — процесс, которому законно читать приманку (антивирус, поиск). Шаблон пути: `*` заменяет один каталог целиком.
// Publisher — имя издателя в подписи exe; без него запись принимается только внутри каталогов, куда обычная учётка не пишет.
type Allow struct {
	Path      string `json:"path"`
	Publisher string `json:"publisher,omitempty"`
}

func defaultAllow() []Allow {
	sys := isolation.KnownDir(windows.FOLDERID_Windows, `C:\Windows`)
	pd := isolation.KnownDir(windows.FOLDERID_ProgramData, `C:\ProgramData`)
	pf := isolation.KnownDir(windows.FOLDERID_ProgramFiles, `C:\Program Files`)
	a := []Allow{
		{Path: filepath.Join(sys, `System32\SearchIndexer.exe`)},
		{Path: filepath.Join(sys, `System32\SearchProtocolHost.exe`)},
		{Path: filepath.Join(sys, `System32\SearchFilterHost.exe`)},
		{Path: filepath.Join(sys, `explorer.exe`)},
		{Path: filepath.Join(pd, `Microsoft\Windows Defender\Platform\*\NisSrv.exe`)},
		{Path: filepath.Join(pd, `Microsoft\Windows Defender\Platform\*\MpCmdRun.exe`)},
		{Path: filepath.Join(pd, `Microsoft\Windows Defender\Platform\*\MsMpEng.exe`)},
		{Path: filepath.Join(pd, `Microsoft\Windows Defender\Platform\*\MpCopyAccelerator.exe`)},
		{Path: filepath.Join(pf, `Windows Defender\MsMpEng.exe`)},
	}
	// Сторонние антивирусы читают всё подряд. Издатель обязателен: подпись проверяется, чужой exe с тем же именем не пройдёт.
	pf86 := isolation.KnownDir(windows.FOLDERID_ProgramFilesX86, `C:\Program Files (x86)`)
	for _, root := range []string{pf, pf86} {
		a = append(a,
			Allow{Path: filepath.Join(root, `Kaspersky Lab\*\avp.exe`), Publisher: "AO Kaspersky Lab"},
			Allow{Path: filepath.Join(root, `ESET\*\ekrn.exe`), Publisher: "ESET, spol. s r.o."},
			Allow{Path: filepath.Join(root, `Avast Software\Avast\AvastSvc.exe`), Publisher: "AVAST Software s.r.o."},
			Allow{Path: filepath.Join(root, `Malwarebytes\Anti-Malware\MBAMService.exe`), Publisher: "Malwarebytes Inc"},
			Allow{Path: filepath.Join(root, `Norton Security\Engine\*\ccSvcHst.exe`), Publisher: "NortonLifeLock Inc."},
		)
	}
	// Обычный браузер, запущенный из основной учётки (ссылка, автозапуск), читает свой прежний профиль:
	// это не кража, и тревога убила бы защищённые приложения. Подпись проверяется, подмена exe не пройдёт.
	for _, name := range profiles.TemplateNames() {
		if p, _ := profiles.Template(name); p.Decoy == "chromium" {
			a = append(a, Allow{Path: p.Exe, Publisher: p.Publisher})
		}
	}
	return a
}

// Каталоги, где нет записи у обычной учётки: exe оттуда нельзя подменить без прав администратора.
func protectedRoots() []string {
	return []string{
		isolation.KnownDir(windows.FOLDERID_Windows, `C:\Windows`),
		isolation.KnownDir(windows.FOLDERID_ProgramFiles, `C:\Program Files`),
		isolation.KnownDir(windows.FOLDERID_ProgramFilesX86, `C:\Program Files (x86)`),
	}
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
