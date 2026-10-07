package service

import (
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/loar32/sessionvault/internal/isolation"
	"golang.org/x/sys/windows"
)

const imageCacheTTL = time.Minute

type imageCache struct {
	mu sync.Mutex
	m  map[string]imageVerdict
}

type imageVerdict struct {
	clean bool
	at    time.Time
}

// Каталоги, куда обычная учётка не пишет: модуль оттуда подменить без прав администратора нельзя.
func trustedModuleRoots() []string {
	pd := isolation.KnownDir(windows.FOLDERID_ProgramData, `C:\ProgramData`)
	return append(protectedRoots(), filepath.Join(pd, `Microsoft\Windows Defender`))
}

// Разрешённый по пути процесс мог получить чужой код: DLL подложена рядом с exe (sideloading) или загружена внедрением.
// Модуль из каталога, куда пишет обычная учётка, допустим только с действительной подписью Authenticode (так загружаются,
// например, оболочечные расширения OneDrive). Процесс уже мог выйти, тогда проверять нечего: короткоживущие
// проверки антивируса не должны давать ложных тревог. Результат по процессу помнится минуту: событий чтения много.
func (a allowlist) imageClean(process string, pid uint32) bool {
	if a.modules == nil || pid == 0 || pid == 4 {
		return true
	}
	key := fmt.Sprintf("%s|%d", process, pid)
	if v, ok := a.images.get(key); ok {
		return v
	}
	mods, err := a.modules(pid)
	if err != nil {
		return true
	}
	roots := trustedModuleRoots()
	clean := true
	for _, m := range mods {
		if within(m, roots) {
			continue
		}
		if _, err := a.signer(m); err != nil {
			clean = false
			break
		}
	}
	a.images.put(key, clean)
	return clean
}

func (c *imageCache) get(key string) (bool, bool) {
	if c == nil {
		return false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[key]
	if !ok || time.Since(v.at) > imageCacheTTL {
		return false, false
	}
	return v.clean, true
}

func (c *imageCache) put(key string, clean bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil || len(c.m) > 512 {
		c.m = map[string]imageVerdict{}
	}
	c.m[key] = imageVerdict{clean, time.Now()}
}
