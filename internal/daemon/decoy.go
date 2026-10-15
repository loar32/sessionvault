//go:build linux

package daemon

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

type decoyFile struct {
	name     string
	min, max int
	sqlite   bool // начало как у базы SQLite, размер кратен странице
}

const sqliteHeader = "SQLite format 3\x00"

// Раскладки приманки по виду приложения: имена и порядок размеров как у настоящих данных.
// У telegram D877F783D5D3EF8C — постоянное имя папки первого аккаунта; у chromium базы лежат в профиле Default.
var decoyLayouts = map[string][]decoyFile{
	"telegram": {
		{"tdata/key_datas", 1500, 3500, false},
		{"tdata/D877F783D5D3EF8Cs", 15000, 60000, false},
		{"tdata/D877F783D5D3EF8C/maps", 20000, 80000, false},
		{"tdata/settingss", 300, 900, false},
		{"tdata/usertag", 8, 8, false},
	},
	"chromium": {
		{"Local State", 20000, 60000, false},
		{"First Run", 0, 0, false},
		{"Default/Preferences", 20000, 80000, false},
		{"Default/Login Data", 40960, 61440, true},
		{"Default/Web Data", 98304, 163840, true},
		{"Default/History", 122880, 245760, true},
		{"Default/Cookies", 24576, 122880, true},
		{"Default/Network/Cookies", 24576, 122880, true},
	},
	"discord": {
		{"Local State", 2000, 6000, false},
		{"Preferences", 800, 2500, false},
		{"Local Storage/leveldb/000003.log", 3000, 60000, false},
		{"Local Storage/leveldb/CURRENT", 16, 16, false},
		{"Local Storage/leveldb/MANIFEST-000001", 60, 200, false},
		{"Network/Cookies", 20480, 45056, true},
		{"settings.json", 300, 700, false},
	},
}

// DecoyFile — файл приманки в манифесте: по размеру и времени изменения видно, что его не заменило настоящее приложение.
type DecoyFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	Mod  int64  `json:"mod"`
}

type decoyEntry struct {
	Path  string      `json:"path"`
	Files []DecoyFile `json:"files"`
}

func loadDecoys() map[string]decoyEntry {
	m := map[string]decoyEntry{}
	if b, err := os.ReadFile(DecoysPath()); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func saveDecoys(m map[string]decoyEntry) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(DecoysPath(), b, 0o600)
}

func randInt(min, max int) int {
	if max <= min {
		return min
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return min
	}
	return min + int(n.Int64())
}

func decoyContent(f decoyFile) []byte {
	size := randInt(f.min, f.max)
	if f.sqlite {
		size -= size % 4096
	}
	b := make([]byte, size)
	_, _ = rand.Read(b)
	if f.sqlite && size >= len(sqliteHeader) {
		copy(b, sqliteHeader)
	}
	return b
}

// makeDecoy создаёт приманку в dir; выполняется с правами владельца (помощник), поэтому ссылки в его каталоге ни к чему
// не ведут. Существующие файлы не трогаются.
func makeDecoy(layout, dir string) ([]DecoyFile, error) {
	files, ok := decoyLayouts[layout]
	if !ok {
		return nil, errors.New("неизвестная раскладка приманки")
	}
	// Время как у давно работающего приложения: свежие одинаковые даты выдавали бы приманку.
	base := time.Now().Add(-time.Duration(randInt(3, 40)) * 24 * time.Hour)
	var out []DecoyFile
	for i, f := range files {
		p := filepath.Join(dir, f.name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return nil, err
		}
		fh, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return nil, err
		}
		_, err = fh.Write(decoyContent(f))
		if cerr := fh.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return nil, err
		}
		mod := base.Add(time.Duration(i*randInt(60, 7200)) * time.Second)
		_ = os.Chtimes(p, mod, mod)
		fi, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		out = append(out, DecoyFile{Name: f.name, Size: fi.Size(), Mod: fi.ModTime().UnixNano()})
	}
	return out, nil
}

// removeDecoy убирает только файлы, совпадающие с манифестом (размер и время), и пустые после этого каталоги.
// Файл, который переписало настоящее приложение, остаётся: это уже чужие данные.
func removeDecoy(dir string, files []DecoyFile) error {
	var dirs []string
	for _, f := range files {
		p := filepath.Join(dir, f.Name)
		fi, err := os.Lstat(p)
		if err != nil {
			continue
		}
		if !fi.Mode().IsRegular() || fi.Size() != f.Size || fi.ModTime().UnixNano() != f.Mod {
			continue
		}
		if err := os.Remove(p); err != nil {
			return err
		}
		for d := filepath.Dir(p); d != dir && len(d) > len(dir); d = filepath.Dir(d) {
			dirs = append(dirs, d)
		}
	}
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, d := range append(dirs, dir) {
		_ = os.Remove(d) // только пустые
	}
	return nil
}
