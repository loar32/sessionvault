// Package decoy кладёт на прежнее место данных приложения приманку: папку с тем же устройством, но случайным содержимым.
// Настоящие данные в это время зашифрованы в хранилище, так что любое чтение приманки чужим процессом — подозрительно.
package decoy

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/loar32/sessionvault/internal/isolation"
	"golang.org/x/sys/windows"
)

// ErrForeign — по этому пути лежит не наша приманка (например, настоящая tdata): её нельзя трогать.
var ErrForeign = errors.New("по пути лежат чужие данные")

type entry struct {
	Path    string    `json:"path"`
	Names   []string  `json:"names"`
	Updated time.Time `json:"updated"`
}

type file struct {
	name     string
	min, max int
}

// Имена и порядок размеров как у tdata Telegram Desktop; D877F783D5D3EF8C — постоянное имя папки первого аккаунта.
var layout = []file{
	{"key_datas", 1500, 3500},
	{"D877F783D5D3EF8Cs", 15000, 60000},
	{`D877F783D5D3EF8C\maps`, 20000, 80000},
	{"settingss", 300, 900},
	{"usertag", 8, 8},
}

func statePath() string { return filepath.Join(isolation.BaseDir(), "decoys.json") }

func load() (map[string]entry, error) {
	m := map[string]entry{}
	b, err := os.ReadFile(statePath())
	if os.IsNotExist(err) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	return m, json.Unmarshal(b, &m)
}

func save(m map[string]entry) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(statePath(), b, 0o644)
}

// Ensure создаёт приманку, если места нет, и пересоздаёт её не реже раза в refresh, чтобы даты выглядели живыми.
// created сообщает, что папка новая: на неё нужно заново поставить аудит.
func Ensure(profile, path string, user *windows.SID, refresh time.Duration) (created bool, err error) {
	st, err := load()
	if err != nil {
		return false, err
	}
	e, known := st[profile]
	if _, err := os.Stat(path); err == nil {
		// Узнаём свою папку по записи о ней: всё, что на диске, обязано быть из нашего списка.
		if !known || e.Path != path || !ours(path, e.Names) {
			return false, ErrForeign
		}
		if time.Since(e.Updated) < refresh {
			return false, nil
		}
		if err := os.RemoveAll(path); err != nil {
			return false, err
		}
	}
	if err := noReparse(path); err != nil {
		return false, err
	}
	names, err := generate(path)
	if err != nil {
		_ = os.RemoveAll(path)
		return false, err
	}
	if err := isolation.GiveToUser(path, user); err != nil {
		_ = os.RemoveAll(path)
		return false, err
	}
	st[profile] = entry{Path: path, Names: names, Updated: time.Now()}
	return true, save(st)
}

// Known — по этому пути мы когда-то создали приманку: наблюдение за ней продолжается, даже если в ней появились чужие файлы.
func Known(profile, path string) bool {
	st, err := load()
	if err != nil {
		return false
	}
	e, ok := st[profile]
	return ok && e.Path == path
}

// SYSTEM пишет и меняет владельца по пути из профиля пользователя; если пользователь подменил каталог
// ссылкой или junction, это ушло бы в чужое место.
func noReparse(path string) error {
	for p := path; ; {
		if fi, err := os.Lstat(p); err == nil && fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return errors.New("на пути есть ссылка или junction: " + p)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return nil
		}
		p = parent
	}
}

// Remove убирает нашу приманку перед возвратом настоящих данных; чужую папку не трогает.
func Remove(profile, path string) error {
	st, err := load()
	if err != nil {
		return err
	}
	e, known := st[profile]
	if _, err := os.Stat(path); err == nil {
		if !known || e.Path != path || !ours(path, e.Names) {
			return ErrForeign
		}
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	delete(st, profile)
	return save(st)
}

func ours(root string, names []string) bool {
	ok := true
	_ = filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			ok = false
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if rel != "." && !slices.Contains(names, rel) {
			ok = false
			return fs.SkipAll
		}
		return nil
	})
	return ok
}

// В списке и сами файлы, и их папки: иначе обход сочтёт папку чужой.
func generate(root string) ([]string, error) {
	var names []string
	for _, f := range layout {
		p := filepath.Join(root, f.name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return nil, err
		}
		size, err := between(f.min, f.max)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, size)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		if err := os.WriteFile(p, buf, 0o644); err != nil {
			return nil, err
		}
		age, err := between(1, 72)
		if err != nil {
			return nil, err
		}
		t := time.Now().Add(-time.Duration(age) * time.Hour)
		if err := os.Chtimes(p, t, t); err != nil {
			return nil, err
		}
		names = append(names, f.name)
		if d := filepath.Dir(f.name); d != "." {
			names = append(names, d)
		}
	}
	return names, nil
}

func between(min, max int) (int, error) {
	if min == max {
		return min, nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return 0, err
	}
	return min + int(n.Int64()), nil
}
