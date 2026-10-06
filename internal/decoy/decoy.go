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
	// Размер и время изменения созданных файлов: приложение, записавшее поверх приманки настоящую сессию, не должно быть удалено.
	// В записях прежних версий поля нет, тогда сверяются только имена.
	Sigs map[string]sig `json:"sigs,omitempty"`
}

type sig struct {
	Size int64 `json:"size"`
	Mod  int64 `json:"mod"`
}

type file struct {
	name     string
	min, max int
	sqlite   bool // начало как у базы SQLite, размер кратен странице
}

const sqliteHeader = "SQLite format 3\x00"

// Раскладки приманки по виду приложения: имена и порядок размеров как у настоящих данных.
// У telegram D877F783D5D3EF8C — постоянное имя папки первого аккаунта; у chromium базы лежат в профиле Default.
var layouts = map[string][]file{
	"telegram": {
		{"key_datas", 1500, 3500, false},
		{"D877F783D5D3EF8Cs", 15000, 60000, false},
		{`D877F783D5D3EF8C\maps`, 20000, 80000, false},
		{"settingss", 300, 900, false},
		{"usertag", 8, 8, false},
	},
	"discord": {
		{"Local State", 2000, 6000, false},
		{"Preferences", 800, 2500, false},
		{`Local Storage\leveldb\000003.log`, 3000, 60000, false},
		{`Local Storage\leveldb\CURRENT`, 16, 16, false},
		{`Local Storage\leveldb\MANIFEST-000001`, 60, 200, false},
		{`Network\Cookies`, 20480, 45056, true},
		{"settings.json", 300, 700, false},
	},
	"chromium": {
		{"Local State", 20000, 60000, false},
		{"First Run", 0, 0, false},
		{`Default\Preferences`, 20000, 80000, false},
		{`Default\Login Data`, 40960, 61440, true},
		{`Default\Web Data`, 98304, 163840, true},
		{`Default\History`, 122880, 245760, true},
		{`Default\Network\Cookies`, 24576, 122880, true},
	},
}

// ErrKind — неизвестная раскладка приманки.
var ErrKind = errors.New("неизвестная раскладка приманки")

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
func Ensure(profile, kind, path string, user *windows.SID, refresh time.Duration) (created bool, err error) {
	if _, ok := layouts[kind]; !ok {
		return false, ErrKind
	}
	st, err := load()
	if err != nil {
		return false, err
	}
	e, known := st[profile]
	if _, err := os.Stat(path); err == nil {
		// Узнаём свою папку по записи о ней: всё, что на диске, обязано быть из нашего списка.
		if !known || e.Path != path || !ours(path, e) {
			return false, ErrForeign
		}
		if time.Since(e.Updated) < refresh {
			return false, nil
		}
		if err := os.RemoveAll(path); err != nil {
			return false, err
		}
	}
	if err := NoReparse(path); err != nil {
		return false, err
	}
	// Папка приманки лежит в профиле пользователя и ему подконтрольна, а службе приходится менять в ней владельца и права.
	// Пока SYSTEM работает в такой папке, пользователь мог бы подменить подпапку ссылкой (junction) и заставить службу
	// менять владельца у системных файлов. Поэтому приманка собирается в закрытой папке службы и переносится целиком.
	stage := stagePath(profile)
	_ = os.RemoveAll(stage)
	names, sigs, err := generate(stage, layouts[kind])
	if err != nil {
		_ = os.RemoveAll(stage)
		return false, err
	}
	if err := grantUser(stage, user); err != nil {
		_ = os.RemoveAll(stage)
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		_ = os.RemoveAll(stage)
		return false, err
	}
	if err := NoReparse(path); err != nil {
		_ = os.RemoveAll(stage)
		return false, err
	}
	if err := os.Rename(stage, path); err != nil {
		_ = os.RemoveAll(stage)
		return false, err
	}
	st[profile] = entry{Path: path, Names: names, Updated: time.Now(), Sigs: sigs}
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

// NoReparse: SYSTEM пишет и меняет владельца по пути из профиля пользователя; если пользователь подменил каталог
// ссылкой или junction, это ушло бы в чужое место.
func NoReparse(path string) error {
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
		if !known || e.Path != path || !ours(path, e) {
			return ErrForeign
		}
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	delete(st, profile)
	return save(st)
}

func ours(root string, e entry) bool {
	ok := true
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			ok = false
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if rel != "." && !slices.Contains(e.Names, rel) {
			ok = false
			return fs.SkipAll
		}
		if want, has := e.Sigs[rel]; has {
			fi, err := d.Info()
			if err != nil || fi.Size() != want.Size || fi.ModTime().UnixNano() != want.Mod {
				ok = false
				return fs.SkipAll
			}
		}
		return nil
	})
	return ok
}

// В списке и сами файлы, и их папки: иначе обход сочтёт папку чужой.
func generate(root string, layout []file) ([]string, map[string]sig, error) {
	var names []string
	sigs := map[string]sig{}
	for _, f := range layout {
		p := filepath.Join(root, f.name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return nil, nil, err
		}
		size, err := between(f.min, f.max)
		if err != nil {
			return nil, nil, err
		}
		if f.sqlite {
			size -= size % 4096
		}
		buf := make([]byte, size)
		if _, err := rand.Read(buf); err != nil {
			return nil, nil, err
		}
		if f.sqlite {
			copy(buf, sqliteHeader)
		}
		if err := os.WriteFile(p, buf, 0o644); err != nil {
			return nil, nil, err
		}
		age, err := between(1, 72)
		if err != nil {
			return nil, nil, err
		}
		t := time.Now().Add(-time.Duration(age) * time.Hour)
		if err := os.Chtimes(p, t, t); err != nil {
			return nil, nil, err
		}
		fi, err := os.Stat(p)
		if err != nil {
			return nil, nil, err
		}
		sigs[f.name] = sig{Size: fi.Size(), Mod: fi.ModTime().UnixNano()}
		names = append(names, f.name)
		// Все папки на пути к файлу: иначе обход сочтёт промежуточную папку чужой.
		for d := filepath.Dir(f.name); d != "."; d = filepath.Dir(d) {
			if !slices.Contains(names, d) {
				names = append(names, d)
			}
		}
	}
	return names, sigs, nil
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

func stagePath(profile string) string {
	return filepath.Join(isolation.BaseDir(), "decoy-stage", profile)
}

// Явные права вместо наследования: у собранной в закрытой папке приманки родитель другой, а после переноса права остаются как есть.
func grantUser(root string, user *windows.SID) error {
	sd, err := windows.SecurityDescriptorFromString("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user.String() + ")")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			user, nil, dacl, nil)
	})
}
