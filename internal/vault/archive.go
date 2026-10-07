package vault

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"github.com/loar32/sessionvault/internal/i18n"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Размер архива ограничен: он собирается в памяти целиком.
var maxArchive = 1 << 30

var ErrTooLarge = errors.New("данные приложения больше 1 ГиБ: шифрование отменено")

// Шаблон сравнивается с относительным путём по сегментам: `*` заменяет часть имени, но не границу папки
// (`*\Cache` — кэш в любом профиле браузера). Регистр не важен.
func excluded(rel string, exclude []string) bool {
	rel = strings.ToLower(rel)
	for _, x := range exclude {
		if ok, _ := filepath.Match(strings.ToLower(filepath.Clean(x)), rel); ok {
			return true
		}
	}
	return false
}

// Excluded — путь относительно папки данных попадает под шаблоны исключений.
func Excluded(rel string, exclude []string) bool { return excluded(rel, exclude) }

// exclude — пути относительно root (кэши): в архив не попадают, вместе с открытой папкой удаляются.
func packDir(root string, exclude []string) ([]byte, int, error) {
	var buf bytes.Buffer
	var tw *tar.Writer
	var files int
	var tooBig bool
	err := retry(func() error {
		buf.Reset()
		files = 0
		tooBig = false
		tw = tar.NewWriter(&buf)
		return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, p)
			if err != nil || rel == "." {
				return err
			}
			if excluded(rel, exclude) {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if buf.Len() > maxArchive {
				tooBig = true
				return fs.SkipAll
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			// Ссылка или junction в данных (приложение под vault могло оставить): в архив не берём. Ошибка здесь
			// оставляла бы данные расшифрованными после каждого выхода приложения.
			if !info.Mode().IsRegular() && !info.IsDir() {
				return nil
			}
			h, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			h.Name = filepath.ToSlash(rel)
			if err := tw.WriteHeader(h); err != nil || info.IsDir() {
				return err
			}
			files++
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			_, err = io.Copy(tw, f)
			return err
		})
	})
	if err != nil {
		return nil, 0, err
	}
	if tooBig {
		return nil, 0, ErrTooLarge
	}
	if err := tw.Close(); err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), files, nil
}

func unpackDir(data []byte, root string) error {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if !filepath.IsLocal(h.Name) {
			return fmt.Errorf(i18n.T("недопустимый путь в архиве: %q"), h.Name)
		}
		dst := filepath.Join(root, filepath.FromSlash(h.Name))
		switch h.Typeflag {
		case tar.TypeDir:
			err = os.MkdirAll(dst, 0o755)
		case tar.TypeReg:
			err = writeFile(dst, tr)
		default:
			err = fmt.Errorf(i18n.T("недопустимый тип в архиве: %q"), h.Name)
		}
		if err != nil {
			return err
		}
	}
}

func writeFile(dst string, r io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
