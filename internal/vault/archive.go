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

// Архив прежних форматов data.enc (до версии 3) собирался в памяти целиком, поэтому был ограничен.
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

// PackDir — архив папки в памяти (только файлы и каталоги, без ссылок) и число файлов в нём.
func PackDir(root string, exclude []string) ([]byte, int, error) { return packDir(root, exclude) }

// UnpackDir распаковывает архив PackDir в root.
func UnpackDir(data []byte, root string) error { return unpackDir(data, root) }

// WriteTar пишет архив папки в w потоком (только файлы и каталоги, без ссылок) и возвращает число файлов.
func WriteTar(w io.Writer, root string, exclude []string) (int, error) {
	return writeTar(w, root, exclude)
}

// ExtractTar распаковывает поток WriteTar в root.
func ExtractTar(r io.Reader, root string) error { return extractTar(r, root) }

type limitBuffer struct {
	bytes.Buffer
	tooBig bool
}

func (b *limitBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > maxArchive {
		b.tooBig = true
		return 0, ErrTooLarge
	}
	return b.Buffer.Write(p)
}

func packDir(root string, exclude []string) ([]byte, int, error) {
	var buf limitBuffer
	var files int
	err := retry(func() error {
		buf.Reset()
		buf.tooBig = false
		var err error
		files, err = writeTar(&buf, root, exclude)
		if buf.tooBig {
			return nil
		}
		return err
	})
	if buf.tooBig {
		return nil, 0, ErrTooLarge
	}
	if err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), files, nil
}

// exclude — пути относительно root (кэши): в архив не попадают, вместе с открытой папкой удаляются.
func writeTar(w io.Writer, root string, exclude []string) (int, error) {
	tw := tar.NewWriter(w)
	files := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
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
		h.Uname, h.Gname = "", ""
		if err := tw.WriteHeader(h); err != nil || info.IsDir() {
			return err
		}
		files++
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		// Файл мог измениться после stat: в архив идёт ровно заявленный размер, иначе tar отвергнет запись.
		n, err := io.Copy(tw, io.LimitReader(f, info.Size()))
		if err == nil && n < info.Size() {
			_, err = io.CopyN(tw, zeros{}, info.Size()-n)
		}
		return err
	})
	if err != nil {
		return 0, err
	}
	return files, tw.Close()
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func unpackDir(data []byte, root string) error { return extractTar(bytes.NewReader(data), root) }

func extractTar(r io.Reader, root string) error {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	tr := tar.NewReader(r)
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
			err = writeFile(dst, tr, os.FileMode(h.Mode)&0o111)
		default:
			err = fmt.Errorf(i18n.T("недопустимый тип в архиве: %q"), h.Name)
		}
		if err != nil {
			return err
		}
	}
}

// exec — биты исполнения из архива: в данных Linux-приложения бывают свои программы (клиент Discord лежит в его папке).
// Прочие биты (setuid, запись для всех) не переносятся.
func writeFile(dst string, r io.Reader, exec os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644|exec)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
