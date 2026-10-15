//go:build linux

package daemon

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/loar32/sessionvault/internal/i18n"
)

// Копия программы добавленного приложения: если программа лежит там, где её может заменить не только root (домашний
// каталог, AppImage, /opt владельца), запускается её копия в каталоге SessionVault. Иначе стилер подменил бы файл,
// который потом получит расшифрованные данные.

// writeProgramTar — архив файла или каталога программы со ссылками (библиотеки программ ссылаются друг на друга).
// Выполняется помощником с правами владельца.
func writeProgramTar(w io.Writer, src string) error {
	tw := tar.NewWriter(w)
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if fi.Mode().IsRegular() {
		if err := addTarEntry(tw, src, filepath.Base(src), fi); err != nil {
			return err
		}
		return tw.Close()
	}
	err = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil || rel == "." {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return addTarEntry(tw, p, rel, info)
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

func addTarEntry(tw *tar.Writer, path, rel string, fi os.FileInfo) error {
	var link string
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		var err error
		if link, err = os.Readlink(path); err != nil {
			return err
		}
	case fi.IsDir(), fi.Mode().IsRegular():
	default:
		return nil // сокеты, устройства и каналы программе не нужны
	}
	h, err := tar.FileInfoHeader(fi, link)
	if err != nil {
		return err
	}
	h.Name, h.Uname, h.Gname = filepath.ToSlash(rel), "", ""
	if err := tw.WriteHeader(h); err != nil || !fi.Mode().IsRegular() {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(tw, io.LimitReader(f, fi.Size()))
	return err
}

// extractProgramTar распаковывает архив программы. Выполняется помощником с правами учётки приложения: ссылки из архива
// не уводят запись туда, куда она не может писать и так. Запись через ссылку в пути всё равно отвергается: копия должна
// быть целиком внутри своего каталога.
func extractProgramTar(r io.Reader, root string) error {
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
		for p := filepath.Dir(dst); p != root && len(p) > len(root); p = filepath.Dir(p) {
			if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf(i18n.T("недопустимый путь в архиве: %q"), h.Name)
			}
		}
		switch h.Typeflag {
		case tar.TypeDir:
			err = os.MkdirAll(dst, 0o755)
		case tar.TypeReg:
			err = writeProgramFile(dst, tr, os.FileMode(h.Mode)&0o755)
		case tar.TypeSymlink:
			if err = os.MkdirAll(filepath.Dir(dst), 0o755); err == nil {
				err = os.Symlink(h.Linkname, dst)
			}
		}
		if err != nil {
			return err
		}
	}
}

func writeProgramFile(dst string, r io.Reader, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode|0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// extractAppImage распаковывает AppImage его же средствами (--appimage-extract) в песочнице без сети и без доступа к
// чему-либо, кроме своей папки. Выполняется с правами учётки приложения.
func extractAppImage(r io.Reader, dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	img := filepath.Join(dir, "app.AppImage")
	if err := writeProgramFile(img, r, 0o700); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bwrapPath, "--unshare-all", "--die-with-parent", "--new-session",
		"--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/bin", "/sbin",
		"--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64",
		"--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
		"--bind", dir, "/work", "--chdir", "/work", "--", "/work/app.AppImage", "--appimage-extract")
	cmd.Env = []string{"PATH=/usr/bin", "HOME=/work"}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf(i18n.T("AppImage не распаковался: %v: %s"), err, lastLine(out))
	}
	if _, err := os.Stat(filepath.Join(dir, "squashfs-root")); err != nil {
		return errors.New(i18n.T("AppImage не распаковался: нет squashfs-root"))
	}
	return os.Remove(img)
}

func lastLine(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return lines[len(lines)-1]
}

// shareACL выдаёт (или забирает) учётке приложения права на папку владельца и всё внутри. Права по умолчанию дают
// доступ и к новым файлам: учётке приложения — к созданным владельцем, владельцу — к созданным приложением.
func shareACL(path, op, svUID, ownerUID string) error {
	var spec []string
	switch op {
	case "grant":
		spec = []string{"-m", "u:" + svUID + ":rwX,d:u:" + svUID + ":rwX,d:u:" + ownerUID + ":rwX"}
	case "revoke":
		spec = []string{"-x", "u:" + svUID + ",d:u:" + svUID}
	default:
		return errors.New("helper acl: неверные аргументы")
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf(i18n.T("%s не папка"), path)
	}
	if out, err := exec.Command("/usr/bin/setfacl", append(spec, path)...).CombinedOutput(); err != nil {
		return fmt.Errorf("setfacl: %v: %s", err, strings.TrimSpace(string(out)))
	}
	// Внутри: чужие файлы (не владельца) пропускаются с ошибкой setfacl — это не повод отменять всё.
	_ = exec.Command("/usr/bin/setfacl", append([]string{"-R", "-P"}, append(spec, path)...)...).Run()
	return nil
}
