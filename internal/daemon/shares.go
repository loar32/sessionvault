//go:build linux

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"

	"github.com/loar32/sessionvault/internal/i18n"
	"golang.org/x/sys/unix"
)

// Открытые приложению папки владельца. Учётка приложения не может пройти в дом владельца (он закрыт), поэтому служба
// сама монтирует папку в каталог учётки /run/sessionvault/shares/<имя>/<n>, а bwrap берёт её оттуда. Папка открывается
// без перехода по ссылкам и монтируется по дескриптору: подменённый путь не приведёт к чужой папке.

func sharesDir(name string) string { return filepath.Join(RunDir, "shares", name) }

type share struct {
	src  string // папка, смонтированная службой
	dest string // путь в песочнице (тот же, что у владельца)
}

func mountShares(a App, acc account, owner int) ([]share, error) {
	unmountShares(a.Name)
	if len(a.Shares) == 0 {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Join(RunDir, "shares"), 0o711); err != nil {
		return nil, err
	}
	dir := sharesDir(a.Name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chown(dir, acc.uid, acc.gid); err != nil {
		return nil, err
	}
	var out []share
	var errs []error
	for i, s := range a.Shares {
		f, err := openShare(s, owner)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		target := filepath.Join(dir, strconv.Itoa(i))
		err = os.Mkdir(target, 0o700)
		if err == nil {
			err = unix.Mount("/proc/self/fd/"+strconv.Itoa(int(f.Fd())), target, "", unix.MS_BIND, "")
		}
		_ = f.Close()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, share{src: target, dest: s})
	}
	return out, errors.Join(errs...)
}

func unmountShares(name string) {
	dir := sharesDir(name)
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		_ = unix.Unmount(p, unix.MNT_DETACH)
		// rmdir, а не RemoveAll: если папка осталась смонтированной, RemoveAll удалил бы файлы владельца.
		_ = os.Remove(p)
	}
	_ = os.Remove(dir)
}

// openShare открывает папку владельца без перехода по ссылкам и проверяет, что она его.
func openShare(dir string, owner int) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, dir, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), dir)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || int(st.Uid) != owner {
		_ = f.Close()
		return nil, errors.New(i18n.T("папка принадлежит не владельцу"))
	}
	return f, nil
}
