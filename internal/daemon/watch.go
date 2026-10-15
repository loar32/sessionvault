//go:build linux

package daemon

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/loar32/sessionvault/internal/i18n"
	"golang.org/x/sys/unix"
)

// fanWatch — метки fanotify на файлах приманки. Метка стоит на inode, а не на пути: чтение через жёсткую ссылку или после
// переименования каталога тоже видно.
// События-разрешения (FAN_OPEN_PERM): открывающий процесс ждёт ответа службы, поэтому его exe и uid ещё можно прочитать —
// короткоживущий процесс (cat, скрипт) при обычном уведомлении успевает завершиться. Чтение всегда разрешается: в приманке
// мусор. Если ядро собрано без них, остаются обычные уведомления.
type fanWatch struct {
	fd    int
	perm  bool
	files map[string]string // ключ dev:inode -> приложение
}

const fanMetaSize = 24 // struct fanotify_event_metadata

func newFanWatch(perm bool) (*fanWatch, error) {
	class := uint(unix.FAN_CLASS_NOTIF)
	if perm {
		class = unix.FAN_CLASS_CONTENT
	}
	fd, err := unix.FanotifyInit(class|unix.FAN_CLOEXEC, unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return &fanWatch{fd: fd, perm: perm, files: map[string]string{}}, nil
}

func (w *fanWatch) mask() uint64 {
	if w.perm {
		return unix.FAN_OPEN_PERM
	}
	return unix.FAN_OPEN
}

func inodeKey(st *unix.Stat_t) string {
	return strconv.FormatUint(st.Dev, 10) + ":" + strconv.FormatUint(st.Ino, 10)
}

// StartTraps ставит метки на приманки и начинает разбирать события.
func (d *Daemon) StartTraps() {
	d.reloadTraps()
	go d.watchProcs()
}

func (d *Daemon) reloadTraps() {
	w, err := d.markDecoys(true)
	if errors.Is(err, unix.EINVAL) {
		w, err = d.markDecoys(false)
	}
	if err != nil {
		d.log.Println("fanotify:", err)
		return
	}
	d.mu.Lock()
	old := d.fan
	d.fan = w
	d.mu.Unlock()
	if old != nil {
		_ = unix.Close(old.fd)
	}
	d.log.Printf("приманки под наблюдением: %d файлов", len(w.files))
	go d.readEvents(w)
}

func (d *Daemon) markDecoys(perm bool) (*fanWatch, error) {
	w, err := newFanWatch(perm)
	if err != nil {
		return nil, err
	}
	for app, e := range loadDecoys() {
		for _, f := range e.Files {
			err := w.mark(filepath.Join(e.Path, f.Name), d.cfg.Owner, app)
			if errors.Is(err, unix.EINVAL) {
				_ = unix.Close(w.fd)
				return nil, err
			}
			if err != nil {
				d.log.Printf("%s: приманка %s: %v", app, f.Name, err)
			}
		}
	}
	return w, nil
}

// mark открывает файл без перехода по ссылкам и ставит метку на сам открытый файл: подменённый путь не уведёт метку
// на системный файл. Файл должен принадлежать владельцу. O_PATH не годится: fanotify_mark без имени его не принимает.
func (w *fanWatch) mark(path string, owner int, app string) error {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if int(st.Uid) != owner || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New(i18n.T("файл приманки подменён"))
	}
	if err := unix.FanotifyMark(w.fd, unix.FAN_MARK_ADD, w.mask(), fd, ""); err != nil {
		return err
	}
	w.files[inodeKey(&st)] = app
	return nil
}

func (d *Daemon) readEvents(w *fanWatch) {
	buf := make([]byte, 4096)
	for {
		n, err := unix.Read(w.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return // группа закрыта при перезагрузке меток
		}
		for off := 0; off+fanMetaSize <= n; {
			l := int(binary.LittleEndian.Uint32(buf[off:]))
			if l < fanMetaSize || off+l > n {
				break
			}
			fd := int(int32(binary.LittleEndian.Uint32(buf[off+16:])))
			pid := int(int32(binary.LittleEndian.Uint32(buf[off+20:])))
			if fd >= 0 {
				a, ok := d.onOpen(w, fd, pid)
				if w.perm {
					allow(w.fd, fd)
				}
				_ = unix.Close(fd)
				if ok {
					go d.alarm(a)
				}
			}
			off += l
		}
	}
}

// allow — ответ на событие-разрешение: struct fanotify_response {fd, response}.
func allow(group, fd int) {
	var resp [8]byte
	binary.LittleEndian.PutUint32(resp[0:], uint32(fd))
	binary.LittleEndian.PutUint32(resp[4:], unix.FAN_ALLOW)
	_, _ = unix.Write(group, resp[:])
}

// onOpen разбирает открытие приманки, пока открывающий ещё жив; тревога поднимается уже после ответа ядру.
func (d *Daemon) onOpen(w *fanWatch, fd, pid int) (a Alert, alarm bool) {
	defer func() {
		if p := recover(); p != nil {
			d.log.Printf("обработка события приманки: %v", p)
			alarm = false
		}
	}()
	if pid == os.Getpid() {
		return a, false
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		return a, false
	}
	app, ok := w.files[inodeKey(&st)]
	if !ok {
		return a, false
	}
	object, _ := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	exe, _ := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if d.allowed(exe) {
		return a, false
	}
	return Alert{App: app, Process: exe, PID: pid, UID: procUID(pid), Object: object}, true
}

// Своё приложение, запущенное в обход SessionVault (например, браузер из терминала), открывает свою прежнюю папку —
// там приманка, это не кража. Остальное разрешается только явно (decoy_allow).
func (d *Daemon) allowed(exe string) bool {
	if exe == "" {
		return false
	}
	for _, a := range Apps {
		if slices.Contains(a.Images, exe) {
			return true
		}
	}
	return slices.Contains(d.cfg.DecoyAllow, exe)
}

type Alert struct {
	App     string    `json:"app"`
	Process string    `json:"process"`
	PID     int       `json:"pid"`
	UID     int       `json:"uid"`
	SHA256  string    `json:"sha256"`
	Object  string    `json:"object"`
	Time    time.Time `json:"time"`
}

func (d *Daemon) alarmed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.alarmedLocked()
}

func (d *Daemon) alarmedLocked() bool {
	return !d.alarmAt.IsZero() && time.Since(d.alarmAt) < alarmLatch
}

// alarm: сначала гасим приложения — это единственное, что нельзя откладывать; ключи стираются после шифрования, оно идёт
// на тех же ключах. Потом журнал и уведомление.
func (d *Daemon) alarm(a Alert) {
	d.mu.Lock()
	repeat := !d.alarmAt.IsZero() && time.Since(d.alarmAt) < alarmDedup
	d.alarmAt = time.Now()
	d.alarmGen++
	d.mu.Unlock()
	if repeat {
		d.log.Printf("повторное чтение приманки: %q (PID %d)", a.Process, a.PID)
		return
	}
	d.killAll()
	go func() {
		d.wg.Wait()
		d.mu.Lock()
		if len(d.running) == 0 && len(d.starting) == 0 {
			d.lock()
		} else {
			d.lockPending = true
		}
		d.mu.Unlock()
	}()
	a.Time = time.Now()
	a.SHA256 = fileHash(a.Process)
	d.log.Printf("ТРЕВОГА: приманку %s прочитал %q (PID %d, uid %d, SHA-256 %s)", a.App, a.Process, a.PID, a.UID, a.SHA256)
	if err := appendAlert(a); err != nil {
		d.log.Println("журнал тревог:", err)
	}
	title := i18n.T("SessionVault: тревога")
	body := i18n.Tf("Приманку %s прочитала программа %s (PID %d). Защищённые приложения закрыты, хранилище заблокировано.", a.App, a.Process, a.PID)
	notifyOwner(d.cfg, title, body, true)
}

func fileHash(path string) string {
	if path == "" {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 1<<30)); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func appendAlert(a Alert) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	rotate(AlertsPath())
	f, err := os.OpenFile(AlertsPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	// Журнал тревог читает владелец (sessionvault alerts): в нём путь программы и хэш, секретов нет.
	_ = f.Chmod(0o644)
	_, err = f.Write(append(b, '\n'))
	return err
}
