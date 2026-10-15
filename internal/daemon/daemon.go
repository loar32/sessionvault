//go:build linux

package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/i18n"
	"github.com/loar32/sessionvault/internal/ipc"
	"github.com/loar32/sessionvault/internal/vault"
	"golang.org/x/sys/unix"
)

const (
	launchGrace  = 3 * time.Second
	stopWait     = 30 * time.Second
	runGap       = time.Second
	failCooldown = 10 * time.Second
	maxFails     = 3
	maxConns     = 16
	defaultIdle  = 240
	alarmLatch   = 10 * time.Minute
	alarmDedup   = 30 * time.Second
)

type instance struct {
	cmd    *exec.Cmd
	sess   session
	acc    account
	bus    *busProxy
	links  *net.UnixListener
	shares []share
}
type Daemon struct {
	cfg Config
	log *log.Logger
	ln  *net.UnixListener

	unlockMu sync.Mutex // разблокировка по одной: Argon2 берёт 128 МиБ, параллельные запросы выбили бы память

	mu          sync.Mutex
	keys        map[string][]byte // DEK приложений, пока хранилище разблокировано
	running     map[string]*instance
	closing     map[string]bool // приложение вышло, данные ещё шифруются: новый экземпляр запускать нельзя
	starting    map[string]bool
	fails       map[string]int
	failAt      map[string]time.Time
	lastRun     map[string]time.Time
	idle        *time.Timer
	lockPending bool // блокировку попросили, но приложение ещё работает: ключ нужен для шифрования при выходе
	alarmGen    int  // растёт с каждой тревогой: запуск, начавшийся до неё, не должен её пережить
	alarmAt     time.Time
	server      int // pid композитора последнего сеанса: его выход — выход из системы
	wg          sync.WaitGroup

	fan    *fanWatch
	trapMu sync.Mutex // перестановка меток приманок по одной
}

func New(cfg Config, l *log.Logger) *Daemon {
	return &Daemon{cfg: cfg, log: l, keys: map[string][]byte{}, running: map[string]*instance{}, closing: map[string]bool{},
		starting: map[string]bool{}, fails: map[string]int{}, failAt: map[string]time.Time{}, lastRun: map[string]time.Time{}}
}

func (d *Daemon) idleAfter() time.Duration {
	m := d.cfg.IdleMinutes
	if m == 0 {
		m = defaultIdle
	}
	if m < 0 {
		return 0
	}
	return time.Duration(m) * time.Minute
}

// Listen — сокет открыт всем на подключение, но запросы принимаются только от владельца и root (SO_PEERCRED).
func (d *Daemon) Listen() error {
	if err := os.MkdirAll(RunDir, 0o755); err != nil {
		return err
	}
	_ = os.Remove(SocketPath)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: SocketPath, Net: "unix"})
	if err != nil {
		return err
	}
	if err := os.Chmod(SocketPath, 0o666); err != nil {
		_ = l.Close()
		return err
	}
	d.ln = l
	return nil
}

func (d *Daemon) Serve() {
	sem := make(chan struct{}, maxConns)
	for {
		c, err := d.ln.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			d.log.Println("сокет:", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				d.handle(c)
			}()
		default:
			_ = c.Close()
		}
	}
}

func peerCred(c *net.UnixConn) (*unix.Ucred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) { cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return nil, err
	}
	return cred, cerr
}

func readLine(r *bufio.Reader, max int) (string, error) {
	var b []byte
	for {
		c, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if c == '\n' {
			return string(b), nil
		}
		if len(b) >= max {
			return "", errors.New(i18n.T("слишком длинная строка"))
		}
		b = append(b, c)
	}
}

func (d *Daemon) handle(c *net.UnixConn) {
	defer func() { _ = c.Close() }()
	defer func() {
		if p := recover(); p != nil {
			d.log.Printf("паника при обработке запроса: %v", p)
		}
	}()
	cred, err := peerCred(c)
	if err != nil || (int(cred.Uid) != d.cfg.Owner && cred.Uid != 0) {
		return
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	line, err := readLine(r, ipc.MaxLine)
	if err != nil {
		return
	}
	req, err := ParseRequest(line)
	if err != nil {
		reply(c, ipc.Failed)
		return
	}
	var extra string
	switch req.Cmd {
	case "open", "webapp":
		// Ссылка: для веб-приложения только http(s), для open ещё и свои схемы приложения (проверяются в run).
		extra, err = readLine(r, ipc.MaxURL)
		if _, ok := linkScheme(extra); err != nil || !ok || (req.Cmd == "webapp" && ipc.ValidURL(extra) != nil) {
			reply(c, ipc.Failed)
			return
		}
	}
	switch req.Cmd {
	case "status":
		reply(c, d.state())
	case "list":
		reply(c, d.list())
	case "running":
		reply(c, d.runningList())
	case "check":
		_ = c.SetDeadline(time.Now().Add(time.Minute))
		b, err := json.Marshal(d.Check())
		if err != nil {
			reply(c, ipc.Failed)
			return
		}
		reply(c, string(b))
	case "lock":
		d.lockRequested("команда lock")
		reply(c, ipc.Ok)
	case "close":
		reply(c, d.closeApp(req.Profile))
	case "run", "open", "webapp":
		_ = c.SetDeadline(time.Now().Add(time.Minute))
		reply(c, d.run(req.Profile, req.Cmd, extra, int(cred.Pid)))
	case "unlock":
		_ = c.SetDeadline(time.Now().Add(time.Minute))
		pw, err := readSecret(r, ipc.MaxPassword)
		if err != nil {
			reply(c, ipc.Failed)
			return
		}
		reply(c, d.unlock(req.Profile, pw))
		crypto.Wipe(pw)
	case "reload":
		if cred.Uid != 0 {
			reply(c, ipc.Failed)
			return
		}
		d.reloadTraps()
		reply(c, ipc.Ok)
	}
}

func readSecret(r *bufio.Reader, max int) ([]byte, error) {
	b := make([]byte, 0, max)
	for {
		c, err := r.ReadByte()
		if err != nil {
			crypto.Wipe(b)
			return nil, err
		}
		if c == '\n' {
			return b, nil
		}
		if len(b) >= max {
			crypto.Wipe(b)
			return nil, errors.New("too long")
		}
		b = append(b, c)
	}
}

func reply(w io.Writer, s string) { _, _ = io.WriteString(w, s+"\n") }

func (d *Daemon) state() string {
	if d.alarmed() {
		return ipc.Alarm
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.keys) == 0 {
		return ipc.Locked
	}
	return ipc.Unlocked
}

func (d *Daemon) list() string {
	var n []string
	for _, a := range Protected() {
		n = append(n, a.Name)
	}
	return strings.Join(n, ",")
}

func (d *Daemon) runningList() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var n []string
	for name := range d.running {
		n = append(n, name)
	}
	return strings.Join(n, ",")
}

func (d *Daemon) unlock(name string, pw []byte) string {
	a, ok := FindApp(name)
	if !ok {
		return ipc.Failed
	}
	v := appVault(a)
	if !v.Exists() {
		return ipc.Failed
	}
	d.mu.Lock()
	if d.alarmedLocked() {
		d.mu.Unlock()
		return ipc.Alarm
	}
	if d.fails[name] >= maxFails && time.Since(d.failAt[name]) < failCooldown {
		d.mu.Unlock()
		return "wait"
	}
	d.mu.Unlock()

	d.unlockMu.Lock()
	dek, err := v.Unlock(pw)
	d.unlockMu.Unlock()
	if err != nil {
		d.mu.Lock()
		d.fails[name]++
		d.failAt[name] = time.Now()
		n := d.fails[name]
		d.mu.Unlock()
		d.log.Printf("%s: неверный пароль (попытка %d): %v", name, n, err)
		if !errors.Is(err, vault.ErrWrongPassword) {
			return ipc.Failed
		}
		// Пауза после каждой ошибки: подбор пароля через сокет и так упирается в Argon2, но не должен идти без остановки.
		time.Sleep(time.Second)
		return "bad"
	}
	if err := crypto.Lock(dek); err != nil {
		d.log.Printf("%s: mlock: %v", name, err)
	}
	d.mu.Lock()
	if old := d.keys[name]; old != nil {
		crypto.Wipe(old)
		crypto.Unlock(old)
	}
	d.keys[name] = dek
	d.fails[name] = 0
	d.resetIdle()
	d.mu.Unlock()
	d.log.Printf("%s: хранилище разблокировано", name)
	return ipc.Ok
}

// run запускает приложение. Хранилище заперто — ответ locked: окно пароля показывает клиент в сеансе владельца,
// служба окон не рисует. Приложение уже запущено — новый экземпляр в той же песочнице передаст ссылку работающему.
func (d *Daemon) run(name, mode, link string, pid int) string {
	a, ok := FindApp(name)
	if !ok || (mode == "open" && !a.AcceptsLink(link)) {
		return ipc.Failed
	}
	v := appVault(a)
	if !v.Exists() {
		return ipc.Failed
	}
	d.mu.Lock()
	if d.alarmedLocked() {
		d.mu.Unlock()
		return ipc.Alarm
	}
	if time.Since(d.lastRun[name]) < runGap || d.closing[name] || d.starting[name] {
		d.mu.Unlock()
		return ipc.Busy
	}
	d.lastRun[name] = time.Now()
	inst := d.running[name]
	dek := d.keys[name]
	if inst == nil && dek == nil {
		d.mu.Unlock()
		return ipc.Locked
	}
	if inst != nil {
		d.mu.Unlock()
		if err := d.forward(a, inst, mode, link); err != nil {
			d.log.Printf("%s: передача запуска: %v", name, err)
			return ipc.Failed
		}
		return ipc.Ok
	}
	d.starting[name] = true
	d.stopIdle()
	gen := d.alarmGen
	d.mu.Unlock()

	err := d.start(a, v, dek, mode, link, pid, gen)
	d.mu.Lock()
	delete(d.starting, name)
	d.mu.Unlock()
	if err != nil {
		d.log.Printf("%s: запуск: %v", name, err)
		d.finish(name)
		return ipc.Failed
	}
	return ipc.Ok
}

func appArgs(a App, mode, link string, owner int, ownerHome string) ([]string, error) {
	exe, err := a.FindExe()
	if err != nil {
		return nil, err
	}
	argv := append([]string{exe}, browserFlags(a, owner, ownerHome)...)
	argv = append(argv, a.Args...)
	switch {
	case mode == "open" && a.AcceptsLink(link):
		argv = append(argv, link)
	case mode == "webapp" && a.Chromium:
		argv = append(argv, "--app="+link)
	case mode == "webapp" && a.Browser:
		argv = append(argv, link)
	}
	return argv, nil
}

func (d *Daemon) start(a App, v vault.Vault, dek []byte, mode, link string, pid, gen int) (err error) {
	sess, err := findSession(d.cfg.Owner, pid)
	if err != nil {
		return err
	}
	acc, err := ensureAccount(a.Name)
	if err != nil {
		return err
	}
	unlock, err := v.Lock()
	if err != nil {
		return err
	}
	encrypted := true
	defer func() {
		if err != nil {
			if !encrypted {
				err = errors.Join(err, v.Encrypt(dek))
			}
			unlock()
		}
	}()
	if v.NeedsRecovery() {
		d.log.Printf("%s: дошифровываю открытые данные после сбоя", a.Name)
		killUID(acc.uid)
		if err := v.Encrypt(dek); err != nil {
			return err
		}
	}
	if err := v.Decrypt(dek); err != nil {
		return err
	}
	encrypted = false
	home := filepath.Join(AppDir(a.Name), homeName)
	if err := chownTree(home, acc.uid, acc.gid); err != nil {
		return err
	}
	if err := os.Chmod(home, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(AppDir(a.Name), "tmp")
	_ = os.RemoveAll(tmp)
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return err
	}
	if err := os.Chown(tmp, acc.uid, acc.gid); err != nil {
		return err
	}
	argv, err := appArgs(a, mode, link, d.cfg.Owner, d.cfg.OwnerHome)
	if err != nil {
		return err
	}
	if err := sess.grant(acc.uid); err != nil {
		return err
	}
	inst := &instance{sess: sess, acc: acc}
	if inst.bus, err = startBus(d.cfg, a, acc); err != nil {
		d.log.Printf("%s: шина сеанса недоступна: %v", a.Name, err)
	}
	if inst.links, err = listenLinks(a, acc); err != nil {
		d.log.Printf("%s: сокет ссылок: %v", a.Name, err)
	} else {
		go d.serveLinks(a, acc, inst.links, sess)
	}
	if inst.shares, err = mountShares(a, acc, d.cfg.Owner); err != nil {
		d.log.Printf("%s: открытые папки: %v", a.Name, err)
	}
	cmd, err := d.sandboxCmd(a, inst, argv)
	if err != nil {
		d.cleanup(a, inst)
		return err
	}
	logw := appLog(a.Name)
	if logw != nil {
		cmd.Stdout = logw
		cmd.Stderr = logw
		defer func() {
			if err != nil {
				_ = logw.f.Close()
			}
		}()
	}
	err = cmd.Start()
	if err != nil {
		d.cleanup(a, inst)
		return err
	}
	inst.cmd = cmd
	d.mu.Lock()
	alarmed := d.alarmGen != gen
	d.running[a.Name] = inst
	d.server = sess.server
	d.mu.Unlock()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	if alarmed {
		killUID(acc.uid)
		<-exited
		d.cleanup(a, inst)
		return errors.New(i18n.T("тревога во время запуска"))
	}
	select {
	case werr := <-exited:
		killUID(acc.uid)
		d.cleanup(a, inst)
		return fmt.Errorf(i18n.T("приложение не запустилось: %v"), werr)
	case <-time.After(launchGrace):
	}
	d.log.Printf("%s: запущено (pid %d)", a.Name, cmd.Process.Pid)
	encrypted = true // дальше шифрует горутина выхода
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		<-exited
		if logw != nil {
			_ = logw.f.Close()
		}
		d.mu.Lock()
		d.closing[a.Name] = true
		alarmedNow := d.alarmGen != gen
		d.mu.Unlock()
		// Процессы, ушедшие из-под bwrap (их быть не должно: своё пространство PID), гасятся до шифрования.
		killUID(acc.uid)
		d.cleanup(a, inst)
		// После тревоги в доме приложения не ищем ничего нового: ключи вот-вот сотрутся, нужна только запись.
		if !alarmedNow {
			d.afterClose(a)
		}
		if err := v.Encrypt(dek); err != nil {
			d.log.Printf("%s: шифрование после закрытия: %v", a.Name, err)
		} else {
			d.log.Printf("%s: закрыто, данные зашифрованы", a.Name)
		}
		unlock()
		d.finish(a.Name)
	}()
	return nil
}

// afterClose: новые папки данных добавленного приложения получают приманку, автозапуск из песочницы переносится
// владельцу.
func (d *Daemon) afterClose(a App) {
	before := len(a.Dirs)
	learnDirs(d.cfg, a, d.log)
	if cur, ok := FindApp(a.Name); ok && len(cur.Dirs) != before {
		d.reloadTraps()
	}
	syncAutostart(d.cfg, a)
}

func (d *Daemon) cleanup(a App, inst *instance) {
	inst.sess.revoke(inst.acc.uid)
	inst.bus.stop()
	if inst.links != nil {
		_ = inst.links.Close()
	}
	_ = os.RemoveAll(filepath.Join(RunDir, "bus", a.Name))
	unmountShares(a.Name)
	_ = os.RemoveAll(filepath.Join(AppDir(a.Name), "tmp"))
}

func (d *Daemon) sandboxCmd(a App, inst *instance, argv []string) (*exec.Cmd, error) {
	cmd := exec.Command(bwrapPath, d.sandboxArgs(a, inst, argv)...)
	cmd.Env = d.sandboxEnv(a, inst)
	cmd.Dir = "/"
	groups := []uint32{}
	if g, err := user.LookupGroup("video"); err == nil {
		if id, err := strconv.Atoi(g.Gid); err == nil {
			groups = append(groups, uint32(id)) // камера: /dev/video* открыты группе video
		}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(inst.acc.uid), Gid: uint32(inst.acc.gid), Groups: groups},
		Setsid:     true,
		Pdeathsig:  syscall.SIGKILL,
	}
	// Вывод идёт через канал: процесс, переживший bwrap, не должен держать Wait бесконечно.
	cmd.WaitDelay = 2 * time.Second
	return cmd, nil
}

// forward — второй экземпляр в песочнице того же приложения: он найдёт работающий по сокету в общем /tmp и передаст ему
// ссылку (Chromium откроет вкладку, Telegram покажет окно), а сам выйдет.
func (d *Daemon) forward(a App, inst *instance, mode, link string) error {
	argv, err := appArgs(a, mode, link, d.cfg.Owner, d.cfg.OwnerHome)
	if err != nil {
		return err
	}
	if err := inst.sess.grant(inst.acc.uid); err != nil {
		return err
	}
	cmd, err := d.sandboxCmd(a, inst, argv)
	if err != nil {
		return err
	}
	logw := openCapped(filepath.Join(AppDir(a.Name), "forward.log"))
	if logw != nil {
		cmd.Stdout = logw
		cmd.Stderr = logw
	}
	err = cmd.Start()
	if err != nil {
		return err
	}
	go func() {
		_ = cmd.Wait()
		if logw != nil {
			_ = logw.f.Close()
		}
	}()
	return nil
}

func (d *Daemon) finish(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.running, name)
	delete(d.closing, name)
	if d.lockPending && len(d.running) == 0 {
		d.lock()
		d.log.Println("хранилище заблокировано после выхода приложений")
		return
	}
	d.resetIdle()
}

func (d *Daemon) closeApp(name string) string {
	d.mu.Lock()
	inst := d.running[name]
	d.mu.Unlock()
	if inst == nil {
		return ipc.Ok
	}
	killUID(inst.acc.uid)
	return ipc.Ok
}

// lockRequested — блокировка экрана, сон, выход из сеанса или команда: ключи стираются сразу, а если приложение запущено,
// то после его выхода (ключ нужен для шифрования).
func (d *Daemon) lockRequested(why string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.keys) == 0 {
		return
	}
	if len(d.running) > 0 || len(d.starting) > 0 {
		d.lockPending = true
		d.log.Printf("блокировка (%s) после выхода приложений", why)
		return
	}
	d.lock()
	d.log.Printf("хранилище заблокировано (%s)", why)
}

// Вызывается под mu.
func (d *Daemon) resetIdle() {
	d.stopIdle()
	after := d.idleAfter()
	if len(d.running) > 0 || len(d.keys) == 0 || after <= 0 {
		return
	}
	d.idle = time.AfterFunc(after, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if len(d.running) == 0 && len(d.starting) == 0 {
			d.lock()
			d.log.Println("хранилище заблокировано по бездействию")
		}
	})
}

func (d *Daemon) stopIdle() {
	if d.idle != nil {
		d.idle.Stop()
		d.idle = nil
	}
}

// Вызывается под mu.
func (d *Daemon) lock() {
	d.lockPending = false
	d.stopIdle()
	for name, k := range d.keys {
		crypto.Wipe(k)
		crypto.Unlock(k)
		delete(d.keys, name)
	}
}

// Stop: приложения гасятся, данные шифруются ещё не стёртыми ключами, потом ключи стираются.
func (d *Daemon) Stop() {
	_ = d.ln.Close()
	d.killAll()
	done := make(chan struct{})
	go func() { d.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(stopWait):
		d.log.Println("не все данные успели зашифроваться при остановке")
	}
	d.mu.Lock()
	d.lock()
	d.mu.Unlock()
}

func (d *Daemon) killAll() {
	d.mu.Lock()
	var uids []int
	for _, inst := range d.running {
		uids = append(uids, inst.acc.uid)
	}
	d.mu.Unlock()
	for _, uid := range uids {
		killUID(uid)
	}
}

// capWriter — вывод приложения (для разбора сбоев запуска), не больше мегабайта: файл обрезается при каждом запуске.
type capWriter struct {
	f    *os.File
	left int
}

func (w *capWriter) Write(p []byte) (int, error) {
	if w.left > 0 {
		n := min(len(p), w.left)
		_, _ = w.f.Write(p[:n])
		w.left -= n
	}
	return len(p), nil
}

func appLog(name string) *capWriter { return openCapped(filepath.Join(AppDir(name), "app.log")) }

func openCapped(path string) *capWriter {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil
	}
	return &capWriter{f: f, left: 1 << 20}
}
