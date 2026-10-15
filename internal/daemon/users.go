//go:build linux

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// AccountName — учётка приложения: у каждого своя, чтобы взломанное приложение не читало данные соседа.
func AccountName(app string) string { return "sv-" + app }

type account struct {
	uid, gid int
}

func lookupAccount(app string) (account, error) {
	u, err := user.Lookup(AccountName(app))
	if err != nil {
		return account{}, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return account{}, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return account{}, err
	}
	return account{uid, gid}, nil
}

// Системная учётка без пароля и оболочки: войти в неё нельзя, процессы в ней запускает только служба.
func ensureAccount(app string) (account, error) {
	if a, err := lookupAccount(app); err == nil {
		return a, nil
	}
	home := filepath.Join(AppDir(app), homeName)
	out, err := exec.Command("useradd", "--system", "--no-create-home", "--home-dir", home,
		"--shell", "/usr/bin/nologin", "--user-group", "--comment", "SessionVault "+app, AccountName(app)).CombinedOutput()
	if err != nil {
		return account{}, fmt.Errorf("useradd: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return lookupAccount(app)
}

func deleteAccount(app string) error {
	if _, err := user.Lookup(AccountName(app)); err != nil {
		return nil
	}
	killUser(app)
	out, err := exec.Command("userdel", AccountName(app)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("userdel: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// killUser гасит все процессы учётки приложения: у каждого приложения своя учётка, так что лишнего это не заденет.
func killUser(app string) int {
	a, err := lookupAccount(app)
	if err != nil {
		return 0
	}
	return killUID(a.uid)
}

func killUID(uid int) int {
	n := 0
	for range 20 {
		pids := pidsOf(uid)
		if len(pids) == 0 {
			return n
		}
		for _, pid := range pids {
			if syscall.Kill(pid, syscall.SIGKILL) == nil {
				n++
			}
		}
		sleepShort()
	}
	return n
}

func pidsOf(uid int) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if procUID(pid) == uid {
			out = append(out, pid)
		}
	}
	return out
}

// Настоящий uid берётся из status: владелец /proc/<pid> у процессов, запретивших дамп (рендереры Chromium), — root.
func procUID(pid int) int {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "Uid:" {
			if uid, err := strconv.Atoi(f[1]); err == nil {
				return uid
			}
		}
	}
	return -1
}

func sleepShort() { time.Sleep(100 * time.Millisecond) }

// chownTree отдаёт дом приложения его учётке. Ссылки не трогаются (Lchown), за них не ходим.
func chownTree(root string, uid, gid int) error {
	return filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	})
}
