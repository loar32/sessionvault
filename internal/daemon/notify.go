//go:build linux

package daemon

import (
	"context"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// notifyOwner показывает уведомление в сеансе владельца: от его имени, через его шину сеанса. В Omarchy — её же командой
// (она же рисует свои уведомления), иначе notify-send.
func notifyOwner(cfg Config, title, body string, critical bool) {
	cred, err := ownerCred(cfg)
	if err != nil {
		return
	}
	run := "/run/user/" + strconv.Itoa(cfg.Owner)
	urgency := "normal"
	if critical {
		urgency = "critical"
	}
	var args []string
	name := "notify-send"
	if _, err := os.Stat("/usr/bin/omarchy-notification-send"); err == nil {
		name = "/usr/bin/omarchy-notification-send"
		args = []string{"--app-name", "SessionVault", "-u", urgency, "-g", "\U000F0483", title, body}
	} else {
		args = []string{"-a", "SessionVault", "-u", urgency, title, body}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	cmd.Env = []string{"HOME=" + cfg.OwnerHome, "PATH=/usr/local/bin:/usr/bin", "XDG_RUNTIME_DIR=" + run,
		"DBUS_SESSION_BUS_ADDRESS=unix:path=" + run + "/bus"}
	cmd.Dir = "/"
	_ = cmd.Run()
}

// rotate: журнал больше мегабайта уходит в файл .1 (прежний .1 удаляется).
func rotate(path string) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > 1<<20 {
		_ = os.Rename(path, path+".1")
	}
}

type rotatingLog struct{ path string }

func (r rotatingLog) Write(p []byte) (int, error) {
	rotate(r.path)
	f, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	return f.Write(p)
}

// OpenLog — журнал службы: в файл и в journald (stderr службы systemd).
func OpenLog() *log.Logger {
	return log.New(io.MultiWriter(rotatingLog{LogPath()}, os.Stderr), "", log.LstdFlags)
}
