//go:build linux

package daemon

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// SandboxInit — первый процесс в песочнице (sessionvault sandbox <pid> программа ...). Значок в трее приложение
// регистрирует под именем со своим pid, а в своём пространстве PID все приложения начинают с одних и тех же номеров:
// прослойка расходует номера до заданного (у каждой учётки свой, его же разрешает шина) и запускает программу потомком.
// Дескрипторы от bwrap (сокет шины, открытые папки) программе не передаются.
func SandboxInit(args []string) int {
	if len(args) < 2 {
		return 2
	}
	target, err := strconv.Atoi(args[0])
	if err != nil {
		return 2
	}
	closeInherited()
	for range 4096 {
		c := exec.Command("/usr/bin/true")
		if c.Start() != nil {
			break
		}
		pid := c.Process.Pid
		_ = c.Wait()
		if pid >= target-1 {
			break
		}
	}
	cmd := exec.Command(args[1], args[2:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	if err := cmd.Start(); err != nil {
		return 127
	}
	go func() {
		for s := range sig {
			_ = cmd.Process.Signal(s)
		}
	}()
	err = cmd.Wait()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if st, ok := ee.Sys().(syscall.WaitStatus); ok && st.Signaled() {
			return 128 + int(st.Signal())
		}
		return ee.ExitCode()
	}
	if err != nil {
		return 1
	}
	return 0
}

func closeInherited() {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return
	}
	for _, e := range entries {
		if fd, err := strconv.Atoi(e.Name()); err == nil && fd > 2 {
			unix.CloseOnExec(fd)
		}
	}
}
