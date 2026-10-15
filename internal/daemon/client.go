//go:build linux

package daemon

import (
	"bufio"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/loar32/sessionvault/internal/i18n"
)

// Call отправляет запрос службе; extra — вторая строка (ссылка или пароль). Ответ — одна строка.
func Call(line string, extra []byte, timeout time.Duration) (string, error) {
	c, err := net.DialTimeout("unix", SocketPath, 3*time.Second)
	if err != nil {
		return "", errors.New(i18n.T("служба SessionVault не отвечает (systemctl status sessionvault)"))
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(timeout))
	msg := []byte(line + "\n")
	if extra != nil {
		msg = append(msg, extra...)
		msg = append(msg, '\n')
	}
	_, err = c.Write(msg)
	clear(msg)
	if err != nil {
		return "", err
	}
	resp, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(resp), nil
}
