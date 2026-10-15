//go:build linux

package daemon

import (
	"errors"
	"strings"

	"github.com/loar32/sessionvault/internal/profiles"
)

type Request struct {
	Cmd     string
	Profile string
}

var errBadRequest = errors.New("неверный запрос")

// ParseRequest — единственные запросы к службе. Без имени: status, list, running, lock, check (отчёт JSON), reload (только root).
// С именем приложения: run, close, unlock (пароль следующей строкой), open и webapp (ссылка следующей строкой, см. ipc.ValidURL).
// Ни путей, ни аргументов: ответ — одно слово или список имён.
func ParseRequest(line string) (Request, error) {
	if len(line) > 64 {
		return Request{}, errBadRequest
	}
	for _, r := range line {
		if r < 0x20 || r > 0x7e {
			return Request{}, errBadRequest
		}
	}
	parts := strings.Split(line, " ")
	switch {
	case len(parts) == 1:
		switch parts[0] {
		case "status", "list", "running", "lock", "reload", "check":
			return Request{Cmd: parts[0]}, nil
		}
	case len(parts) == 2 && profiles.ValidName(parts[1]):
		switch parts[0] {
		case "run", "close", "unlock", "open", "webapp":
			return Request{Cmd: parts[0], Profile: parts[1]}, nil
		}
	}
	return Request{}, errBadRequest
}
