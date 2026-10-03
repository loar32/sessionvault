package ipc

import (
	"errors"
	"strings"

	"github.com/loar32/sessionvault/internal/profiles"
)

const (
	CommandPipe = `\.\pipe\SessionVault`
	UnlockPipe  = `\.\pipe\SessionVault-unlock`

	MaxLine = 64

	Ok       = "ok"
	Locked   = "locked"
	Unlocked = "unlocked"
	Busy     = "busy"
	Failed   = "error"
)

type Request struct {
	Cmd     string
	Profile string
}

var errBadRequest = errors.New("неверный запрос")

// Единственные запросы: «status» и «run <профиль>». Ни аргументов, ни путей, ни данных в ответе.
func Parse(line string) (Request, error) {
	if len(line) > MaxLine {
		return Request{}, errBadRequest
	}
	for _, r := range line {
		if r < 0x20 || r > 0x7e {
			return Request{}, errBadRequest
		}
	}
	parts := strings.Split(line, " ")
	switch {
	case len(parts) == 1 && parts[0] == "status":
		return Request{Cmd: "status"}, nil
	case len(parts) == 2 && parts[0] == "run" && profiles.ValidName(parts[1]):
		return Request{Cmd: "run", Profile: parts[1]}, nil
	}
	return Request{}, errBadRequest
}
