package ipc

import (
	"errors"
	"net/url"
	"strings"

	"github.com/loar32/sessionvault/internal/profiles"
)

const (
	CommandPipe = `\\.\pipe\SessionVault`
	// Префикс: к нему служба на каждый запрос добавляет случайный хвост, чтобы чужой процесс не занял имя заранее.
	UnlockPipe = `\\.\pipe\SessionVault-unlock-`

	MaxLine     = 64
	MaxPassword = 256
	MaxURL      = 2048
	MaxReply    = 256  // ответ на list: имена профилей через запятую
	MaxCheck    = 8192 // ответ на check: отчёт JSON одной строкой

	Ok       = "ok"
	Locked   = "locked"
	Unlocked = "unlocked"
	Busy     = "busy"
	// Только в ответе на status: недавно прочитана приманка.
	Alarm  = "alarm"
	Failed = "error"
)

type Request struct {
	Cmd     string
	Profile string
}

var errBadRequest = errors.New("неверный запрос")

// Единственные запросы: «status», «list», «check», «open» (ссылка следующей строкой, см. ValidURL), «run <профиль>», «hello <профиль>» и «fido <профиль>». Ни аргументов, ни путей, ни данных в ответе (list отдаёт только имена).
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
	case len(parts) == 1 && parts[0] == "list":
		return Request{Cmd: "list"}, nil
	case len(parts) == 2 && parts[0] == "run" && profiles.ValidName(parts[1]):
		return Request{Cmd: "run", Profile: parts[1]}, nil
	case len(parts) == 1 && parts[0] == "check":
		return Request{Cmd: "check"}, nil
	case len(parts) == 1 && parts[0] == "open":
		return Request{Cmd: "open"}, nil
	case len(parts) == 2 && (parts[0] == "hello" || parts[0] == "fido") && profiles.ValidName(parts[1]):
		return Request{Cmd: parts[0], Profile: parts[1]}, nil
	}
	return Request{}, errBadRequest
}

// Ссылка уходит в командную строку браузера, поэтому допускаются только http(s) и печатный ASCII без пробелов и кавычек
// (всё остальное в ссылке должно быть закодировано через %). Начинаться с «-» она не может: схема обязательна.
func ValidURL(s string) error {
	if len(s) == 0 || len(s) > MaxURL {
		return errBadRequest
	}
	for _, r := range s {
		if r <= 0x20 || r > 0x7e || r == '"' || r == '\\' || r == '^' || r == '`' {
			return errBadRequest
		}
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return errBadRequest
	}
	return nil
}
