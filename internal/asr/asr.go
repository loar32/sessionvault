// Package asr включает правила Attack Surface Reduction в Defender (политика в реестре, режим блокировки).
// Прежние значения запоминаются для отката.
package asr

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"golang.org/x/sys/windows/registry"
)

type Rule struct{ ID, Title string }

var Rules = []Rule{
	{"5beb7efe-fd9a-4556-801d-275e5ffc04cc", "обфусцированные скрипты"},
	{"d3e037e1-3eb8-44c8-a917-57927947596d", "JS/VBS запускает скачанный exe"},
	{"be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "исполняемое содержимое из почты и вебпочты"},
	{"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "кража учётных данных из LSASS"},
}

const (
	policyKey = `SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR`
	rulesKey  = policyKey + `\Rules`
	// Куда Defender сам пишет правила, заданные не политикой (например, через Set-MpPreference).
	localKey = `SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`
	master   = "ExploitGuard_ASR_Rules"
	// Ключ в State для прежнего значения общего переключателя; GUID правил им быть не могут.
	masterName = "_policy"
	block      = "1"
)

// State — прежние значения по GUID правил и общего переключателя; пустая строка — значения не было.
type State map[string]string

// Реестр за интерфейсом: в тестах подменяется.
type system interface {
	get(key, value string) (string, bool)
	setDword(key, value string, v uint32) error
	setString(key, value, s string) error
	remove(key, value string) error
}

type winSystem struct{}

func (winSystem) get(key, value string) (string, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer func() { _ = k.Close() }()
	if s, _, err := k.GetStringValue(value); err == nil {
		return s, true
	}
	if v, _, err := k.GetIntegerValue(value); err == nil {
		return strconv.FormatUint(v, 10), true
	}
	return "", false
}

func (winSystem) setDword(key, value string, v uint32) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	return k.SetDWordValue(value, v)
}

func (winSystem) setString(key, value, s string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	return k.SetStringValue(value, s)
}

func (winSystem) remove(key, value string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	defer func() { _ = k.Close() }()
	if err := k.DeleteValue(value); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

// Apply включает правила в режиме блокировки и возвращает состояние для отката. Уже записанное в prev значение не
// перезаписывается: повторный запуск не должен принять наши же изменения за исходные.
func Apply(prev State) (State, error) { return apply(winSystem{}, prev) }

// Revert возвращает прежние значения. Ошибка одного значения не мешает остальным.
func Revert(st State) error { return revert(winSystem{}, st) }

// Active — сколько правил из нашего набора сейчас работают в блокировке (политикой или локальной настройкой Defender).
func Active() int { return active(winSystem{}) }

func apply(sys system, prev State) (State, error) {
	st := State{}
	for k, v := range prev {
		st[k] = v
	}
	if _, ok := st[masterName]; !ok {
		st[masterName], _ = sys.get(policyKey, master)
	}
	if err := sys.setDword(policyKey, master, 1); err != nil {
		return st, fmt.Errorf("включение политики ASR: %w", err)
	}
	for _, r := range Rules {
		if _, ok := st[r.ID]; !ok {
			st[r.ID], _ = sys.get(rulesKey, r.ID)
		}
		if err := sys.setString(rulesKey, r.ID, block); err != nil {
			return st, fmt.Errorf("правило %s: %w", r.Title, err)
		}
	}
	return st, nil
}

// Значения приходят из config.json: в реестр пишется только короткое число.
var validOld = regexp.MustCompile(`^[0-9]{1,2}$`)

func revert(sys system, st State) error {
	var errs []error
	restore := func(key, value, old string, dword bool) {
		var err error
		switch {
		case old == "":
			err = sys.remove(key, value)
		case !validOld.MatchString(old):
			err = fmt.Errorf("недопустимое прежнее значение %q", old)
		case dword:
			n, _ := strconv.ParseUint(old, 10, 32)
			err = sys.setDword(key, value, uint32(n))
		default:
			err = sys.setString(key, value, old)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", value, err))
		}
	}
	for _, r := range Rules {
		if old, ok := st[r.ID]; ok {
			restore(rulesKey, r.ID, old, false)
		}
	}
	if old, ok := st[masterName]; ok {
		restore(policyKey, master, old, true)
	}
	return errors.Join(errs...)
}

func active(sys system) int {
	policy := false
	if v, ok := sys.get(policyKey, master); ok && v == "1" {
		policy = true
	}
	n := 0
	for _, r := range Rules {
		// Значение из политики главнее локальной настройки: отключённое политикой правило не работает.
		if v, ok := sys.get(rulesKey, r.ID); policy && ok {
			if v == block {
				n++
			}
			continue
		}
		if v, ok := sys.get(localKey, r.ID); ok && v == block {
			n++
		}
	}
	return n
}
