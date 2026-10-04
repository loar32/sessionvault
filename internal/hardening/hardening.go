// Package hardening включает системные меры, закрывающие утечку данных запущенного приложения на диск:
// шифрование файла подкачки, отключение гибернации и дампов памяти. Прежние значения запоминаются для отката.
package hardening

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// State — прежние значения мер по именам; absent — значения в реестре не было.
type State map[string]int64

const absent int64 = -1

type setting struct {
	name, key, value string
	want             uint32
}

var settings = []setting{
	{"hibernate", `SYSTEM\CurrentControlSet\Control\Power`, "HibernateEnabled", 0},
	{"encrypt_pagefile", `SYSTEM\CurrentControlSet\Control\FileSystem`, "NtfsEncryptPagingFile", 1},
	{"crash_dumps", `SYSTEM\CurrentControlSet\Control\CrashControl`, "CrashDumpEnabled", 0},
}

// Реестр и powercfg за интерфейсом: в тестах подменяются.
type system interface {
	get(key, value string) (int64, error)
	set(key, value string, v uint32) error
	remove(key, value string) error
	hibernate(on bool) error
}

type winSystem struct{}

func (winSystem) get(key, value string) (int64, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return absent, nil
		}
		return 0, err
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetIntegerValue(value)
	if errors.Is(err, registry.ErrNotExist) {
		return absent, nil
	}
	return int64(v), err
}

func (winSystem) set(key, value string, v uint32) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	return k.SetDWordValue(value, v)
}

func (winSystem) remove(key, value string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	return k.DeleteValue(value)
}

func (winSystem) hibernate(on bool) error {
	arg := "off"
	if on {
		arg = "on"
	}
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	if out, err := exec.Command(filepath.Join(dir, "powercfg.exe"), "/hibernate", arg).CombinedOutput(); err != nil {
		return fmt.Errorf("powercfg /hibernate %s: %v: %s", arg, err, out)
	}
	return nil
}

// Apply включает меры и возвращает состояние для отката. Уже записанное в prev значение не перезаписывается:
// повторный запуск не должен принять наши же изменения за исходное состояние.
func Apply(prev State) (State, error) {
	return apply(winSystem{}, prev)
}

// Revert возвращает прежние значения. Ошибки одной меры не мешают остальным.
func Revert(st State) error {
	return revert(winSystem{}, st)
}

func apply(sys system, prev State) (State, error) {
	st := State{}
	for k, v := range prev {
		st[k] = v
	}
	for _, s := range settings {
		old, err := sys.get(s.key, s.value)
		if err != nil {
			return st, fmt.Errorf("%s: %w", s.name, err)
		}
		if _, ok := st[s.name]; !ok {
			st[s.name] = old
		}
		if s.name == "hibernate" {
			if old > 0 { // нет значения — гибернация недоступна, powercfg создал бы его
				if err := sys.hibernate(false); err != nil {
					return st, err
				}
			}
			continue
		}
		if old == int64(s.want) {
			continue
		}
		if err := sys.set(s.key, s.value, s.want); err != nil {
			return st, fmt.Errorf("%s: %w", s.name, err)
		}
	}
	return st, nil
}

func revert(sys system, st State) error {
	var errs []error
	for _, s := range settings {
		old, ok := st[s.name]
		if !ok {
			continue
		}
		var err error
		switch {
		case s.name == "hibernate":
			if old == 1 {
				err = sys.hibernate(true)
			}
		case old == absent:
			err = sys.remove(s.key, s.value)
			if errors.Is(err, registry.ErrNotExist) {
				err = nil
			}
		default:
			err = sys.set(s.key, s.value, uint32(old))
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.name, err))
		}
	}
	return errors.Join(errs...)
}
