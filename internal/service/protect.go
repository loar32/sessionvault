package service

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/decoy"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"github.com/loar32/sessionvault/internal/vault"
)

// ErrCancelled — владелец не подтвердил удаление прежнего профиля браузера.
var ErrCancelled = errors.New("отменено: прежний профиль браузера не удалён, защита не включена")

// Каталог прежнего профиля переименовывается до создания хранилища и удаляется после: если что-то пойдёт не так,
// его возвращают на место целиком.
const oldProfileSuffix = ".sessionvault-delete"

// ProtectBrowser создаёт для браузера пустое защищённое хранилище и убирает его прежний профиль из основной учётки.
// Куки и пароли Chromium зашифрованы ключом DPAPI основной учётки, vault их прочитать не может, поэтому профиль новый
// (входы делаются заново), а прежний удаляется: пока он на месте, стилер читает его как раньше.
// confirm спрашивает разрешение удалить прежний профиль, askPassword — мастер-пароль нового хранилища.
// left непуст, если прежний профиль удалить не удалось до конца.
func ProtectBrowser(app string, confirm func(path string, size int64) bool, askPassword func() ([]byte, error)) (left string, err error) {
	if !isolation.IsElevated() {
		return "", errors.New("нужен запуск от администратора")
	}
	if err := isolation.EnablePrivileges("SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege"); err != nil {
		return "", err
	}
	cfg, err := LoadConfig()
	if err != nil {
		return "", fmt.Errorf("конфигурация не прочитана: сначала install: %w", err)
	}
	p, ok := profiles.Template(app)
	if !ok || p.Decoy != "chromium" {
		return "", fmt.Errorf("%q не браузер: доступны chrome, edge, brave", app)
	}
	if _, err := os.Stat(p.Exe); err != nil {
		return "", fmt.Errorf("%s не найден (%s): поддерживается только установка для всех пользователей (Program Files)", p.Title, p.Exe)
	}
	if err := verifyPublisher(p); err != nil {
		return "", err
	}
	if _, err := os.Stat(isolation.VaultDir()); err != nil {
		return "", errors.New("защищённой папки нет: сначала install")
	}
	v := vault.Vault{Dir: isolation.DataPath(app), DataName: workDataName, Exclude: p.Exclude}
	if v.Exists() {
		return "", fmt.Errorf("%s уже защищён", p.Title)
	}
	// Данные без vault.json — возможно, единственная копия сессии после сбоя: поверх них ничего не создаём.
	if _, err := os.Stat(isolation.WorkPath(app)); err == nil {
		return "", fmt.Errorf("в %s есть данные без хранилища: разберитесь с ними вручную", v.Dir)
	}

	origin := filepath.Join(usersDir(), cfg.MainUser, p.Origin)
	if err := decoy.NoReparse(origin); err != nil {
		return "", err
	}
	aside := origin + oldProfileSuffix
	if _, err := os.Stat(aside); err == nil {
		return "", fmt.Errorf("остался каталог от прошлой попытки (%s): удалите его вручную", aside)
	}
	_, statErr := os.Stat(origin)
	hadOld := statErr == nil
	if hadOld && !confirm(origin, dirSize(origin)) {
		return "", ErrCancelled
	}
	pw, err := askPassword()
	if err != nil {
		return "", err
	}
	defer crypto.Wipe(pw)

	if hadOld {
		// Путь проверялся давно: за время вопросов пользователя родительскую папку могли подменить ссылкой.
		if err := decoy.NoReparse(origin); err != nil {
			return "", err
		}
		if err := os.Rename(origin, aside); err != nil {
			return "", fmt.Errorf("не удалось убрать прежний профиль (закройте %s и повторите): %w", p.Title, err)
		}
	}
	done := false
	defer func() {
		if done {
			return
		}
		if hadOld {
			_ = os.Rename(aside, origin)
		}
		_ = os.RemoveAll(v.Dir)
		_ = os.Remove(filepath.Join(isolation.ProfilesDir(), app+".json"))
		_ = UpdateConfig(func(c *Config) { delete(c.Origins, app) })
	}()

	if err := profiles.Save(isolation.ProfilesDir(), p); err != nil {
		return "", err
	}
	err = UpdateConfig(func(c *Config) {
		if c.Origins == nil {
			c.Origins = map[string]string{}
		}
		c.Origins[app] = origin
	})
	if err != nil {
		return "", err
	}
	// Браузеру нужен хоть один файл, иначе архив считался бы пустым; сам он досоздаст остальное.
	dst := filepath.Join(isolation.WorkPath(app), p.DataDir)
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dst, "First Run"), nil, 0o644); err != nil {
		return "", err
	}
	if err := isolation.ProtectDir(v.Dir); err != nil {
		return "", err
	}
	dek, err := v.Create(pw)
	if err != nil {
		return "", err
	}
	defer crypto.Wipe(dek)
	if err := v.Encrypt(dek); err != nil {
		return "", err
	}
	check, err := v.Unlock(pw)
	if err != nil {
		return "", fmt.Errorf("хранилище не открывается после создания: %w", err)
	}
	crypto.Wipe(check)
	done = true

	if hadOld {
		if err := os.RemoveAll(aside); err != nil {
			return aside, nil
		}
	}
	return "", nil
}

func dirSize(root string) int64 {
	var n int64
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
			n += info.Size()
		}
		return nil
	})
	return n
}
