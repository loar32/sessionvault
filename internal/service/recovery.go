package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"github.com/loar32/sessionvault/internal/recovery"
	"github.com/loar32/sessionvault/internal/vault"
)

func adminVaults() (map[string]vault.Vault, error) {
	if !isolation.IsElevated() {
		return nil, errors.New("нужен запуск от администратора")
	}
	if err := isolation.EnablePrivileges("SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege"); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(isolation.VaultDir())
	if err != nil {
		return nil, err
	}
	out := map[string]vault.Vault{}
	for _, e := range entries {
		if !e.IsDir() || !profiles.ValidName(e.Name()) {
			continue
		}
		if v := (vault.Vault{Dir: isolation.DataPath(e.Name()), DataName: workDataName}); v.Exists() {
			out[e.Name()] = v
		}
	}
	if len(out) == 0 {
		return nil, errors.New("защищённых приложений нет")
	}
	return out, nil
}

// lockAll занимает running.lock всех хранилищ: пока приложение запущено, оно и служба пишут vault.json сами,
// и запись слота из другого процесса могла бы затереться (или затереть номер записи).
func lockAll(vs map[string]vault.Vault, names []string) (release func(), err error) {
	var rel []func()
	release = func() {
		for _, r := range rel {
			r()
		}
	}
	for _, n := range names {
		r, err := vs[n].Lock()
		if err != nil {
			release()
			return nil, fmt.Errorf("%s: приложение запущено или не завершено: закройте его и повторите", n)
		}
		rel = append(rel, r)
	}
	return release, nil
}

func names(vs map[string]vault.Vault) []string {
	out := make([]string, 0, len(vs))
	for n := range vs {
		out = append(out, n)
	}
	return out
}

// RecoveryCreate выпускает новый ключ восстановления для всех хранилищ; прежний перестаёт работать.
// Сначала открываются все хранилища (пароль каждого спрашивает ask), и только потом пишутся слоты: ошибка не оставит часть на старом ключе.
func RecoveryCreate(ask func(name string) ([]byte, error)) (string, error) {
	vs, err := adminVaults()
	if err != nil {
		return "", err
	}
	deks := map[string][]byte{}
	defer func() {
		for _, d := range deks {
			crypto.Wipe(d)
		}
	}()
	for name, v := range vs {
		pw, err := ask(name)
		if err != nil {
			return "", err
		}
		dek, err := v.Unlock(pw)
		crypto.Wipe(pw)
		if err != nil {
			return "", fmt.Errorf("%s: %w", name, err)
		}
		deks[name] = dek
	}
	release, err := lockAll(vs, names(vs))
	if err != nil {
		return "", err
	}
	defer release()
	key, err := crypto.NewKey()
	if err != nil {
		return "", err
	}
	defer crypto.Wipe(key)
	words, err := recovery.Words(key)
	if err != nil {
		return "", err
	}
	for name, v := range vs {
		if err := v.SetRecovery(deks[name], key); err != nil {
			return "", fmt.Errorf("%s: %w", name, err)
		}
	}
	return words, nil
}

// RecoveryReset задаёт новый мастер-пароль всем хранилищам, которые открывает ключ восстановления.
func RecoveryReset(words string, password []byte) (reset, skipped []string, err error) {
	vs, err := adminVaults()
	if err != nil {
		return nil, nil, err
	}
	key, err := recovery.Parse(words)
	if err != nil {
		return nil, nil, err
	}
	defer crypto.Wipe(key)
	release, err := lockAll(vs, names(vs))
	if err != nil {
		return nil, nil, err
	}
	defer release()
	for name, v := range vs {
		dek, err := v.UnlockRecovery(key)
		if err != nil {
			skipped = append(skipped, name)
			continue
		}
		err = v.SetPassword(dek, password)
		crypto.Wipe(dek)
		if err != nil {
			return reset, skipped, fmt.Errorf("%s: %w", name, err)
		}
		reset = append(reset, name)
	}
	if len(reset) == 0 {
		return nil, nil, errors.New("ключ восстановления не подошёл ни к одному хранилищу")
	}
	return reset, skipped, nil
}

// RecoveryCovered — приложения без слота восстановления: их ключ не откроет.
func RecoveryCovered() (with, without []string, err error) {
	vs, err := adminVaults()
	if err != nil {
		return nil, nil, err
	}
	for name, v := range vs {
		if v.HasRecovery() {
			with = append(with, name)
		} else {
			without = append(without, name)
		}
	}
	return with, without, nil
}

type bundle struct {
	App  string
	Meta []byte
	Data []byte
}

// Export пишет зашифрованное хранилище приложения в один файл для переноса на другой ПК.
func Export(app, path string) error {
	vs, err := adminVaults()
	if err != nil {
		return err
	}
	v, ok := vs[app]
	if !ok {
		return fmt.Errorf("хранилища %s нет", app)
	}
	release, err := lockAll(vs, []string{app})
	if err != nil {
		return err
	}
	defer release()
	m, d, err := v.Export()
	if err != nil {
		return err
	}
	b, err := json.Marshal(bundle{App: app, Meta: m, Data: d})
	if err != nil {
		return err
	}
	// O_EXCL: существующий файл (и ссылка на него) не перезаписывается: команда идёт от администратора.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

// Import восстанавливает приложение из файла Export на новом ПК; secret — мастер-пароль или ключ восстановления.
// Прежние данные приложения на этом ПК не трогаются: если они там есть, разберитесь с ними вручную.
func Import(path string, ask func(app string) ([]byte, error)) (string, error) {
	if !isolation.IsElevated() {
		return "", errors.New("нужен запуск от администратора")
	}
	if err := isolation.EnablePrivileges("SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege"); err != nil {
		return "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var b bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return "", errors.New("файл не похож на экспорт SessionVault")
	}
	p, ok := profiles.Template(b.App)
	if !ok {
		return "", fmt.Errorf("неизвестное приложение %q", b.App)
	}
	cfg, err := LoadConfig()
	if err != nil {
		return "", fmt.Errorf("конфигурация не прочитана: сначала install: %w", err)
	}
	if _, err := os.Stat(isolation.VaultDir()); err != nil {
		return "", errors.New("защищённой папки нет: сначала install")
	}
	if _, err := os.Stat(p.Exe); err != nil {
		return "", fmt.Errorf("%s не найден (%s): сначала установите приложение", p.Title, p.Exe)
	}
	if err := verifyPublisher(p); err != nil {
		return "", err
	}
	v := vault.Vault{Dir: isolation.DataPath(b.App), DataName: workDataName, Exclude: p.Exclude}
	if v.Exists() {
		return "", fmt.Errorf("%s уже защищён на этом ПК", p.Title)
	}
	if _, err := os.Stat(isolation.WorkPath(b.App)); err == nil {
		return "", fmt.Errorf("в %s есть данные без хранилища: разберитесь с ними вручную", v.Dir)
	}
	secret, err := ask(b.App)
	if err != nil {
		return "", err
	}
	defer crypto.Wipe(secret)
	if err := os.MkdirAll(v.Dir, 0o755); err != nil {
		return "", err
	}
	if err := isolation.ProtectDir(v.Dir); err != nil {
		return "", err
	}
	if err := v.Import(b.Meta, b.Data, secret); err != nil {
		_ = os.RemoveAll(v.Dir)
		return "", err
	}
	origin := UserTdata(cfg.MainUser)
	if b.App != "telegram" {
		origin = filepath.Join(usersDir(), cfg.MainUser, p.Origin)
	}
	if err := profiles.Save(isolation.ProfilesDir(), p); err != nil {
		return "", err
	}
	err = UpdateConfig(func(c *Config) {
		if c.Origins == nil {
			c.Origins = map[string]string{}
		}
		c.Origins[b.App] = origin
	})
	return b.App, err
}
