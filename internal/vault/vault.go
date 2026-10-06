package vault

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/recovery"
	"golang.org/x/sys/windows"
)

const (
	metaFile = "vault.json"
	dataFile = "data.enc"
	openFile = "open"

	backupFile = "data.enc.bak"

	// Заголовок data.enc версии 2: метка и номер записи; номер входит в AAD, поэтому его нельзя подменить отдельно от шифротекста.
	dataMagic  = "SVD2"
	headerSize = len(dataMagic) + 8
	metaV2     = 2
)

var (
	ErrWrongPassword = errors.New("неверный пароль")
	ErrEmptyData     = errors.New("рабочая папка пуста: шифрование отменено, прежний архив сохранён")
	ErrRollback      = errors.New("data.enc старше последней записи: возможен откат на прежнюю копию")
)

// Vault — одно приложение: Dir\vault.json, Dir\data.enc и открытая папка Dir\<DataName> на время работы.
type Vault struct {
	Dir      string
	DataName string
	Exclude  []string // пути внутри открытой папки, которые не шифруются (кэши)
}

type meta struct {
	Version    int
	Salt       []byte
	Params     crypto.Params
	WrappedDEK []byte
	// Число записей data.enc; с версии 2. Откат data.enc на старую копию даёт номер меньше этого.
	Counter uint64 `json:",omitempty"`
	// Второй способ открыть тот же DEK: ключ из подписи Windows Hello. Пароль остаётся запасным.
	Hello *helloSlot `json:",omitempty"`
	// Третий способ: ключ восстановления с бумаги (24 слова), один на все хранилища.
	Recovery []byte `json:",omitempty"`
}

type helloSlot struct {
	Name       string // имя ключа Hello у пользователя
	Challenge  []byte // запрос, который подписывается ключом
	WrappedDEK []byte
}

// Имя и challenge, входящие в проверку подлинности: слот нельзя перенести в другое хранилище или подменить запрос.
func (m meta) helloAAD(name string, challenge []byte) []byte {
	b := append([]byte("sv-hello-v1"), m.aad()...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(name)))
	b = append(b, name...)
	return append(b, challenge...)
}

// Версия, соль и параметры вывода ключа входят в проверку обёрнутого ключа: подмена любого из них не пройдёт.
func (m meta) aad() []byte {
	b := append([]byte("sv-meta-v2"), m.Salt...)
	b = binary.BigEndian.AppendUint32(b, m.Params.Memory)
	b = binary.BigEndian.AppendUint32(b, m.Params.Time)
	return append(b, m.Params.Threads)
}

func (v Vault) readMeta() (meta, error) {
	var m meta
	b, err := os.ReadFile(v.path(metaFile))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, err
	}
	if m.Version != 1 && m.Version != metaV2 {
		return m, fmt.Errorf("версия хранилища %d не поддерживается", m.Version)
	}
	// Файл читается до проверки пароля: огромные параметры вывода ключа не должны выбить память.
	if len(m.Salt) != crypto.SaltSize || m.Params.Time < 1 || m.Params.Time > 20 ||
		m.Params.Threads < 1 || m.Params.Memory < 8*1024 || m.Params.Memory > 1024*1024 {
		return m, errors.New("vault.json повреждён: недопустимые параметры")
	}
	return m, nil
}

func (v Vault) writeMeta(m meta) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return writeAtomic(v.path(metaFile), b)
}

func (v Vault) path(name string) string { return filepath.Join(v.Dir, name) }

func (v Vault) dataDir() string { return v.path(v.DataName) }

func (v Vault) Exists() bool {
	_, err := os.Stat(v.path(metaFile))
	return err == nil
}

// После сбоя открытая копия остаётся вместе с маркером.
func (v Vault) NeedsRecovery() bool {
	_, err := os.Stat(v.path(openFile))
	return err == nil
}

// Создаёт ключи; данные при этом не шифрует. Вызывающий обнуляет возвращённый ключ.
func (v Vault) Create(password []byte) ([]byte, error) {
	salt, err := crypto.NewSalt()
	if err != nil {
		return nil, err
	}
	dek, err := crypto.NewKey()
	if err != nil {
		return nil, err
	}
	p := crypto.DefaultParams()
	kek := crypto.DeriveKey(password, salt, p)
	defer crypto.Wipe(kek)
	m := meta{Version: metaV2, Salt: salt, Params: p}
	if m.WrappedDEK, err = crypto.SealAAD(kek, dek, m.aad()); err != nil {
		return nil, err
	}
	if err := v.writeMeta(m); err != nil {
		crypto.Wipe(dek)
		return nil, err
	}
	return dek, nil
}

// Вместо пароля принимает и ключ восстановления (24 слова): так он работает везде, где спрашивают пароль.
func (v Vault) Unlock(password []byte) ([]byte, error) {
	if key, err := recovery.Parse(string(password)); err == nil {
		defer crypto.Wipe(key)
		if dek, err := v.UnlockRecovery(key); err == nil {
			return dek, nil
		}
	}
	m, err := v.readMeta()
	if err != nil {
		return nil, err
	}
	kek := crypto.DeriveKey(password, m.Salt, m.Params)
	defer crypto.Wipe(kek)
	if m.Version == 1 {
		dek, err := crypto.Open(kek, m.WrappedDEK)
		if err != nil {
			return nil, ErrWrongPassword
		}
		// Хранилище v1 переводится в v2 при первой разблокировке; если записать не вышло, оно остаётся рабочим как v1.
		m.Version = metaV2
		if w, err := crypto.SealAAD(kek, dek, m.aad()); err == nil {
			m.WrappedDEK = w
			if err := v.writeMeta(m); err != nil {
				m.Version = 1
			}
		}
		return dek, nil
	}
	dek, err := crypto.OpenAAD(kek, m.WrappedDEK, m.aad())
	if err != nil {
		return nil, ErrWrongPassword
	}
	return dek, nil
}

// Ключ не выводится через Argon2: он случайный, 256 бит. Соль хранилища и AAD привязывают слот к этому vault.json.
func (m meta) recoveryAAD() []byte { return append([]byte("sv-recovery-v1"), m.aad()...) }

// SetRecovery обёртывает dek ключом восстановления; прежний слот заменяется.
func (v Vault) SetRecovery(dek, key []byte) error {
	m, err := v.readMeta()
	if err != nil {
		return err
	}
	kek, err := crypto.DeriveRecoveryKey(key, m.Salt)
	if err != nil {
		return err
	}
	defer crypto.Wipe(kek)
	if m.Recovery, err = crypto.SealAAD(kek, dek, m.recoveryAAD()); err != nil {
		return err
	}
	return v.writeMeta(m)
}

func (v Vault) HasRecovery() bool {
	m, err := v.readMeta()
	return err == nil && m.Recovery != nil
}

func (v Vault) UnlockRecovery(key []byte) ([]byte, error) {
	m, err := v.readMeta()
	if err != nil {
		return nil, err
	}
	if m.Recovery == nil {
		return nil, errors.New("ключ восстановления не создан")
	}
	kek, err := crypto.DeriveRecoveryKey(key, m.Salt)
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(kek)
	dek, err := crypto.OpenAAD(kek, m.Recovery, m.recoveryAAD())
	if err != nil {
		return nil, ErrWrongPassword
	}
	return dek, nil
}

// SetPassword меняет мастер-пароль. Соль и параметры остаются прежними: от них зависят слоты Hello и восстановления.
func (v Vault) SetPassword(dek, password []byte) error {
	m, err := v.readMeta()
	if err != nil {
		return err
	}
	kek := crypto.DeriveKey(password, m.Salt, m.Params)
	defer crypto.Wipe(kek)
	m.Version = metaV2
	if m.WrappedDEK, err = crypto.SealAAD(kek, dek, m.aad()); err != nil {
		return err
	}
	return v.writeMeta(m)
}

// HelloInfo — имя ключа Hello и challenge, если вход через Hello включён.
func (v Vault) HelloInfo() (name string, challenge []byte, ok bool) {
	m, err := v.readMeta()
	if err != nil || m.Hello == nil {
		return "", nil, false
	}
	return m.Hello.Name, m.Hello.Challenge, true
}

// EnableHello добавляет слот Hello: dek оборачивается ключом из secret (подписи challenge).
func (v Vault) EnableHello(dek []byte, name string, challenge, secret []byte) error {
	m, err := v.readMeta()
	if err != nil {
		return err
	}
	kek, err := crypto.DeriveHelloKey(secret)
	if err != nil {
		return err
	}
	defer crypto.Wipe(kek)
	w, err := crypto.SealAAD(kek, dek, m.helloAAD(name, challenge))
	if err != nil {
		return err
	}
	m.Hello = &helloSlot{Name: name, Challenge: challenge, WrappedDEK: w}
	return v.writeMeta(m)
}

// UnlockHello открывает DEK ключом из подписи Hello.
func (v Vault) UnlockHello(secret []byte) ([]byte, error) {
	m, err := v.readMeta()
	if err != nil {
		return nil, err
	}
	if m.Hello == nil {
		return nil, errors.New("вход через Windows Hello не включён")
	}
	kek, err := crypto.DeriveHelloKey(secret)
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(kek)
	dek, err := crypto.OpenAAD(kek, m.Hello.WrappedDEK, m.helloAAD(m.Hello.Name, m.Hello.Challenge))
	if err != nil {
		return nil, ErrWrongPassword
	}
	return dek, nil
}

// DisableHello убирает слот Hello; пароль продолжает работать.
func (v Vault) DisableHello() error {
	m, err := v.readMeta()
	if err != nil {
		return err
	}
	if m.Hello == nil {
		return nil
	}
	m.Hello = nil
	return v.writeMeta(m)
}

// Открытая папка → data.enc. Порядок важен при сбое: пока data.enc не заменён, маркер и открытая копия целы;
// после замены data.enc полный, а недоудалённая папка без маркера при следующем Decrypt затирается.
func (v Vault) Encrypt(dek []byte) error {
	tar, files, err := packDir(v.dataDir(), v.Exclude)
	if err != nil {
		return err
	}
	defer crypto.Wipe(tar)
	// Пустая папка — признак того, что приложение стёрло данные или упало: архив из неё затёр бы рабочую копию.
	if files == 0 {
		return ErrEmptyData
	}
	m, err := v.readMeta()
	if err != nil {
		return err
	}
	var blob []byte
	if m.Version == 1 {
		blob, err = crypto.Seal(dek, tar)
	} else {
		hdr := binary.BigEndian.AppendUint64([]byte(dataMagic), m.Counter+1)
		var sealed []byte
		if sealed, err = crypto.SealAAD(dek, tar, hdr); err == nil {
			blob = append(hdr, sealed...)
		}
	}
	if err != nil {
		return err
	}
	// Предыдущий архив остаётся на случай, если в новый попало повреждённое состояние приложения.
	if old, err := os.ReadFile(v.path(dataFile)); err == nil {
		if err := writeAtomic(v.path(backupFile), old); err != nil {
			return err
		}
	}
	if err := writeAtomic(v.path(dataFile), blob); err != nil {
		return err
	}
	// Сбой между двумя записями оставляет data.enc с номером на единицу больше: Decrypt такое принимает и подтягивает номер.
	if m.Version != 1 {
		m.Counter++
		if err := v.writeMeta(m); err != nil {
			return err
		}
	}
	if err := os.Remove(v.path(openFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return removeAll(v.dataDir())
}

// data.enc → открытая папка. Маркер ставится после распаковки: частичная распаковка не считается открытыми данными.
func (v Vault) Decrypt(dek []byte) error {
	blob, err := os.ReadFile(v.path(dataFile))
	if err != nil {
		return err
	}
	tar, err := v.openData(dek, blob)
	if err != nil {
		return err
	}
	defer crypto.Wipe(tar)
	if err := removeAll(v.dataDir()); err != nil {
		return err
	}
	if err := unpackDir(tar, v.dataDir()); err != nil {
		return errors.Join(err, removeAll(v.dataDir()))
	}
	return os.WriteFile(v.path(openFile), nil, 0o600)
}

// Проверяет, что архив не старше последней записи, и подтягивает номер после сбоя между записью data.enc и vault.json.
func (v Vault) openData(dek, blob []byte) ([]byte, error) {
	m, err := v.readMeta()
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(blob, []byte(dataMagic)) {
		// Прежний формат допустим только пока в v2 не было ни одной записи: иначе старый архив подсунули бы в обход счётчика.
		if m.Version != 1 && m.Counter > 0 {
			return nil, ErrRollback
		}
		return crypto.Open(dek, blob)
	}
	if m.Version == 1 || len(blob) < headerSize {
		return nil, errors.New("data.enc не соответствует версии хранилища")
	}
	n := binary.BigEndian.Uint64(blob[len(dataMagic):headerSize])
	if n < m.Counter {
		return nil, ErrRollback
	}
	tar, err := crypto.OpenAAD(dek, blob[headerSize:], blob[:headerSize])
	if err != nil {
		return nil, err
	}
	if n > m.Counter {
		m.Counter = n
		if err := v.writeMeta(m); err != nil {
			crypto.Wipe(tar)
			return nil, err
		}
	}
	return tar, nil
}

// Сразу после выхода процесса файлы ещё могут быть заняты (антивирус, индексатор).
func retry(f func() error) error {
	var err error
	for range 20 {
		if err = f(); err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return err
}

func removeAll(path string) error {
	return retry(func() error { return os.RemoveAll(path) })
}

func writeAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	// Sync до rename: после потери питания на месте data.enc не должно оказаться пустого файла.
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return retry(func() error { return os.Rename(tmp, path) })
}

// Эксклюзивно открытый файл держит запущенный экземпляр; при падении процесса система снимает блокировку сама.
func (v Vault) Lock() (release func(), err error) {
	name, err := windows.UTF16PtrFromString(v.path("running.lock"))
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, errors.New("уже запущено (или не завершено): running.lock занят")
	}
	return func() { _ = windows.CloseHandle(h) }, nil
}

// RestoreBackup возвращает предыдущий архив и опускает номер записи до его номера: это осознанное действие владельца
// (нужен ключ), в отличие от тихой подмены data.enc. Открытой копии быть не должно.
func (v Vault) RestoreBackup(dek []byte) error {
	if v.NeedsRecovery() {
		return errors.New("есть открытые данные: сначала закройте приложение")
	}
	blob, err := os.ReadFile(v.path(backupFile))
	if err != nil {
		return err
	}
	m, err := v.readMeta()
	if err != nil {
		return err
	}
	if bytes.HasPrefix(blob, []byte(dataMagic)) && len(blob) >= headerSize {
		tar, err := crypto.OpenAAD(dek, blob[headerSize:], blob[:headerSize])
		if err != nil {
			return err
		}
		crypto.Wipe(tar)
		m.Counter = binary.BigEndian.Uint64(blob[len(dataMagic):headerSize])
	} else {
		tar, err := crypto.Open(dek, blob)
		if err != nil {
			return err
		}
		crypto.Wipe(tar)
		m.Counter = 0
	}
	// Сначала номер, потом файл: сбой между ними оставляет data.enc новее номера, а это допустимо.
	if err := v.writeMeta(m); err != nil {
		return err
	}
	return retry(func() error { return os.Rename(v.path(backupFile), v.path(dataFile)) })
}

// Export возвращает vault.json без слота Hello (ключ Hello работает только на этом ПК) и data.enc: оба файла уже зашифрованы.
func (v Vault) Export() (metaJSON, data []byte, err error) {
	if v.NeedsRecovery() {
		return nil, nil, errors.New("есть открытые данные: сначала закройте приложение")
	}
	m, err := v.readMeta()
	if err != nil {
		return nil, nil, err
	}
	m.Hello = nil
	if metaJSON, err = json.Marshal(m); err != nil {
		return nil, nil, err
	}
	if data, err = os.ReadFile(v.path(dataFile)); err != nil {
		return nil, nil, err
	}
	return metaJSON, data, nil
}

// Import кладёт файлы из Export на место и проверяет, что secret (пароль или ключ восстановления) их открывает;
// иначе всё убирается. Существующее хранилище не перезаписывается.
func (v Vault) Import(metaJSON, data, secret []byte) (err error) {
	if v.Exists() {
		return errors.New("хранилище уже есть")
	}
	if _, err := os.Stat(v.path(dataFile)); err == nil {
		return errors.New("рядом лежит data.enc без vault.json: разберитесь с ним вручную")
	}
	// Слот Hello из чужого файла не нужен: он привязан к ключу другого ПК.
	var m meta
	if err := json.Unmarshal(metaJSON, &m); err != nil {
		return err
	}
	m.Hello = nil
	if metaJSON, err = json.Marshal(m); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(v.path(metaFile))
			_ = os.Remove(v.path(dataFile))
		}
	}()
	if err := writeAtomic(v.path(dataFile), data); err != nil {
		return err
	}
	if err := writeAtomic(v.path(metaFile), metaJSON); err != nil {
		return err
	}
	if _, err := v.readMeta(); err != nil {
		return err
	}
	dek, err := v.Unlock(secret)
	if err != nil {
		return err
	}
	defer crypto.Wipe(dek)
	tar, err := v.openData(dek, data)
	if err != nil {
		return err
	}
	crypto.Wipe(tar)
	return nil
}
