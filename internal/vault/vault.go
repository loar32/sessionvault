package vault

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/loar32/sessionvault/internal/i18n"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/recovery"
)

const (
	metaFile = "vault.json"
	dataFile = "data.enc"
	openFile = "open"

	backupFile = "data.enc.bak"

	// Заголовок data.enc: метка и номер записи; номер входит в AAD, поэтому его нельзя подменить отдельно от шифротекста.
	// Версия 2 — один блок AES-GCM на весь архив (архив в памяти), версия 3 — поток блоков без ограничения размера.
	dataMagic   = "SVD2"
	streamMagic = "SVD3"
	headerSize  = len(dataMagic) + 8
	metaV2      = 2
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
	// Ещё один способ: секрет hmac-secret ключа FIDO2 (YubiKey). Работает на любом ПК, где есть ключ и его PIN.
	Fido *fidoSlot `json:",omitempty"`
	// Третий способ: ключ восстановления с бумаги (24 слова), один на все хранилища.
	Recovery []byte `json:",omitempty"`
}

type helloSlot struct {
	Name       string // имя ключа Hello у пользователя
	Challenge  []byte // запрос, который подписывается ключом
	WrappedDEK []byte
}

type fidoSlot struct {
	CredID     []byte // идентификатор учётных данных на ключе
	Salt       []byte // соль hmac-secret
	WrappedDEK []byte
}

// Учётные данные и соль входят в проверку подлинности: слот нельзя перенести в другое хранилище или подменить.
func (m meta) fidoAAD(credID, salt []byte) []byte {
	b := append([]byte("sv-fido-v1"), m.aad()...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(credID)))
	b = append(b, credID...)
	return append(b, salt...)
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
	metaMu.Lock()
	defer metaMu.Unlock()
	return v.readMetaLocked()
}

func (v Vault) readMetaLocked() (meta, error) {
	var m meta
	b, err := os.ReadFile(v.path(metaFile))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, err
	}
	if m.Version != 1 && m.Version != metaV2 {
		return m, fmt.Errorf(i18n.T("версия хранилища %d не поддерживается"), m.Version)
	}
	// Файл читается до проверки пароля: огромные параметры вывода ключа не должны выбить память.
	if len(m.Salt) != crypto.SaltSize || m.Params.Time < 1 || m.Params.Time > 20 ||
		m.Params.Threads < 1 || m.Params.Memory < 8*1024 || m.Params.Memory > 1024*1024 {
		return m, errors.New(i18n.T("vault.json повреждён: недопустимые параметры"))
	}
	return m, nil
}

// metaMu не даёт двум изменениям vault.json в одном процессе затереть друг друга: Encrypt при закрытии приложения,
// включение Hello или FIDO и смена пароля читают файл, правят свою часть и пишут его целиком. Чтение тоже под ней:
// Windows не даёт открыть файл в момент, когда его заменяет rename.
var metaMu sync.Mutex

// updateMeta читает vault.json, применяет изменение и записывает; всё под одной блокировкой.
func (v Vault) updateMeta(change func(m *meta) error) error {
	metaMu.Lock()
	defer metaMu.Unlock()
	m, err := v.readMetaLocked()
	if err != nil {
		return err
	}
	if err := change(&m); err != nil {
		return err
	}
	return v.writeMetaLocked(m)
}

func (v Vault) writeMeta(m meta) error {
	metaMu.Lock()
	defer metaMu.Unlock()
	return v.writeMetaLocked(m)
}

func (v Vault) writeMetaLocked(m meta) error {
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
	return v.updateMeta(func(m *meta) (err error) {
		kek, err := crypto.DeriveRecoveryKey(key, m.Salt)
		if err != nil {
			return err
		}
		defer crypto.Wipe(kek)
		m.Recovery, err = crypto.SealAAD(kek, dek, m.recoveryAAD())
		return err
	})
}

// RemoveRecovery убирает слот ключа восстановления у одного хранилища (ключ перестаёт его открывать).
func (v Vault) RemoveRecovery() error {
	return v.updateMeta(func(m *meta) error {
		m.Recovery = nil
		return nil
	})
}

// MetaBytes — vault.json как есть: точка отката для операций, которые меняют несколько хранилищ.
func (v Vault) MetaBytes() ([]byte, error) {
	metaMu.Lock()
	defer metaMu.Unlock()
	return os.ReadFile(v.path(metaFile))
}

// RestoreMeta возвращает vault.json, снятый MetaBytes.
func (v Vault) RestoreMeta(b []byte) error {
	metaMu.Lock()
	defer metaMu.Unlock()
	return writeAtomic(v.path(metaFile), b)
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
		return nil, errors.New(i18n.T("ключ восстановления не создан"))
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
	return v.updateMeta(func(m *meta) (err error) {
		kek := crypto.DeriveKey(password, m.Salt, m.Params)
		defer crypto.Wipe(kek)
		m.Version = metaV2
		m.WrappedDEK, err = crypto.SealAAD(kek, dek, m.aad())
		return err
	})
}

// HelloInfo — имя ключа Hello и challenge, если вход через Hello включён.
func (v Vault) HelloInfo() (name string, challenge []byte, ok bool) {
	m, err := v.readMeta()
	if err != nil || m.Hello == nil {
		return "", nil, false
	}
	return m.Hello.Name, m.Hello.Challenge, true
}

// FidoInfo — учётные данные и соль, если вход по ключу FIDO2 включён.
func (v Vault) FidoInfo() (credID, salt []byte, ok bool) {
	m, err := v.readMeta()
	if err != nil || m.Fido == nil {
		return nil, nil, false
	}
	return m.Fido.CredID, m.Fido.Salt, true
}

// EnableFido добавляет слот ключа FIDO2: dek оборачивается ключом из secret (hmac-secret для credID и salt).
func (v Vault) EnableFido(dek, credID, salt, secret []byte) error {
	return v.updateMeta(func(m *meta) error {
		kek, err := crypto.DeriveFidoKey(secret)
		if err != nil {
			return err
		}
		defer crypto.Wipe(kek)
		w, err := crypto.SealAAD(kek, dek, m.fidoAAD(credID, salt))
		if err != nil {
			return err
		}
		m.Fido = &fidoSlot{CredID: credID, Salt: salt, WrappedDEK: w}
		return nil
	})
}

func (v Vault) UnlockFido(secret []byte) ([]byte, error) {
	m, err := v.readMeta()
	if err != nil {
		return nil, err
	}
	if m.Fido == nil {
		return nil, errors.New(i18n.T("вход по ключу FIDO2 не включён"))
	}
	kek, err := crypto.DeriveFidoKey(secret)
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(kek)
	dek, err := crypto.OpenAAD(kek, m.Fido.WrappedDEK, m.fidoAAD(m.Fido.CredID, m.Fido.Salt))
	if err != nil {
		return nil, ErrWrongPassword
	}
	return dek, nil
}

// DisableFido убирает слот ключа FIDO2; пароль, Hello и ключ восстановления продолжают работать.
func (v Vault) DisableFido() error {
	return v.updateMeta(func(m *meta) error {
		m.Fido = nil
		return nil
	})
}

// EnableHello добавляет слот Hello: dek оборачивается ключом из secret (подписи challenge).
func (v Vault) EnableHello(dek []byte, name string, challenge, secret []byte) error {
	return v.updateMeta(func(m *meta) error {
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
		return nil
	})
}

// UnlockHello открывает DEK ключом из подписи Hello.
func (v Vault) UnlockHello(secret []byte) ([]byte, error) {
	m, err := v.readMeta()
	if err != nil {
		return nil, err
	}
	if m.Hello == nil {
		return nil, errors.New(i18n.T("вход через Windows Hello не включён"))
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
	return v.updateMeta(func(m *meta) error {
		m.Hello = nil
		return nil
	})
}

// Открытая папка → data.enc. Порядок важен при сбое: пока data.enc не заменён, маркер и открытая копия целы;
// после замены data.enc полный, а недоудалённая папка без маркера при следующем Decrypt затирается.
func (v Vault) Encrypt(dek []byte) error {
	m, err := v.readMeta()
	if err != nil {
		return err
	}
	if m.Version == 1 {
		return v.encryptV1(dek)
	}
	hdr := binary.BigEndian.AppendUint64([]byte(streamMagic), m.Counter+1)
	tmp := v.path(dataFile + ".tmp")
	var files int
	err = retry(func() (err error) {
		files, err = v.writeStream(tmp, dek, hdr)
		return err
	})
	if err == nil && files == 0 {
		// Пустая папка — признак того, что приложение стёрло данные или упало: архив из неё затёр бы рабочую копию.
		err = ErrEmptyData
	}
	if err == nil {
		err = v.keepBackup()
	}
	if err == nil {
		err = retry(func() error { return os.Rename(tmp, v.path(dataFile)) })
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// Сбой между двумя записями оставляет data.enc с номером на единицу больше: Decrypt такое принимает и подтягивает номер.
	// Файл перечитывается: пока шло шифрование, могли включить Hello или сменить пароль, и записать устаревшую копию нельзя.
	counter := m.Counter + 1
	if err := v.updateMeta(func(cur *meta) error {
		cur.Counter = counter
		return nil
	}); err != nil {
		return err
	}
	return v.closeOpen()
}

func (v Vault) closeOpen() error {
	if err := os.Remove(v.path(openFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return removeAll(v.dataDir())
}

// Хранилище версии 1 (до первой разблокировки новой версией) пишется прежним форматом: один блок без заголовка.
func (v Vault) encryptV1(dek []byte) error {
	tar, files, err := packDir(v.dataDir(), v.Exclude)
	if err != nil {
		return err
	}
	defer crypto.Wipe(tar)
	if files == 0 {
		return ErrEmptyData
	}
	blob, err := crypto.Seal(dek, tar)
	if err != nil {
		return err
	}
	if err := v.keepBackup(); err != nil {
		return err
	}
	if err := writeAtomic(v.path(dataFile), blob); err != nil {
		return err
	}
	return v.closeOpen()
}

// writeStream шифрует открытую папку в файл path потоком: архив не собирается в памяти, размер не ограничен.
func (v Vault) writeStream(path string, dek, hdr []byte) (int, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	bw := bufio.NewWriterSize(f, 256<<10)
	if _, err := bw.Write(hdr); err != nil {
		return 0, err
	}
	sw, err := crypto.NewSealWriter(dek, hdr, bw)
	if err != nil {
		return 0, err
	}
	files, err := writeTar(sw, v.dataDir(), v.Exclude)
	if cerr := sw.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return 0, err
	}
	if err := bw.Flush(); err != nil {
		return 0, err
	}
	// Sync до rename: после потери питания на месте data.enc не должно оказаться недописанного файла.
	if err := f.Sync(); err != nil {
		return 0, err
	}
	return files, f.Close()
}

// Предыдущий архив остаётся на случай, если в новый попало повреждённое состояние приложения. Жёсткая ссылка не копирует
// гигабайты; где ссылок нет, файл копируется.
func (v Vault) keepBackup() error {
	cur := v.path(dataFile)
	if _, err := os.Stat(cur); err != nil {
		return nil
	}
	tmp := v.path(backupFile + ".tmp")
	_ = os.Remove(tmp)
	if err := os.Link(cur, tmp); err != nil {
		if err := copyFile(cur, tmp); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	return retry(func() error { return os.Rename(tmp, v.path(backupFile)) })
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	return writeStreamFile(dst, in)
}

// writeStreamFile пишет поток в файл и сбрасывает его на диск.
func writeStreamFile(path string, r io.Reader) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// data.enc → открытая папка. Маркер ставится после распаковки: частичная распаковка не считается открытыми данными.
func (v Vault) Decrypt(dek []byte) error {
	f, err := os.Open(v.path(dataFile))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	hdr := make([]byte, headerSize)
	if n, _ := io.ReadFull(f, hdr); n == headerSize && string(hdr[:len(streamMagic)]) == streamMagic {
		return v.decryptStream(dek, f, hdr)
	}
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

// decryptStream распаковывает поток блоков по мере проверки. Блок, не прошедший проверку на середине, отменяет всё:
// уже распакованное удаляется.
func (v Vault) decryptStream(dek []byte, r io.Reader, hdr []byte) error {
	m, err := v.readMeta()
	if err != nil {
		return err
	}
	if m.Version == 1 {
		return errors.New(i18n.T("data.enc не соответствует версии хранилища"))
	}
	n := binary.BigEndian.Uint64(hdr[len(streamMagic):])
	if n < m.Counter {
		return ErrRollback
	}
	if err := removeAll(v.dataDir()); err != nil {
		return err
	}
	or, err := crypto.NewOpenReader(dek, hdr, r)
	if err != nil {
		return err
	}
	defer or.Close()
	err = extractTar(or, v.dataDir())
	if err == nil {
		err = or.Verify()
	}
	if err != nil {
		return errors.Join(err, removeAll(v.dataDir()))
	}
	if n > m.Counter {
		if err := v.updateMeta(func(cur *meta) error {
			cur.Counter = max(cur.Counter, n)
			return nil
		}); err != nil {
			return errors.Join(err, removeAll(v.dataDir()))
		}
	}
	return os.WriteFile(v.path(openFile), nil, 0o600)
}

// verifyData проверяет, что файл формата data.enc открывается ключом, ничего не распаковывая. Возвращает номер записи
// и есть ли у файла заголовок (у формата версии 1 его нет).
func verifyData(dek []byte, path string) (counter uint64, header bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = f.Close() }()
	hdr := make([]byte, headerSize)
	if n, _ := io.ReadFull(f, hdr); n == headerSize && string(hdr[:len(streamMagic)]) == streamMagic {
		or, err := crypto.NewOpenReader(dek, hdr, f)
		if err != nil {
			return 0, false, err
		}
		defer or.Close()
		return binary.BigEndian.Uint64(hdr[len(streamMagic):]), true, or.Verify()
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		return 0, false, err
	}
	if bytes.HasPrefix(blob, []byte(dataMagic)) && len(blob) >= headerSize {
		tar, err := crypto.OpenAAD(dek, blob[headerSize:], blob[:headerSize])
		crypto.Wipe(tar)
		return binary.BigEndian.Uint64(blob[len(dataMagic):headerSize]), true, err
	}
	tar, err := crypto.Open(dek, blob)
	crypto.Wipe(tar)
	return 0, false, err
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
		return nil, errors.New(i18n.T("data.enc не соответствует версии хранилища"))
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

// RestoreBackup возвращает предыдущий архив и опускает номер записи до его номера: это осознанное действие владельца
// (нужен ключ), в отличие от тихой подмены data.enc. Открытой копии быть не должно.
func (v Vault) RestoreBackup(dek []byte) error {
	if v.NeedsRecovery() {
		return errors.New(i18n.T("есть открытые данные: сначала закройте приложение"))
	}
	counter, _, err := verifyData(dek, v.path(backupFile))
	if err != nil {
		return err
	}
	m, err := v.readMeta()
	if err != nil {
		return err
	}
	m.Counter = counter
	// Сначала номер, потом файл: сбой между ними оставляет data.enc новее номера, а это допустимо.
	if err := v.writeMeta(m); err != nil {
		return err
	}
	return retry(func() error { return os.Rename(v.path(backupFile), v.path(dataFile)) })
}

// ExportMeta — vault.json без слота Hello (ключ Hello работает только на этом ПК); он уже зашифрован.
func (v Vault) ExportMeta() ([]byte, error) {
	if v.NeedsRecovery() {
		return nil, errors.New(i18n.T("есть открытые данные: сначала закройте приложение"))
	}
	m, err := v.readMeta()
	if err != nil {
		return nil, err
	}
	m.Hello = nil
	return json.Marshal(m)
}

// DataPath — зашифрованный архив хранилища (для переноса потоком).
func (v Vault) DataPath() string { return v.path(dataFile) }

// Export возвращает vault.json без слота Hello и data.enc: оба файла уже зашифрованы.
func (v Vault) Export() (metaJSON, data []byte, err error) {
	if metaJSON, err = v.ExportMeta(); err != nil {
		return nil, nil, err
	}
	if data, err = os.ReadFile(v.path(dataFile)); err != nil {
		return nil, nil, err
	}
	return metaJSON, data, nil
}

// Import кладёт файлы из Export на место и проверяет, что secret (пароль или ключ восстановления) их открывает;
// иначе всё убирается. Существующее хранилище не перезаписывается.
func (v Vault) Import(metaJSON, data, secret []byte) error {
	return v.ImportFrom(metaJSON, bytes.NewReader(data), secret)
}

// ImportFrom — Import с архивом из потока: большой data.enc не читается в память.
func (v Vault) ImportFrom(metaJSON []byte, data io.Reader, secret []byte) (err error) {
	if v.Exists() {
		return errors.New(i18n.T("хранилище уже есть"))
	}
	if _, err := os.Stat(v.path(dataFile)); err == nil {
		return errors.New(i18n.T("рядом лежит data.enc без vault.json: разберитесь с ним вручную"))
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
			_ = os.Remove(v.path(dataFile + ".tmp"))
		}
	}()
	tmp := v.path(dataFile + ".tmp")
	if err := writeStreamFile(tmp, data); err != nil {
		return err
	}
	if err := retry(func() error { return os.Rename(tmp, v.path(dataFile)) }); err != nil {
		return err
	}
	if err := writeAtomic(v.path(metaFile), metaJSON); err != nil {
		return err
	}
	if m, err = v.readMeta(); err != nil {
		return err
	}
	dek, err := v.Unlock(secret)
	if err != nil {
		return err
	}
	defer crypto.Wipe(dek)
	counter, header, err := verifyData(dek, v.path(dataFile))
	if err != nil {
		return err
	}
	// Тот же запрет отката, что при расшифровке: архив не старше записи в vault.json.
	if (header && counter < m.Counter) || (!header && m.Version != 1 && m.Counter > 0) {
		return ErrRollback
	}
	return nil
}
