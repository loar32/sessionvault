package vault

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/loar32/sessionvault/internal/crypto"
	"github.com/loar32/sessionvault/internal/recovery"
)

func newVault(t *testing.T) Vault {
	t.Helper()
	v := Vault{Dir: t.TempDir(), DataName: "tdata"}
	write(t, filepath.Join(v.dataDir(), "key_datas"), "секрет")
	write(t, filepath.Join(v.dataDir(), "emoji", "cache"), "кэш")
	return v
}

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRoundTrip(t *testing.T) {
	v := newVault(t)
	dek, err := v.Create([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Encrypt(dek); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(v.dataDir()); !os.IsNotExist(err) {
		t.Fatal("открытая папка осталась после шифрования")
	}
	blob := read(t, v.path(dataFile))
	if bytes.Contains([]byte(blob), []byte("секрет")) {
		t.Fatal("в data.enc виден открытый текст")
	}

	dek2, err := v.Unlock([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Decrypt(dek2); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(v.dataDir(), "key_datas")) != "секрет" || read(t, filepath.Join(v.dataDir(), "emoji", "cache")) != "кэш" {
		t.Fatal("данные после расшифровки не совпали")
	}
	if !v.NeedsRecovery() {
		t.Fatal("маркер открытых данных не создан")
	}
}

func TestWrongPassword(t *testing.T) {
	v := newVault(t)
	if _, err := v.Create([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Unlock([]byte("другой")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("ждали ErrWrongPassword, получили %v", err)
	}
}

// Сбой питания после Decrypt: открытые данные и маркер остались, Encrypt их возвращает в архив.
func TestRecovery(t *testing.T) {
	v := newVault(t)
	dek, _ := v.Create([]byte("pw"))
	if err := v.Encrypt(dek); err != nil {
		t.Fatal(err)
	}
	if err := v.Decrypt(dek); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(v.dataDir(), "key_datas"), "новое")
	if !v.NeedsRecovery() {
		t.Fatal("после Decrypt должен быть маркер")
	}
	if err := v.Encrypt(dek); err != nil {
		t.Fatal(err)
	}
	if v.NeedsRecovery() {
		t.Fatal("маркер остался после дошифровки")
	}
	if err := v.Decrypt(dek); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(v.dataDir(), "key_datas")) != "новое" {
		t.Fatal("правка не сохранилась при дошифровке")
	}
}

// Недоудалённая после сбоя папка без маркера не должна смешиваться с новой распаковкой.
func TestDecryptWipesStale(t *testing.T) {
	v := newVault(t)
	dek, _ := v.Create([]byte("pw"))
	if err := v.Encrypt(dek); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(v.dataDir(), "stale"), "мусор")
	if err := v.Decrypt(dek); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(v.dataDir(), "stale")); !os.IsNotExist(err) {
		t.Fatal("старый файл пережил распаковку")
	}
}

func TestUnpackRejectsEscape(t *testing.T) {
	for _, name := range []string{"../evil", "/abs", `C:\abs`, "a/../../evil"} {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("x"))
		_ = tw.Close()
		if err := unpackDir(buf.Bytes(), filepath.Join(t.TempDir(), "d")); err == nil {
			t.Fatalf("путь %q принят", name)
		}
	}
}

func TestUnpackRejectsSymlink(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "link", Linkname: `C:\Windows`, Typeflag: tar.TypeSymlink})
	_ = tw.Close()
	if err := unpackDir(buf.Bytes(), filepath.Join(t.TempDir(), "d")); err == nil {
		t.Fatal("симлинк принят")
	}
}

func TestUnlockRejectsBadParams(t *testing.T) {
	v := newVault(t)
	if _, err := v.Create([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	b := read(t, v.path(metaFile))
	for _, bad := range []string{`"Memory":4194304`, `"Memory":1`, `"Time":0`, `"Threads":0`} {
		key := bad[:strings.Index(bad, ":")]
		re := regexp.MustCompile(key + `:\d+`)
		write(t, v.path(metaFile), re.ReplaceAllString(b, bad))
		if _, err := v.Unlock([]byte("pw")); err == nil || errors.Is(err, ErrWrongPassword) {
			t.Fatalf("параметры %s приняты или приняты за неверный пароль: %v", bad, err)
		}
	}
}

func TestEmptyDataKeepsArchive(t *testing.T) {
	v := newVault(t)
	dek, _ := v.Create([]byte("pw"))
	if err := v.Encrypt(dek); err != nil {
		t.Fatal(err)
	}
	if err := v.Decrypt(dek); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(v.dataDir(), "emoji")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(v.dataDir(), "key_datas")); err != nil {
		t.Fatal(err)
	}
	if err := v.Encrypt(dek); !errors.Is(err, ErrEmptyData) {
		t.Fatalf("ждали ErrEmptyData, получили %v", err)
	}
	if !v.NeedsRecovery() {
		t.Fatal("при отказе маркер и открытая папка должны остаться")
	}
	if err := v.Decrypt(dek); err != nil {
		t.Fatalf("прежний архив испорчен: %v", err)
	}
}

func TestBackupHoldsPreviousArchive(t *testing.T) {
	v := newVault(t)
	dek, _ := v.Create([]byte("pw"))
	if err := v.Encrypt(dek); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(v.path(backupFile)); err == nil {
		t.Fatal("первое шифрование не должно создавать .bak")
	}
	if err := v.Decrypt(dek); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(v.dataDir(), "key_datas"), "новое")
	if err := v.Encrypt(dek); err != nil {
		t.Fatal(err)
	}
	if err := v.RestoreBackup(dek); err != nil {
		t.Fatal(err)
	}
	if err := v.Decrypt(dek); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(v.dataDir(), "key_datas")) != "секрет" {
		t.Fatal(".bak должен хранить прежнее состояние")
	}
}

func TestRollbackRejected(t *testing.T) {
	v := newVault(t)
	dek, _ := v.Create([]byte("pw"))
	if err := v.Encrypt(dek); err != nil {
		t.Fatal(err)
	}
	old := read(t, v.path(dataFile))
	if err := v.Decrypt(dek); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(v.dataDir(), "key_datas"), "новое")
	if err := v.Encrypt(dek); err != nil {
		t.Fatal(err)
	}
	write(t, v.path(dataFile), old)
	if err := v.Decrypt(dek); !errors.Is(err, ErrRollback) {
		t.Fatalf("ждали ErrRollback, получили %v", err)
	}
}

func TestMetaTamperRejected(t *testing.T) {
	v := newVault(t)
	if _, err := v.Create([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	b := read(t, v.path(metaFile))
	re := regexp.MustCompile(`"Time":\d+`)
	write(t, v.path(metaFile), re.ReplaceAllString(b, `"Time":2`))
	if _, err := v.Unlock([]byte("pw")); err == nil {
		t.Fatal("подмена параметров вывода ключа должна ломать разблокировку")
	}
}

// Сбой между записью data.enc и vault.json: номер архива на единицу больше номера в vault.json.
func TestCrashBetweenWrites(t *testing.T) {
	v := newVault(t)
	dek, _ := v.Create([]byte("pw"))
	if err := v.Encrypt(dek); err != nil {
		t.Fatal(err)
	}
	if err := v.Decrypt(dek); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(v.dataDir(), "key_datas"), "новое")
	meta := read(t, v.path(metaFile))
	if err := v.Encrypt(dek); err != nil {
		t.Fatal(err)
	}
	write(t, v.path(metaFile), meta)
	if err := v.Decrypt(dek); err != nil {
		t.Fatalf("сбой между записями должен приниматься: %v", err)
	}
	if read(t, filepath.Join(v.dataDir(), "key_datas")) != "новое" {
		t.Fatal("новый архив не открылся")
	}
	m, _ := v.readMeta()
	if m.Counter != 2 {
		t.Fatalf("номер записи не подтянут: %d", m.Counter)
	}
}

func TestMigrationFromV1(t *testing.T) {
	v := newVault(t)
	salt, _ := crypto.NewSalt()
	dek, _ := crypto.NewKey()
	p := crypto.Params{Memory: 8 * 1024, Time: 1, Threads: 1}
	kek := crypto.DeriveKey([]byte("pw"), salt, p)
	wrapped, _ := crypto.Seal(kek, dek)
	b, _ := json.Marshal(meta{Version: 1, Salt: salt, Params: p, WrappedDEK: wrapped})
	write(t, v.path(metaFile), string(b))
	tarData, _, err := packDir(v.dataDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := crypto.Seal(dek, tarData)
	write(t, v.path(dataFile), string(blob))
	if err := removeAll(v.dataDir()); err != nil {
		t.Fatal(err)
	}

	got, err := v.Unlock([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := v.readMeta(); m.Version != metaV2 {
		t.Fatalf("после разблокировки версия %d", m.Version)
	}
	if err := v.Decrypt(got); err != nil {
		t.Fatalf("старый архив не открылся: %v", err)
	}
	if err := v.Encrypt(got); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(read(t, v.path(dataFile)), dataMagic) {
		t.Fatal("после записи архив должен быть версии 2")
	}
	// Старый архив после первой записи v2 подсунуть нельзя.
	write(t, v.path(dataFile), string(blob))
	if err := v.Decrypt(got); !errors.Is(err, ErrRollback) {
		t.Fatalf("ждали ErrRollback для старого формата, получили %v", err)
	}
}

func TestExcludeSkipsCaches(t *testing.T) {
	v := newVault(t)
	v.Exclude = []string{`cache`, `emoji\skip.bin`}
	write(t, filepath.Join(v.dataDir(), "cache", "blob"), "кэш")
	write(t, filepath.Join(v.dataDir(), "emoji", "skip.bin"), "пропуск")
	dek, _ := v.Create([]byte("pw"))
	if err := v.Encrypt(dek); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(v.dataDir()); err == nil {
		t.Fatal("открытая папка должна быть удалена целиком, вместе с кэшем")
	}
	if err := v.Decrypt(dek); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(v.dataDir(), "cache")); err == nil {
		t.Fatal("кэш попал в архив")
	}
	if _, err := os.Stat(filepath.Join(v.dataDir(), "emoji", "skip.bin")); err == nil {
		t.Fatal("исключённый файл попал в архив")
	}
	if read(t, filepath.Join(v.dataDir(), "emoji", "cache")) != "кэш" {
		t.Fatal("соседний файл потерян")
	}
}

func TestArchiveSizeLimit(t *testing.T) {
	old := maxArchive
	maxArchive = 10
	defer func() { maxArchive = old }()
	v := newVault(t)
	write(t, filepath.Join(v.dataDir(), "big"), strings.Repeat("x", 100))
	write(t, filepath.Join(v.dataDir(), "z-big"), strings.Repeat("x", 100))
	dek, _ := v.Create([]byte("pw"))
	if err := v.Encrypt(dek); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("ждали ErrTooLarge, получили %v", err)
	}
	if _, err := os.Stat(v.dataDir()); err != nil {
		t.Fatal("при отказе открытая папка должна остаться")
	}
}

func TestExcludePatterns(t *testing.T) {
	ex := []string{`*\Cache`, `*\Service Worker\CacheStorage`, `Crashpad`}
	for rel, want := range map[string]bool{
		`Default\Cache`: true, `Profile 1\cache`: true, `Default\Service Worker\CacheStorage`: true, `Crashpad`: true,
		`Default\Cookies`: false, `Cache`: false, `Default\Cache\x`: false, `Default\Network\Cookies`: false,
	} {
		if got := excluded(rel, ex); got != want {
			t.Errorf("%q: получили %v, ждали %v", rel, got, want)
		}
	}
}

func TestHelloSlot(t *testing.T) {
	v := newVault(t)
	dek, err := v.Create([]byte("парольпароль1"))
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{9}, 256)
	challenge := bytes.Repeat([]byte{3}, 32)
	if err := v.EnableHello(dek, "SessionVault", challenge, secret); err != nil {
		t.Fatal(err)
	}
	name, ch, ok := v.HelloInfo()
	if !ok || name != "SessionVault" || !bytes.Equal(ch, challenge) {
		t.Fatalf("HelloInfo: %q %x %v", name, ch, ok)
	}
	got, err := v.UnlockHello(secret)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("Hello не открыл DEK: %v", err)
	}
	if _, err := v.UnlockHello(bytes.Repeat([]byte{8}, 256)); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("чужой секрет: %v", err)
	}
	if got, err := v.Unlock([]byte("парольпароль1")); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("пароль перестал работать: %v", err)
	}
	// Запись данных (счётчик) не стирает слот.
	if err := v.Encrypt(dek); err != nil {
		t.Fatal(err)
	}
	if _, err := v.UnlockHello(secret); err != nil {
		t.Fatalf("слот потерян после Encrypt: %v", err)
	}
	if err := v.DisableHello(); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := v.HelloInfo(); ok {
		t.Fatal("слот остался после DisableHello")
	}
	if _, err := v.UnlockHello(secret); err == nil {
		t.Fatal("Hello открыл хранилище после отключения")
	}
}

func TestHelloSlotTamperRejected(t *testing.T) {
	v := newVault(t)
	dek, _ := v.Create([]byte("парольпароль1"))
	secret := bytes.Repeat([]byte{9}, 256)
	if err := v.EnableHello(dek, "SessionVault", bytes.Repeat([]byte{3}, 32), secret); err != nil {
		t.Fatal(err)
	}
	m, _ := v.readMeta()
	m.Hello.Challenge[0] ^= 1 // другой запрос при том же слоте
	if err := v.writeMeta(m); err != nil {
		t.Fatal(err)
	}
	if _, err := v.UnlockHello(secret); err == nil {
		t.Fatal("подмена challenge не замечена")
	}
}

func TestPackSkipsJunction(t *testing.T) {
	v := newVault(t)
	outside := filepath.Join(t.TempDir(), "outside")
	write(t, filepath.Join(outside, "secret.txt"), "чужое")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(v.dataDir(), "link"), outside).CombinedOutput(); err != nil {
		t.Skip("junction не создан:", string(out))
	}
	dek, _ := v.Create([]byte("pw"))
	if err := v.Encrypt(dek); err != nil {
		t.Fatalf("junction в данных сорвал шифрование: %v", err)
	}
	if _, err := os.Stat(v.dataDir()); err == nil {
		t.Fatal("открытая папка не удалена")
	}
	if read(t, filepath.Join(outside, "secret.txt")) != "чужое" {
		t.Fatal("удаление открытой папки задело файл за ссылкой")
	}
	if err := v.Decrypt(dek); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(v.dataDir(), "link")); err == nil {
		t.Fatal("ссылка попала в архив")
	}
}

func TestRecoveryAndPassword(t *testing.T) {
	v := newVault(t)
	dek, err := v.Create([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Encrypt(dek); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{9}, 32)
	if _, err := v.UnlockRecovery(key); err == nil {
		t.Fatal("ключ принят без слота")
	}
	if err := v.SetRecovery(dek, key); err != nil {
		t.Fatal(err)
	}
	got, err := v.UnlockRecovery(key)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("ключ восстановления не открыл: %v", err)
	}
	if _, err := v.UnlockRecovery(bytes.Repeat([]byte{8}, 32)); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("чужой ключ: %v", err)
	}
	words, _ := recovery.Words(key)
	if got, err := v.Unlock([]byte(words)); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("Unlock со словами: %v", err)
	}
	if err := v.SetPassword(dek, []byte("новый пароль")); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Unlock([]byte("pw")); !errors.Is(err, ErrWrongPassword) {
		t.Fatal("старый пароль всё ещё работает")
	}
	if got, err := v.Unlock([]byte("новый пароль")); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("новый пароль: %v", err)
	}
	if _, err := v.UnlockRecovery(key); err != nil {
		t.Fatalf("слот восстановления сломан сменой пароля: %v", err)
	}
	// Слот нельзя перенести в другое хранилище.
	other := newVault(t)
	odek, _ := other.Create([]byte("pw"))
	m, _ := v.readMeta()
	om, _ := other.readMeta()
	om.Recovery = m.Recovery
	if err := other.writeMeta(om); err != nil {
		t.Fatal(err)
	}
	if _, err := other.UnlockRecovery(key); err == nil {
		t.Fatal("слот из другого хранилища принят")
	}
	crypto.Wipe(odek)
}

func TestExportImport(t *testing.T) {
	v := newVault(t)
	dek, _ := v.Create([]byte("pw"))
	if err := v.EnableHello(dek, "k", []byte("c"), []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := v.Encrypt(dek); err != nil {
		t.Fatal(err)
	}
	m, d, err := v.Export()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(m, []byte("Hello")) {
		t.Fatal("слот Hello попал в экспорт")
	}
	dst := Vault{Dir: t.TempDir(), DataName: "tdata"}
	if err := dst.Import(m, d, []byte("не тот")); err == nil || dst.Exists() {
		t.Fatalf("импорт с неверным паролем: %v", err)
	}
	if _, err := os.Stat(dst.path(dataFile)); !os.IsNotExist(err) {
		t.Fatal("после неудачного импорта остался data.enc")
	}
	if err := dst.Import(m, d, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	got, err := dst.Unlock([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if err := dst.Decrypt(got); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(dst.dataDir(), "key_datas")) != "секрет" {
		t.Fatal("данные после импорта не совпали")
	}
	if err := dst.Import(m, d, []byte("pw")); err == nil {
		t.Fatal("импорт поверх существующего хранилища")
	}
}
