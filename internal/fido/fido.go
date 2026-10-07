// Package fido получает стабильный секрет от ключа FIDO2 (YubiKey и подобные): расширение hmac-secret возвращает
// 32 байта, зависящие от ключа, учётных данных и соли. Windows сама показывает окно с PIN и касанием; webauthn.dll
// вызывается напрямую, без сторонних библиотек. Нужна Windows 11 (API версии 6 и выше).
package fido

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/loar32/sessionvault/internal/i18n"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/loar32/sessionvault/internal/hello"
)

var (
	dll                  = windows.NewLazySystemDLL("webauthn.dll")
	pGetAPIVersion       = dll.NewProc("WebAuthNGetApiVersionNumber")
	pMakeCredential      = dll.NewProc("WebAuthNAuthenticatorMakeCredential")
	pGetAssertion        = dll.NewProc("WebAuthNAuthenticatorGetAssertion")
	pFreeAttestation     = dll.NewProc("WebAuthNFreeCredentialAttestation")
	pFreeAssertion       = dll.NewProc("WebAuthNFreeAssertion")
	pCancellationID      = dll.NewProc("WebAuthNGetCancellationId")
	pCancel              = dll.NewProc("WebAuthNCancelCurrentOperation")
	user32               = windows.NewLazySystemDLL("user32.dll")
	pGetForegroundWindow = user32.NewProc("GetForegroundWindow")
	pGetDesktopWindow    = user32.NewProc("GetDesktopWindow")
)

const (
	// Идентификатор стороны: в webauthn он нужен для привязки учётных данных; сайта за ним нет, сети тоже.
	rpID = "sessionvault.local"

	minAPIVersion = 6 // pHmacSecretSaltValues в параметрах GetAssertion

	attachmentCrossPlatform = 2 // только внешние ключи: встроенный Windows Hello hmac-secret не умеет
	uvRequired              = 1 // PIN ключа обязателен: без него вор с ключом хранилище не откроет
	attestationNone         = 1
	algES256                = -7
	algRS256                = -257

	ntUserCancelled = 0x80090036
	nteNotSupported = 0x80090029
)

// Timeout — сколько Windows ждёт PIN и касание; по истечении окно закрывается само.
var Timeout = 60 * time.Second

var ErrNotSupported = errors.New("FIDO2 hmac-secret не поддерживается Windows (нужна Windows 11) или ключ не найден")

type rpEntity struct {
	Version uint32
	ID      *uint16
	Name    *uint16
	Icon    *uint16
}

type userEntity struct {
	Version     uint32
	IDLen       uint32
	ID          *byte
	Name        *uint16
	Icon        *uint16
	DisplayName *uint16
}

type clientData struct {
	Version uint32
	Len     uint32
	JSON    *byte
	HashAlg *uint16
}

type coseParam struct {
	Version uint32
	Type    *uint16
	Alg     int32
}

type coseParams struct {
	Count  uint32
	Params *coseParam
}

type extension struct {
	ID    *uint16
	Len   uint32
	Value unsafe.Pointer
}

type extensions struct {
	Count uint32
	Items *extension
}

type credentials struct {
	Count uint32
	Items unsafe.Pointer
}

type makeOptions struct {
	Version               uint32
	Timeout               uint32
	CredentialList        credentials
	Extensions            extensions
	Attachment            uint32
	RequireResidentKey    int32
	UserVerification      uint32
	Attestation           uint32
	Flags                 uint32
	CancellationID        unsafe.Pointer
	ExcludeList           unsafe.Pointer
	EnterpriseAttestation uint32
	LargeBlobSupport      uint32
	PreferResidentKey     int32
}

type credentialEx struct {
	Version    uint32
	IDLen      uint32
	ID         *byte
	Type       *uint16
	Transports uint32
}

type credentialList struct {
	Count uint32
	Items **credentialEx
}

type hmacSalt struct {
	FirstLen  uint32
	First     *byte
	SecondLen uint32
	Second    *byte
}

type saltValues struct {
	Global    *hmacSalt
	CredCount uint32
	CredList  unsafe.Pointer
}

type getOptions struct {
	Version        uint32
	Timeout        uint32
	CredentialList credentials
	Extensions     extensions
	Attachment     uint32
	UserVerif      uint32
	Flags          uint32
	U2fAppID       *uint16
	U2fAppIDUsed   *int32
	CancellationID unsafe.Pointer
	AllowList      *credentialList
	LargeBlobOp    uint32
	LargeBlobLen   uint32
	LargeBlob      *byte
	HmacSalts      *saltValues
	PrivateMode    int32
}

type attestation struct {
	Version    uint32
	FormatType *uint16
	AuthLen    uint32
	AuthData   *byte
	AttLen     uint32
	Att        *byte
	DecodeType uint32
	Decode     unsafe.Pointer
	AttObjLen  uint32
	AttObj     *byte
	CredIDLen  uint32
	CredID     *byte
}

type credential struct {
	Version uint32
	IDLen   uint32
	ID      *byte
	Type    *uint16
}

type assertion struct {
	Version         uint32
	AuthLen         uint32
	AuthData        *byte
	SigLen          uint32
	Sig             *byte
	Credential      credential
	UserIDLen       uint32
	UserID          *byte
	Extensions      extensions
	LargeBlobLen    uint32
	LargeBlob       *byte
	LargeBlobStatus uint32
	HmacSecret      *hmacSalt
}

func u16(s string) *uint16 { p, _ := windows.UTF16PtrFromString(s); return p }

func apiVersion() uint32 {
	if dll.Load() != nil || pGetAPIVersion.Find() != nil {
		return 0
	}
	v, _, _ := pGetAPIVersion.Call()
	return uint32(v)
}

// Supported — webauthn.dll достаточно новая для hmac-secret. Ключ при этом может быть не вставлен: это видно только при операции.
func Supported() bool { return apiVersion() >= minAPIVersion }

func window() uintptr {
	if h, _, _ := pGetForegroundWindow.Call(); h != 0 {
		return h
	}
	h, _, _ := pGetDesktopWindow.Call()
	return h
}

func newClientData(typ string) (*clientData, []byte, error) {
	ch := make([]byte, 32)
	if _, err := rand.Read(ch); err != nil {
		return nil, nil, err
	}
	js := []byte(fmt.Sprintf(`{"type":"%s","challenge":"%s","origin":"https://%s"}`, typ, base64.RawURLEncoding.EncodeToString(ch), rpID))
	return &clientData{Version: 1, Len: uint32(len(js)), JSON: &js[0], HashAlg: u16("SHA-256")}, js, nil
}

func hresult(name string, r uintptr) error {
	switch uint32(r) {
	case ntUserCancelled:
		return errors.New(i18n.T("операция отменена или не завершена вовремя"))
	case nteNotSupported:
		return ErrNotSupported
	}
	return fmt.Errorf("%s: HRESULT 0x%08x", name, uint32(r))
}

// Create создаёт на внешнем ключе учётные данные с hmac-secret и возвращает их идентификатор.
// Пользователь вводит PIN ключа и касается его.
func Create() ([]byte, error) {
	if !Supported() {
		return nil, ErrNotSupported
	}
	cd, js, err := newClientData("webauthn.create")
	if err != nil {
		return nil, err
	}
	userID := make([]byte, 16)
	if _, err := rand.Read(userID); err != nil {
		return nil, err
	}
	rp := &rpEntity{Version: 1, ID: u16(rpID), Name: u16("SessionVault")}
	user := &userEntity{Version: 1, IDLen: uint32(len(userID)), ID: &userID[0], Name: u16("SessionVault"), DisplayName: u16("SessionVault")}
	pub := u16("public-key")
	params := []coseParam{{Version: 1, Type: pub, Alg: algES256}, {Version: 1, Type: pub, Alg: algRS256}}
	cp := &coseParams{Count: uint32(len(params)), Params: &params[0]}
	enable := int32(1)
	ext := []extension{{ID: u16("hmac-secret"), Len: 4, Value: unsafe.Pointer(&enable)}}
	opts := &makeOptions{
		Version:          4,
		Timeout:          uint32(Timeout / time.Millisecond),
		Extensions:       extensions{Count: 1, Items: &ext[0]},
		Attachment:       attachmentCrossPlatform,
		UserVerification: uvRequired,
		Attestation:      attestationNone,
	}
	var att *attestation
	var r uintptr
	cancel := new(windows.GUID)
	if r, _, _ := pCancellationID.Call(uintptr(unsafe.Pointer(cancel))); r == 0 {
		opts.CancellationID = unsafe.Pointer(cancel)
	}
	err = onThread(cancel, func() {
		r, _, _ = pMakeCredential.Call(window(), uintptr(unsafe.Pointer(rp)), uintptr(unsafe.Pointer(user)), uintptr(unsafe.Pointer(cp)),
			uintptr(unsafe.Pointer(cd)), uintptr(unsafe.Pointer(opts)), uintptr(unsafe.Pointer(&att)))
	})
	runtime.KeepAlive(js)
	runtime.KeepAlive(ext)
	runtime.KeepAlive(params)
	if err != nil {
		return nil, err
	}
	if r != 0 {
		return nil, hresult("создание учётных данных", r)
	}
	if att == nil {
		return nil, errors.New(i18n.T("ключ не вернул учётные данные"))
	}
	defer func() { _, _, _ = pFreeAttestation.Call(uintptr(unsafe.Pointer(att))) }()
	if att.CredIDLen == 0 || att.CredID == nil {
		return nil, errors.New(i18n.T("ключ не вернул идентификатор учётных данных"))
	}
	return append([]byte(nil), unsafe.Slice(att.CredID, att.CredIDLen)...), nil
}

// Secret возвращает 32 байта hmac-secret для учётных данных id и соли salt (32 байта). Нужны PIN и касание.
func Secret(id, salt []byte) ([]byte, error) {
	if !Supported() {
		return nil, ErrNotSupported
	}
	if len(id) == 0 || len(salt) != 32 {
		return nil, errors.New(i18n.T("неверные учётные данные или соль"))
	}
	cd, js, err := newClientData("webauthn.get")
	if err != nil {
		return nil, err
	}
	cred := &credentialEx{Version: 1, IDLen: uint32(len(id)), ID: &id[0], Type: u16("public-key")}
	allow := &credentialList{Count: 1, Items: &cred}
	salts := &saltValues{Global: &hmacSalt{FirstLen: 32, First: &salt[0]}}
	opts := &getOptions{
		Version:    6,
		Timeout:    uint32(Timeout / time.Millisecond),
		Attachment: attachmentCrossPlatform,
		UserVerif:  uvRequired,
		AllowList:  allow,
		HmacSalts:  salts,
	}
	var as *assertion
	var r uintptr
	cancel := new(windows.GUID)
	if r, _, _ := pCancellationID.Call(uintptr(unsafe.Pointer(cancel))); r == 0 {
		opts.CancellationID = unsafe.Pointer(cancel)
	}
	err = onThread(cancel, func() {
		r, _, _ = pGetAssertion.Call(window(), uintptr(unsafe.Pointer(u16(rpID))), uintptr(unsafe.Pointer(cd)),
			uintptr(unsafe.Pointer(opts)), uintptr(unsafe.Pointer(&as)))
	})
	runtime.KeepAlive(js)
	runtime.KeepAlive(cred)
	if err != nil {
		return nil, err
	}
	if r != 0 {
		return nil, hresult("получение секрета", r)
	}
	if as == nil {
		return nil, errors.New(i18n.T("ключ не вернул ответ"))
	}
	defer func() { _, _, _ = pFreeAssertion.Call(uintptr(unsafe.Pointer(as))) }()
	if as.Version < 3 || as.HmacSecret == nil || as.HmacSecret.FirstLen != 32 || as.HmacSecret.First == nil {
		return nil, errors.New(i18n.T("ключ не вернул hmac-secret: он не поддерживает расширение или учётные данные созданы без него"))
	}
	// Секрет уходит в наш буфер, а память Windows зануляется до освобождения: иначе он оставался бы в куче процесса.
	src := unsafe.Slice(as.HmacSecret.First, 32)
	secret := append([]byte(nil), src...)
	clear(src)
	return secret, nil
}

// Окна Windows принадлежат потоку, который их создал: вызов идёт в одном закреплённом потоке.
// Окно «Безопасность Windows» само по таймауту не закрывается (и остаётся после выхода процесса), поэтому по нашему
// сроку операция отменяется явно.
func onThread(cancel *windows.GUID, f func()) error {
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer close(done)
		f()
	}()
	// Окно создаёт чужой процесс без права на передний план: выводим его вперёд, пока идёт операция.
	deadline := time.After(Timeout)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
wait:
	for {
		select {
		case <-done:
			return nil
		case <-tick.C:
			hello.RaiseDialog()
		case <-deadline:
			break wait
		}
	}
	_, _, _ = pCancel.Call(uintptr(unsafe.Pointer(cancel)))
	hello.CloseDialog()
	select {
	case <-done:
		return errors.New(i18n.T("операция отменена: PIN и касание не получены вовремя"))
	case <-time.After(10 * time.Second):
		return errors.New(i18n.T("операция с ключом не завершилась вовремя"))
	}
}
