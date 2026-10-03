package audit

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wintrust          = windows.NewLazySystemDLL("wintrust.dll")
	procProvData      = wintrust.NewProc("WTHelperProvDataFromStateData")
	procProvSigner    = wintrust.NewProc("WTHelperGetProvSignerFromChain")
	procProvCert      = wintrust.NewProc("WTHelperGetProvCertFromChain")
	procCertName      = windows.NewLazySystemDLL("crypt32.dll").NewProc("CertGetNameStringW")
	wtdCacheOnlyURL   = uint32(0x1000)
	certNameSimpleDsp = uintptr(4)
)

type providerCert struct {
	Size uint32
	Cert uintptr
}

// Signer проверяет встроенную подпись Authenticode и возвращает имя издателя.
// Без проверки отзыва и без обращений в сеть: подпись, которую нельзя проверить офлайн, не считается действительной.
func Signer(path string) (string, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	fi := windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: p}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&fi),
		ProvFlags:                       windows.WTD_REVOCATION_CHECK_NONE | wtdCacheOnlyURL,
	}
	err = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	defer func() {
		data.StateAction = windows.WTD_STATEACTION_CLOSE
		_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	}()
	if err != nil {
		return "", err
	}
	prov, _, _ := procProvData.Call(uintptr(data.StateData))
	if prov == 0 {
		return "", errors.New("нет данных о подписи")
	}
	sgnr, _, _ := procProvSigner.Call(prov, 0, 0, 0)
	if sgnr == 0 {
		return "", errors.New("нет подписанта")
	}
	pc, _, _ := procProvCert.Call(sgnr, 0)
	if pc == 0 {
		return "", errors.New("нет сертификата подписанта")
	}
	// Указатель принадлежит состоянию проверки (живёт до CLOSE), а не куче Go; vet не знает, что это не ошибка.
	cert := (*providerCert)(*(*unsafe.Pointer)(unsafe.Pointer(&pc))).Cert
	buf := make([]uint16, 256)
	n, _, _ := procCertName.Call(cert, certNameSimpleDsp, 0, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n <= 1 {
		return "", errors.New("в сертификате нет имени")
	}
	return windows.UTF16ToString(buf), nil
}
