package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSignerRejectsUnsigned(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.exe")
	if err := os.WriteFile(p, []byte("MZ not signed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if name, err := Signer(p); err == nil {
		t.Fatalf("неподписанный файл принят, издатель %q", name)
	}
}

func TestSignerReadsPublisher(t *testing.T) {
	for _, p := range []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Windows Defender\MsMpEng.exe`,
	} {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		name, err := Signer(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if name != "Microsoft Corporation" {
			t.Errorf("%s: издатель %q", p, name)
		}
		return
	}
	t.Skip("нет подписанного exe с встроенной подписью")
}
