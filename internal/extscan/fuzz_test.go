package extscan

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzManifest(f *testing.F) {
	f.Add(`{"name":"x","permissions":["cookies"],"host_permissions":["<all_urls>"]}`)
	f.Add(`{"name":null,"permissions":{"a":1},"host_permissions":[1,[2],"<all_urls>"]}`)
	f.Add("\xef\xbb\xbf[1,2")
	f.Fuzz(func(t *testing.T, manifest string) {
		root := t.TempDir()
		dir := filepath.Join(root, "Default", "Extensions", "id", "1.0_0")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Skip()
		}
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o644); err != nil {
			t.Skip()
		}
		res := Scan(root)
		for _, r := range res.Risky {
			if len([]rune(r.Name)) > maxNameRunes+1 {
				t.Fatalf("имя длиннее предела: %q", r.Name)
			}
			for _, c := range r.Name {
				if c < 0x20 || c == 0x7f {
					t.Fatalf("в имени управляющий символ: %q", r.Name)
				}
			}
		}
	})
}
