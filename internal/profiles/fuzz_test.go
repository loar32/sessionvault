package profiles

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzLoad(f *testing.F) {
	f.Add(`{"name":"x","exe":"C:/a.exe","data_dir":"d"}`)
	f.Add(`{"name":"x","exe":"C:/a.exe","data_dir":"../d","exclude":["../x"],"exec_files":["a/b"]}`)
	f.Fuzz(func(t *testing.T, js string) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "x.json"), []byte(js), 0o644); err != nil {
			t.Skip()
		}
		p, err := Load(dir, "x")
		if err != nil {
			return
		}
		if p.Name != "x" || !filepath.IsAbs(p.Exe) || !filepath.IsLocal(p.DataDir) {
			t.Fatalf("принят профиль с недопустимыми путями: %+v", p)
		}
		for _, x := range p.Exclude {
			if !filepath.IsLocal(x) {
				t.Fatalf("недопустимое исключение %q", x)
			}
		}
		for _, x := range p.ExecFiles {
			if x == "" || filepath.Base(x) != x {
				t.Fatalf("недопустимое имя файла %q", x)
			}
		}
		if p.Origin != "" && !filepath.IsLocal(p.Origin) {
			t.Fatalf("недопустимый Origin %q", p.Origin)
		}
	})
}
