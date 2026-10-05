package extscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func put(t *testing.T, root, profile, id, ver, manifest string) {
	t.Helper()
	dir := filepath.Join(root, profile, "Extensions", id, ver)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScan(t *testing.T) {
	root := t.TempDir()
	put(t, root, "Default", "aaaa", "1.0_0", `{"name":"Cookie Grabber","permissions":["cookies","tabs"],"host_permissions":["<all_urls>"]}`)
	put(t, root, "Default", "bbbb", "1.0_0", `{"name":"Только cookies","permissions":["cookies"],"host_permissions":["https://example.com/*"]}`)
	put(t, root, "Default", "cccc", "1.0_0", `{"name":"Все сайты без cookies","permissions":["tabs"],"host_permissions":["*://*/*"]}`)
	put(t, root, "Profile 1", "dddd", "2.0_0", string([]byte{0xEF, 0xBB, 0xBF})+`{"name":"__MSG_appName__","manifest_version":2,"permissions":["cookies","https://*/*",{"fileSystem":["write"]}]}`)
	put(t, root, "Default", "eeee", "1.0_0", `{"name":"Необязательные","permissions":["tabs"],"optional_permissions":["cookies"],"optional_host_permissions":["<all_urls>"]}`)
	put(t, root, "Default", "ffff", "1.0_0", `не json`)
	put(t, root, "Profile 2", "aaaa", "1.0_0", `{"name":"Cookie Grabber","permissions":["cookies"],"host_permissions":["<all_urls>"]}`)

	res := Scan(root)
	if res.Checked != 6 {
		t.Fatalf("проверено %d, ждали 6 уникальных", res.Checked)
	}
	names := map[string]string{}
	for _, f := range res.Risky {
		names[f.ID] = f.Name
	}
	if len(names) != 2 || names["aaaa"] != "Cookie Grabber" || names["dddd"] != "dddd" {
		t.Fatalf("найдено не то: %+v", res.Risky)
	}
}

func TestLastVersionAndNoDir(t *testing.T) {
	root := t.TempDir()
	put(t, root, "Default", "aaaa", "1.0_0", `{"name":"Старая","permissions":["cookies"],"host_permissions":["<all_urls>"]}`)
	put(t, root, "Default", "aaaa", "2.0_0", `{"name":"Новая","permissions":["tabs"]}`)
	if res := Scan(root); len(res.Risky) != 0 || res.Checked != 1 {
		t.Fatalf("берётся последняя версия: %+v", res)
	}
	if res := Scan(filepath.Join(root, "нет такой")); res.Checked != 0 || res.Risky != nil {
		t.Fatalf("пустой результат для отсутствующей папки: %+v", res)
	}
}

func TestNameIsSanitized(t *testing.T) {
	root := t.TempDir()
	long := strings.Repeat("я", 200)
	put(t, root, "Default", "aaaa", "1.0_0", `{"name":"Эви\u0000л\r\nНазвание `+long+`","permissions":["cookies"],"host_permissions":["<all_urls>"]}`)
	res := Scan(root)
	if len(res.Risky) != 1 {
		t.Fatalf("%+v", res)
	}
	n := res.Risky[0].Name
	if strings.ContainsAny(n, "\x00\r\n") || len([]rune(n)) > maxNameRunes+1 {
		t.Fatalf("имя не очищено: %q", n)
	}
}

func TestBigManifestSkipped(t *testing.T) {
	root := t.TempDir()
	big := `{"name":"x","permissions":["cookies"],"host_permissions":["<all_urls>"],"pad":"` + strings.Repeat("a", maxManifest) + `"}`
	put(t, root, "Default", "aaaa", "1.0_0", big)
	if res := Scan(root); len(res.Risky) != 0 {
		t.Fatal("слишком большой manifest не читается")
	}
}
