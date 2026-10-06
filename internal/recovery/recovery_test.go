package recovery

import (
	"bytes"
	"strings"
	"testing"
)

func TestKnownVectors(t *testing.T) {
	cases := map[string]byte{
		strings.TrimSpace(strings.Repeat("abandon ", 23)) + " art": 0x00,
		strings.TrimSpace(strings.Repeat("zoo ", 23)) + " vote":    0xff,
	}
	for want, b := range cases {
		key := bytes.Repeat([]byte{b}, KeySize)
		got, err := Words(key)
		if err != nil || got != want {
			t.Fatalf("Words(%#x) = %q, %v; нужно %q", b, got, err, want)
		}
		back, err := Parse(strings.ToUpper(got) + "  \n")
		if err != nil || !bytes.Equal(back, key) {
			t.Fatalf("Parse не вернул ключ: %v", err)
		}
	}
}

func TestParseRejectsMistakes(t *testing.T) {
	good, _ := Words(bytes.Repeat([]byte{7}, KeySize))
	f := strings.Fields(good)
	for name, s := range map[string]string{
		"пусто":        "",
		"мало слов":    strings.Join(f[:23], " "),
		"не из слов":   strings.Replace(good, f[0], "qwerty", 1),
		"другое слово": strings.Replace(good, f[5], "zoo", 1),
	} {
		if _, err := Parse(s); err == nil {
			t.Fatalf("%s: принято", name)
		}
	}
}
