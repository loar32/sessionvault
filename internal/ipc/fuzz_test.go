package ipc

import (
	"net/url"
	"strings"
	"testing"
)

func FuzzValidURL(f *testing.F) {
	for _, s := range []string{"https://example.com/a?b=c#d", "http://a", "ftp://x", "https://a b", "https://a/%22", "-x", "https://ex.com/--remote-debugging-port=1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if ValidURL(s) != nil {
			return
		}
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			t.Fatalf("принята недопустимая ссылка %q", s)
		}
		if l := strings.ToLower(s); !strings.HasPrefix(l, "http://") && !strings.HasPrefix(l, "https://") {
			t.Fatalf("ссылка принята без префикса http(s)://: %q", s)
		}
		if strings.ContainsAny(s, " \t\r\n\"\\^`") || len(s) > MaxURL {
			t.Fatalf("в принятой ссылке опасный символ: %q", s)
		}
	})
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"status", "run telegram", "hello chrome", "open", "run  x", "run ../x", "run a b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := Parse(s)
		if err != nil {
			return
		}
		switch r.Cmd {
		case "status", "list", "check", "open":
			if r.Profile != "" || strings.Contains(s, " ") {
				t.Fatalf("команда %q приняла аргументы: %q", r.Cmd, s)
			}
		case "run", "hello":
			if strings.ContainsAny(r.Profile, `\/. :`) || r.Profile == "" {
				t.Fatalf("недопустимое имя профиля %q из %q", r.Profile, s)
			}
		default:
			t.Fatalf("неизвестная команда %q из %q", r.Cmd, s)
		}
	})
}
