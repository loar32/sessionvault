package ipc

import (
	"strings"
	"testing"
)

func TestParseAccepts(t *testing.T) {
	r, err := Parse("status")
	if err != nil || r.Cmd != "status" {
		t.Fatalf("status: %+v %v", r, err)
	}
	r, err = Parse("list")
	if err != nil || r.Cmd != "list" {
		t.Fatalf("list: %+v %v", r, err)
	}
	r, err = Parse("run telegram")
	if err != nil || r.Cmd != "run" || r.Profile != "telegram" {
		t.Fatalf("run: %+v %v", r, err)
	}
}

func TestParseRejects(t *testing.T) {
	bad := []string{
		"", " ", "run", "run ", "run  telegram", "run telegram arg", "run telegram ", " run telegram",
		"run ../telegram", `run ..\x`, "run Telegram", "run tele gram", "run telegram\x00", "run telegram\r",
		"list x", "list ", "LIST", "lists", "status x", "status ", "STATUS", "stop", "unlock", "unlock secret", "run\ttelegram",
		"run телеграм", "run " + strings.Repeat("a", 33), strings.Repeat("a", MaxLine+1), strings.Repeat("run telegram", 100),
		"run telegram; calc", "run telegram && calc", "run $(calc)", "run -x",
	}
	for _, s := range bad {
		if r, err := Parse(s); err == nil {
			t.Errorf("запрос %q принят: %+v", s, r)
		}
	}
}

func TestParseHello(t *testing.T) {
	r, err := Parse("hello telegram")
	if err != nil || r.Cmd != "hello" || r.Profile != "telegram" {
		t.Fatalf("hello telegram: %+v %v", r, err)
	}
	for _, s := range []string{"hello", "hello ", "hello ../x", "hello a b", "hello Telegram"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("%q принят", s)
		}
	}
}

func TestParseOpen(t *testing.T) {
	r, err := Parse("open")
	if err != nil || r.Cmd != "open" {
		t.Fatalf("open: %+v %v", r, err)
	}
	for _, s := range []string{"open ", "open https://a.b", "open telegram", "OPEN"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("%q принят", s)
		}
	}
}

func TestValidURL(t *testing.T) {
	for _, s := range []string{"https://example.com", "http://a.b/c?d=1&e=%20f#g", "https://user@host:8080/p"} {
		if err := ValidURL(s); err != nil {
			t.Errorf("%q отклонён: %v", s, err)
		}
	}
	bad := []string{"", "example.com", "--remote-debugging-port=1", "-x https://a.b", "file:///C:/x", "javascript:alert(1)",
		"chrome://settings", "https://", "https:///x", "https://a.b/ c", `https://a.b/"--x`, `https://a.b/\x`, "https://a.b/\n",
		"https://a.b/^x", "https://a.b/привет", "ftp://a.b", "HTTPS://A.B/x ", "https://a.b/" + strings.Repeat("a", MaxURL)}
	for _, s := range bad {
		if err := ValidURL(s); err == nil {
			t.Errorf("%q принят", s)
		}
	}
}

func TestParseCheck(t *testing.T) {
	if r, err := Parse("check"); err != nil || r.Cmd != "check" {
		t.Fatalf("check: %+v %v", r, err)
	}
	for _, s := range []string{"check ", "check x", "CHECK", "check -json"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("запрос %q принят", s)
		}
	}
}
