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
	r, err = Parse("run telegram")
	if err != nil || r.Cmd != "run" || r.Profile != "telegram" {
		t.Fatalf("run: %+v %v", r, err)
	}
}

func TestParseRejects(t *testing.T) {
	bad := []string{
		"", " ", "run", "run ", "run  telegram", "run telegram arg", "run telegram ", " run telegram",
		"run ../telegram", `run ..\x`, "run Telegram", "run tele gram", "run telegram\x00", "run telegram\r",
		"status x", "status ", "STATUS", "stop", "unlock", "unlock secret", "run\ttelegram",
		"run телеграм", "run " + strings.Repeat("a", 33), strings.Repeat("a", MaxLine+1), strings.Repeat("run telegram", 100),
		"run telegram; calc", "run telegram && calc", "run $(calc)", "run -x",
	}
	for _, s := range bad {
		if r, err := Parse(s); err == nil {
			t.Errorf("запрос %q принят: %+v", s, r)
		}
	}
}
