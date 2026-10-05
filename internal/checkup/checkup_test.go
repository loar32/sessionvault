package checkup

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type fake struct {
	ints map[string]int64
	strs map[string]string
	bl   int
	err  error
}

func (f fake) regInt(key, value string) (int64, bool) { v, ok := f.ints[key+"|"+value]; return v, ok }
func (f fake) regStr(key, value string) (string, bool) {
	v, ok := f.strs[key+"|"+value]
	return v, ok
}
func (f fake) bitlocker() (int, error) { return f.bl, f.err }

func good() fake {
	return fake{
		ints: map[string]int64{
			hvciKey + "|Enabled":                          1,
			secureBoot + "|UEFISecureBootEnabled":         1,
			ciConfig + "|VulnerableDriverBlocklistEnable": 1,
		},
		strs: map[string]string{
			ntVersion + "|ProductName":    "Windows 11 Pro",
			ntVersion + "|DisplayVersion": "24H2",
			ntVersion + "|EditionID":      "Professional",
			ntVersion + "|CurrentBuild":   "26100",
		},
		bl: 1,
	}
}

var allOn = Input{Audit: true, Hardened: true, Hello: true, ASRActive: 4, ASRTotal: 4, MemAudit: true}

func level(r Report, id string) Level {
	for _, it := range r.Items {
		if it.ID == id {
			return it.Level
		}
	}
	return ""
}

func TestAllGood(t *testing.T) {
	r := run(good(), allOn, time.Now())
	if r.Overall != OK {
		t.Fatalf("итог %s, ждали ok: %+v", r.Overall, r.Items)
	}
	if level(r, "telegram") != Info {
		t.Fatal("пункт Telegram должен быть справкой")
	}
}

func TestWarnAndBad(t *testing.T) {
	f := good()
	f.bl = 0
	delete(f.ints, hvciKey+"|Enabled")
	r := run(f, allOn, time.Now())
	if r.Overall != Warn || level(r, "bitlocker") != Warn || level(r, "hvci") != Warn {
		t.Fatalf("ждали жёлтые BitLocker и HVCI: %+v", r)
	}
	r = run(good(), Input{MainUserAdmin: true, Audit: true, Hardened: true, Hello: true}, time.Now())
	if r.Overall != Bad || level(r, "user") != Bad {
		t.Fatalf("админ в основной учётке должен быть красным: %+v", r)
	}
	r = run(good(), Input{Hardened: true, Hello: true}, time.Now())
	if level(r, "audit") != Bad {
		t.Fatal("выключенный аудит должен быть красным")
	}
}

func TestUnknownIsWarn(t *testing.T) {
	f := good()
	f.err = errors.New("нет доступа")
	if r := run(f, allOn, time.Now()); level(r, "bitlocker") != Warn {
		t.Fatal("BitLocker не определён — жёлтый")
	}
	r := run(fake{bl: 1}, allOn, time.Now())
	if level(r, "windows") != Warn || level(r, "secureboot") != Warn {
		t.Fatalf("пустой реестр — жёлтые пункты: %+v", r)
	}
}

func TestDefenderAndEditions(t *testing.T) {
	f := good()
	f.ints[defPolicy+"|DisableAntiSpyware"] = 1
	if r := run(f, allOn, time.Now()); level(r, "defender") != Bad {
		t.Fatal("отключённый Defender — красный")
	}
	f = good()
	f.strs[ntVersion+"|EditionID"] = "Core"
	if r := run(f, allOn, time.Now()); level(r, "windows") != Warn {
		t.Fatal("Home — жёлтый")
	}
	f = good()
	delete(f.ints, ciConfig+"|VulnerableDriverBlocklistEnable")
	if r := run(f, allOn, time.Now()); level(r, "blocklist") != OK {
		t.Fatal("на новой сборке блоклист включён по умолчанию")
	}
	f.strs[ntVersion+"|CurrentBuild"] = "19045"
	if r := run(f, allOn, time.Now()); level(r, "blocklist") != Warn {
		t.Fatal("на Windows 10 без значения блоклист не включён")
	}
}

func TestFormat(t *testing.T) {
	f := good()
	f.bl = 0
	out := Format(run(f, allOn, time.Now()), false)
	if !strings.Contains(out, "[!] BitLocker") || !strings.Contains(out, "Итог: есть что улучшить") || strings.Contains(out, "\x1b") {
		t.Fatalf("неверный текст:\n%s", out)
	}
	if !strings.Contains(Format(run(f, allOn, time.Now()), true), "\x1b[33m") {
		t.Fatal("цвет не включился")
	}
}

func TestWindows11Name(t *testing.T) {
	f := good()
	f.strs[ntVersion+"|ProductName"] = "Windows 10 Pro"
	r := run(f, allOn, time.Now())
	for _, it := range r.Items {
		if it.ID == "windows" && !strings.Contains(it.Detail, "Windows 11 Pro") {
			t.Fatalf("сборка 26100 должна называться Windows 11: %s", it.Detail)
		}
	}
}

func TestUnknownUserIsNotGreen(t *testing.T) {
	r := run(good(), Input{MainUserUnknown: true, Audit: true, Hardened: true, Hello: true}, time.Now())
	if level(r, "user") != Warn {
		t.Fatal("не удалось проверить учётку — жёлтый, а не зелёный")
	}
}

func TestReportFitsPipeReply(t *testing.T) {
	r := run(fake{err: errors.New("x")}, Input{MainUserAdmin: true}, time.Now())
	b, _ := json.Marshal(r)
	if len(b) > 4096 {
		t.Fatalf("худший отчёт %d байт: лимит ответа pipe 8192, запас должен быть двойной", len(b))
	}
}

func TestASRItem(t *testing.T) {
	r := run(good(), allOn, time.Now())
	if level(r, "asr") != OK {
		t.Fatal("все правила включены — зелёный")
	}
	partial := allOn
	partial.ASRActive = 1
	r = run(good(), partial, time.Now())
	if level(r, "asr") != Warn || r.Overall != Warn {
		t.Fatalf("включено 1 из 4 — жёлтый: %+v", r)
	}
	f := good()
	f.ints[defPolicy+"|DisableAntiSpyware"] = 1
	if r := run(f, partial, time.Now()); level(r, "asr") != Info {
		t.Fatal("при отключённом Defender правила — справка, а не второй красный пункт")
	}
}

func TestExtensionsItem(t *testing.T) {
	in := allOn
	if r := run(good(), in, time.Now()); level(r, "extensions") != Info {
		t.Fatal("до первого запуска браузера — справка")
	}
	in.ExtScanned = []string{"chrome", "edge"}
	if r := run(good(), in, time.Now()); level(r, "extensions") != OK {
		t.Fatal("проверено, опасных нет — зелёный")
	}
	in.ExtRisky = []string{"A (chrome)", "B (edge)", "C (edge)", "D (edge)", "E (edge)", "F (edge)", "G (edge)"}
	r := run(good(), in, time.Now())
	if level(r, "extensions") != Warn || r.Overall != Warn {
		t.Fatalf("опасные расширения — жёлтый: %+v", r)
	}
	for _, it := range r.Items {
		if it.ID == "extensions" && (!strings.Contains(it.Detail, "A (chrome)") || !strings.Contains(it.Detail, "и ещё 2") || strings.Contains(it.Detail, "G (edge)")) {
			t.Fatalf("список обрезан неверно: %s", it.Detail)
		}
	}
}

func TestMemoryItem(t *testing.T) {
	in := allOn
	in.MemAudit = false
	if r := run(good(), in, time.Now()); level(r, "memory") != Info {
		t.Fatal("аудит не включён — справка")
	}
	in.MemAudit = true
	if r := run(good(), in, time.Now()); level(r, "memory") != OK {
		t.Fatal("обращений нет — зелёный")
	}
	in.MemReads, in.MemLast = 3, "x.exe -> chrome.exe"
	r := run(good(), in, time.Now())
	if level(r, "memory") != Info || r.Overall != OK {
		t.Fatalf("обращения — только справка, итог не меняется: %+v", r)
	}
}
