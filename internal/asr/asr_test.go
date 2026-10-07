package asr

import (
	"strconv"
	"testing"
)

type fake struct {
	vals   map[string]string
	dwords map[string]bool
}

func newFake() *fake { return &fake{vals: map[string]string{}, dwords: map[string]bool{}} }

func (f *fake) get(key, value string) (string, bool) { v, ok := f.vals[key+"|"+value]; return v, ok }
func (f *fake) isDword(key, value string) bool       { return f.dwords[key+"|"+value] }
func (f *fake) setDword(key, value string, v uint32) error {
	f.vals[key+"|"+value] = strconv.Itoa(int(v))
	f.dwords[key+"|"+value] = true
	return nil
}
func (f *fake) setString(key, value, s string) error {
	f.vals[key+"|"+value] = s
	delete(f.dwords, key+"|"+value)
	return nil
}
func (f *fake) remove(key, value string) error {
	delete(f.vals, key+"|"+value)
	delete(f.dwords, key+"|"+value)
	return nil
}

func TestApplyRevert(t *testing.T) {
	f := newFake()
	f.vals[rulesKey+"|"+Rules[1].ID] = "2" // аудит, настроенный раньше
	st, err := apply(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	if active(f) != len(Rules) {
		t.Fatalf("включено %d из %d", active(f), len(Rules))
	}
	if st[Rules[1].ID] != "s:2" || st[Rules[0].ID] != "" || st[masterName] != "" {
		t.Fatalf("прежние значения записаны неверно: %v", st)
	}
	if err := revert(f, st); err != nil {
		t.Fatal(err)
	}
	if v := f.vals[rulesKey+"|"+Rules[1].ID]; v != "2" {
		t.Fatalf("аудит должен вернуться: %q", v)
	}
	if len(f.vals) != 1 {
		t.Fatalf("после отката остались лишние значения: %v", f.vals)
	}
	if active(f) != 0 {
		t.Fatal("после отката правил в блокировке нет")
	}
}

func TestApplyTwiceKeepsOriginal(t *testing.T) {
	f := newFake()
	st, _ := apply(f, nil)
	st, _ = apply(f, st)
	if st[Rules[0].ID] != "" || st[masterName] != "" {
		t.Fatalf("повторный Apply принял наши значения за исходные: %v", st)
	}
	if err := revert(f, st); err != nil || len(f.vals) != 0 {
		t.Fatalf("откат после двух Apply: %v, %v", err, f.vals)
	}
}

func TestRevertRejectsBadValues(t *testing.T) {
	f := newFake()
	err := revert(f, State{Rules[0].ID: "1; calc", masterName: "99999"})
	if err == nil || len(f.vals) != 0 {
		t.Fatalf("недопустимые значения не должны попасть в реестр: %v %v", err, f.vals)
	}
}

func TestActiveNeedsPolicySwitch(t *testing.T) {
	f := newFake()
	f.vals[rulesKey+"|"+Rules[0].ID] = "1"
	if active(f) != 0 {
		t.Fatal("правило без общего переключателя политики не действует")
	}
	f.vals[localKey+"|"+Rules[1].ID] = "1"
	if active(f) != 1 {
		t.Fatal("локальная настройка Defender считается")
	}
	f.vals[localKey+"|"+Rules[2].ID] = "2"
	if active(f) != 1 {
		t.Fatal("режим аудита не считается блокировкой")
	}
}

func TestPolicyOverridesLocal(t *testing.T) {
	f := newFake()
	f.vals[policyKey+"|"+master] = "1"
	f.vals[rulesKey+"|"+Rules[0].ID] = "0"
	f.vals[localKey+"|"+Rules[0].ID] = "1"
	if active(f) != 0 {
		t.Fatal("правило, отключённое политикой, не работает, даже если локально включено")
	}
}

func TestRevertKeepsValueType(t *testing.T) {
	f := newFake()
	key := rulesKey + "|" + Rules[0].ID
	f.vals[key] = "2"
	f.dwords[key] = true // прежнее значение было DWORD
	st, err := apply(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.dwords[key] {
		t.Fatal("после включения правило записано строкой")
	}
	if err := revert(f, st); err != nil {
		t.Fatal(err)
	}
	if !f.dwords[key] || f.vals[key] != "2" {
		t.Fatalf("тип DWORD не вернулся: %q, dword=%v", f.vals[key], f.dwords[key])
	}
}

func TestRevertOldStateWithoutType(t *testing.T) {
	f := newFake()
	if err := revert(f, State{Rules[0].ID: "2"}); err != nil {
		t.Fatal(err)
	}
	if f.vals[rulesKey+"|"+Rules[0].ID] != "2" {
		t.Fatal("запись прежней версии (без типа) не прочитана")
	}
}
