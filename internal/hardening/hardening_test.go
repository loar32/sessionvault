package hardening

import "testing"

type fake struct {
	vals  map[string]int64
	hiber bool
}

func (f *fake) get(key, value string) (int64, error) {
	if v, ok := f.vals[key+"|"+value]; ok {
		return v, nil
	}
	return absent, nil
}
func (f *fake) set(key, value string, v uint32) error { f.vals[key+"|"+value] = int64(v); return nil }
func (f *fake) remove(key, value string) error        { delete(f.vals, key+"|"+value); return nil }
func (f *fake) hibernate(on bool) error {
	f.hiber = on
	if on {
		f.vals[settings[0].key+"|"+settings[0].value] = 1
	} else {
		f.vals[settings[0].key+"|"+settings[0].value] = 0
	}
	return nil
}

func newFake() *fake {
	return &fake{vals: map[string]int64{
		settings[0].key + "|" + settings[0].value: 1,
		settings[2].key + "|" + settings[2].value: 7,
	}, hiber: true}
}

func TestApplyRevert(t *testing.T) {
	f := newFake()
	st, err := apply(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.hiber || f.vals[settings[1].key+"|"+settings[1].value] != 1 || f.vals[settings[2].key+"|"+settings[2].value] != 0 {
		t.Fatalf("меры не применены: %v", f.vals)
	}
	// Повторный запуск не принимает наши значения за исходные.
	st, err = apply(f, st)
	if err != nil || st["crash_dumps"] != 7 || st["hibernate"] != 1 {
		t.Fatalf("повтор испортил состояние: %v %v", st, err)
	}
	if err := revert(f, st); err != nil {
		t.Fatal(err)
	}
	if !f.hiber || f.vals[settings[2].key+"|"+settings[2].value] != 7 {
		t.Fatalf("откат не вернул значения: %v", f.vals)
	}
	if _, ok := f.vals[settings[1].key+"|"+settings[1].value]; ok {
		t.Fatal("значение, которого не было, осталось")
	}
}

func TestHibernateStaysOffIfWasOff(t *testing.T) {
	f := newFake()
	f.vals[settings[0].key+"|"+settings[0].value] = 0
	f.hiber = false
	st, _ := apply(f, nil)
	_ = revert(f, st)
	if f.hiber {
		t.Fatal("гибернация включена, хотя была выключена")
	}
}

func TestHibernateAbsentIsUntouched(t *testing.T) {
	f := newFake()
	delete(f.vals, settings[0].key+"|"+settings[0].value)
	f.hiber = false
	st, _ := apply(f, nil)
	_ = revert(f, st)
	if _, ok := f.vals[settings[0].key+"|"+settings[0].value]; ok {
		t.Fatal("значение гибернации создано там, где его не было")
	}
}
