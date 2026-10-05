package audit

import "testing"

const sample = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4663</EventID></System>` +
	`<EventData><Data Name="SubjectUserSid">S-1-5-21-1</Data>` +
	`<Data Name="ObjectName">\Device\HarddiskVolume3\Users\tester\AppData\Roaming\Telegram Desktop\tdata\key_datas</Data>` +
	`<Data Name="ProcessId">0x1a4</Data><Data Name="AccessMask">0x1</Data>` +
	`<Data Name="ProcessName">C:\Users\tester\Downloads\x.exe</Data></EventData></Event>`

func TestParseRead(t *testing.T) {
	r, err := parseRead([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if r.PID != 0x1a4 || r.Mask != 1 || r.Process != `C:\Users\tester\Downloads\x.exe` {
		t.Errorf("разобрано неверно: %+v", r)
	}
	if !Under(`\Device\HarddiskVolume3\Users\tester\AppData\Roaming\Telegram Desktop\tdata`, r.Object) {
		t.Error("объект внутри приманки не опознан")
	}
}

func TestParseReadRejectsGarbage(t *testing.T) {
	for _, s := range []string{"", "<Event>", `<Event><EventData></EventData></Event>`} {
		if _, err := parseRead([]byte(s)); err == nil {
			t.Errorf("%q принято", s)
		}
	}
}

func TestUnder(t *testing.T) {
	root := `\Device\HarddiskVolume3\Users\t\tdata`
	for obj, want := range map[string]bool{
		root:                true,
		root + `\key_datas`: true,
		`\DEVICE\HARDDISKVOLUME3\USERS\T\TDATA\x`: true,
		root + `2\key_datas`:                      false,
		`\Device\HarddiskVolume3\Users\t`:         false,
	} {
		if got := Under(root, obj); got != want {
			t.Errorf("Under(%q)=%v", obj, got)
		}
	}
}

func TestParseProcessEvent(t *testing.T) {
	x := `<Event><EventData><Data Name="SubjectUserSid">S-1-5-21-1-2-3-1001</Data><Data Name="SubjectUserName">tester</Data>` +
		`<Data Name="ObjectType">Process</Data><Data Name="ObjectName">\Device\HarddiskVolume3\Program Files\Google\Chrome\Application\chrome.exe</Data>` +
		`<Data Name="AccessMask">0x10</Data><Data Name="ProcessId">0x1c38</Data><Data Name="ProcessName">C:\Users\tester\x.exe</Data></EventData></Event>`
	r, err := parseRead([]byte(x))
	if err != nil || r.Type != "Process" || r.User != "tester" || r.SID != "S-1-5-21-1-2-3-1001" || r.Mask != 0x10 || r.PID != 0x1c38 {
		t.Fatalf("событие процесса разобрано неверно: %+v, %v", r, err)
	}
}
