package isolation

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// KillAccountProcesses завершает все процессы учётки приложения (главный процесс и потомков) и возвращает их число.
func KillAccountProcesses(account string) (int, error) {
	sid, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return 0, err
	}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _ = windows.CloseHandle(snap) }()
	e := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	killed := 0
	for err := windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if e.ProcessID == 0 || !ownedBy(e.ProcessID, sid) {
			continue
		}
		if h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, e.ProcessID); err == nil {
			if windows.TerminateProcess(h, 1) == nil {
				killed++
			}
			_ = windows.CloseHandle(h)
		}
	}
	return killed, nil
}

func ownedBy(pid uint32, sid *windows.SID) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var tok windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok) != nil {
		return false
	}
	defer func() { _ = tok.Close() }()
	u, err := tok.GetTokenUser()
	return err == nil && windows.EqualSid(u.User.Sid, sid)
}
