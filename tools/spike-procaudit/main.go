package main

import (
	"fmt"
	"os"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	accessSystemSecurity = 0x01000000
	vmRead               = 0x10
)

func priv(name string) {
	var tok windows.Token
	_ = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok)
	var luid windows.LUID
	_ = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid)
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	fmt.Println("adjust:", windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil))
}

func main() {
	pid, _ := strconv.Atoi(os.Args[2])
	switch os.Args[1] {
	case "set":
		priv("SeSecurityPrivilege")
		h, err := windows.OpenProcess(accessSystemSecurity|windows.READ_CONTROL, false, uint32(pid))
		fmt.Println("open:", err)
		sd, err := windows.SecurityDescriptorFromString("S:(AU;SA;0x3a;;;WD)")
		fmt.Println("sd:", err)
		sacl, _, _ := sd.SACL()
		err = windows.SetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.SACL_SECURITY_INFORMATION, nil, nil, nil, sacl)
		fmt.Println("setsec:", err)
	case "read":
		h, err := windows.OpenProcess(vmRead|windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
		fmt.Println("open:", err)
		var buf [16]byte
		var n uintptr
		err = windows.ReadProcessMemory(h, 0x10000, &buf[0], uintptr(len(buf)), &n)
		fmt.Println("read:", err, unsafe.Sizeof(n))
	}
}
