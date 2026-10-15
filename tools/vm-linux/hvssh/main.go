//go:build windows

// hvssh — ProxyCommand для ssh к Linux-ВМ Hyper-V через Hyper-V socket (vsock в госте): сеть не нужна, поэтому работает и
// когда VPN хоста перехватывает подсеть Default Switch.
//
//	ssh -o ProxyCommand="hvssh.exe sv-omarchy 22" tester@sv-omarchy
//
// В госте: модуль hv_sock и sshd, слушающий vsock::22; на хосте служба порта зарегистрирована в
// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices\<порт>-facb-11e6-bd58-64006a7986d3.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	afHyperV      = 34
	hvProtocolRaw = 1
)

type sockaddrHV struct {
	Family    uint16
	Reserved  uint16
	VMID      windows.GUID
	ServiceID windows.GUID
}

var (
	ws2     = windows.NewLazySystemDLL("ws2_32.dll")
	connect = ws2.NewProc("connect")
	recv    = ws2.NewProc("recv")
	send    = ws2.NewProc("send")
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "hvssh <имя-ВМ|GUID> <порт>")
		os.Exit(2)
	}
	vm, err := vmID(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	port, err := strconv.ParseUint(os.Args[2], 10, 32)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	svc, _ := windows.GUIDFromString("{00000000-facb-11e6-bd58-64006a7986d3}")
	svc.Data1 = uint32(port)

	var wsa windows.WSAData
	if err := windows.WSAStartup(0x0202, &wsa); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	s, err := windows.Socket(afHyperV, windows.SOCK_STREAM, hvProtocolRaw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "socket:", err)
		os.Exit(1)
	}
	sa := sockaddrHV{Family: afHyperV, VMID: vm, ServiceID: svc}
	if r, _, e := connect.Call(uintptr(s), uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa)); r != 0 {
		fmt.Fprintln(os.Stderr, "connect:", e)
		os.Exit(1)
	}
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 && !sendAll(s, buf[:n]) {
				os.Exit(0)
			}
			if err != nil {
				_ = windows.Shutdown(s, windows.SHUT_WR)
				return
			}
		}
	}()
	buf := make([]byte, 32<<10)
	for {
		r, _, _ := recv.Call(uintptr(s), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
		n := int(int32(r))
		if n <= 0 {
			return
		}
		if _, err := os.Stdout.Write(buf[:n]); err != nil {
			return
		}
	}
}

func sendAll(s windows.Handle, b []byte) bool {
	for len(b) > 0 {
		r, _, _ := send.Call(uintptr(s), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
		n := int(int32(r))
		if n <= 0 {
			return false
		}
		b = b[n:]
	}
	return true
}

func vmID(name string) (windows.GUID, error) {
	if g, err := windows.GUIDFromString("{" + strings.Trim(name, "{}") + "}"); err == nil {
		return g, nil
	}
	out, err := exec.Command("powershell", "-NoProfile", "-Command", "(Get-VM '"+strings.ReplaceAll(name, "'", "")+"').Id.Guid").Output()
	if err != nil {
		return windows.GUID{}, fmt.Errorf("Get-VM %s: %w", name, err)
	}
	return windows.GUIDFromString("{" + strings.TrimSpace(string(out)) + "}")
}
