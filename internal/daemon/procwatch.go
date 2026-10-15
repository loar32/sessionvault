//go:build linux

package daemon

import (
	"encoding/binary"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Блокировка экрана в Omarchy не сообщается logind (LockedHint остаётся false): её видно только по запуску
// omarchy-system-lock (им пользуются и клавиши, и меню, и таймер бездействия). Поэтому служба слушает коннектор процессов
// ядра: запуск известного блокировщика или systemd-sleep — блокировка хранилища, выход композитора — конец сеанса.
// Событие приходит от ядра без опроса; разбор одного exec — чтение 16 байт comm.
var lockers = map[string]bool{
	"omarchy-system-": true, // omarchy-system-lock, comm обрезан ядром до 15 символов
	"hyprlock":        true,
	"swaylock":        true,
	"gtklock":         true,
	"waylock":         true,
	"systemd-sleep":   true,
}

const (
	cnIdxProc        = 1
	cnValProc        = 1
	procCnMcastListn = 1
	procEventExec    = 0x00000002
	procEventExit    = 0x80000000
	nlmsgHdrLen      = 16
	cnMsgLen         = 20
)

func (d *Daemon) watchProcs() {
	for {
		if err := d.procConnector(); err != nil {
			d.log.Println("коннектор процессов:", err)
		}
		time.Sleep(10 * time.Second)
	}
}

func (d *Daemon) procConnector() error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_CONNECTOR)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc, Pid: uint32(os.Getpid())}); err != nil {
		return err
	}
	msg := make([]byte, nlmsgHdrLen+cnMsgLen+4)
	binary.LittleEndian.PutUint32(msg[0:], uint32(len(msg)))
	binary.LittleEndian.PutUint16(msg[4:], unix.NLMSG_DONE)
	binary.LittleEndian.PutUint32(msg[12:], uint32(os.Getpid()))
	binary.LittleEndian.PutUint32(msg[16:], cnIdxProc)
	binary.LittleEndian.PutUint32(msg[20:], cnValProc)
	binary.LittleEndian.PutUint16(msg[32:], 4)
	binary.LittleEndian.PutUint32(msg[36:], procCnMcastListn)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	d.log.Println("слежение за блокировкой экрана и сном включено")
	buf := make([]byte, 8192)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EINTR || err == unix.ENOBUFS {
				continue
			}
			return err
		}
		for off := 0; off+nlmsgHdrLen <= n; {
			l := int(binary.LittleEndian.Uint32(buf[off:]))
			if l < nlmsgHdrLen || off+l > n {
				break
			}
			d.procEvent(buf[off+nlmsgHdrLen : off+l])
			off += (l + 3) &^ 3
		}
	}
}

// proc_event: what(4) cpu(4) timestamp(8), затем данные события; у exec и exit первые поля — pid и tgid.
func (d *Daemon) procEvent(cn []byte) {
	if len(cn) < cnMsgLen+24 {
		return
	}
	ev := cn[cnMsgLen:]
	what := binary.LittleEndian.Uint32(ev[0:])
	tgid := int(binary.LittleEndian.Uint32(ev[20:]))
	switch what {
	case procEventExec:
		b, err := os.ReadFile("/proc/" + strconv.Itoa(tgid) + "/comm")
		comm := strings.TrimSpace(string(b))
		switch {
		case err != nil || !lockers[comm]:
		case comm == "systemd-sleep":
			go d.lockRequested("сон")
		default:
			go d.lockRequested("блокировка экрана")
		}
	case procEventExit:
		pid := int(binary.LittleEndian.Uint32(ev[16:]))
		d.mu.Lock()
		ended := d.server != 0 && pid == d.server && tgid == d.server
		if ended {
			d.server = 0
		}
		d.mu.Unlock()
		if ended {
			go d.lockRequested("сеанс завершён")
		}
	}
}
