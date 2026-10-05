package audit

import (
	"encoding/xml"
	"errors"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wevtapi       = windows.NewLazySystemDLL("wevtapi.dll")
	procSubscribe = wevtapi.NewProc("EvtSubscribe")
	procRender    = wevtapi.NewProc("EvtRender")
	procEvtClose  = wevtapi.NewProc("EvtClose")
)

const (
	subscribeToFuture = 1
	actionDeliver     = 1
	renderEventXML    = 1
)

// Read — событие 4663: процесс обратился к объекту (файлу или процессу).
type Read struct {
	Type    string // File, Process и т. п.
	Object  string // для файла путь в формате устройства (\Device\HarddiskVolume3\...), для процесса путь к его exe
	Process string // путь к exe обратившегося процесса
	PID     uint32
	Mask    uint32
	SID     string // учётка обратившегося процесса
	User    string
}

type eventXML struct {
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

func parseRead(b []byte) (Read, error) {
	var e eventXML
	if err := xml.Unmarshal(b, &e); err != nil {
		return Read{}, err
	}
	var r Read
	for _, d := range e.Data {
		switch d.Name {
		case "ObjectType":
			r.Type = d.Value
		case "SubjectUserSid":
			r.SID = d.Value
		case "SubjectUserName":
			r.User = d.Value
		case "ObjectName":
			r.Object = d.Value
		case "ProcessName":
			r.Process = d.Value
		case "ProcessId":
			n, _ := strconv.ParseUint(d.Value, 0, 32)
			r.PID = uint32(n)
		case "AccessMask":
			n, _ := strconv.ParseUint(d.Value, 0, 32)
			r.Mask = uint32(n)
		}
	}
	if r.Object == "" {
		return r, errors.New("в событии нет ObjectName")
	}
	return r, nil
}

// NTPath переводит путь с буквой диска в формат устройства, в котором журнал записывает объекты.
func NTPath(path string) (string, error) {
	if len(path) < 2 || path[1] != ':' {
		return "", errors.New("нужен путь с буквой диска")
	}
	drive, err := windows.UTF16PtrFromString(path[:2])
	if err != nil {
		return "", err
	}
	buf := make([]uint16, 512)
	n, err := windows.QueryDosDevice(drive, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 {
		return "", err
	}
	return windows.UTF16ToString(buf) + path[2:], nil
}

// Under — лежит ли объект внутри папки root (оба пути в одном формате, регистр не важен).
func Under(root, object string) bool {
	root, object = strings.ToLower(strings.TrimRight(root, `\`)), strings.ToLower(object)
	return object == root || strings.HasPrefix(object, root+`\`)
}

// Subscribe вызывает onRead для каждого события чтения. Событие приходит из системы сразу, без опроса журнала.
// Обработчик вызывается из потока ОС и должен возвращаться быстро.
func Subscribe(onRead func(Read)) (closeFn func(), err error) {
	query, err := windows.UTF16PtrFromString("*[System[EventID=4663]]")
	if err != nil {
		return nil, err
	}
	channel, err := windows.UTF16PtrFromString("Security")
	if err != nil {
		return nil, err
	}
	cb := windows.NewCallback(func(action, _, event uintptr) uintptr {
		if action != actionDeliver {
			return 0
		}
		if b := render(event); b != nil {
			if r, err := parseRead(b); err == nil {
				onRead(r)
			}
		}
		return 0
	})
	h, _, e := procSubscribe.Call(0, 0, uintptr(unsafe.Pointer(channel)), uintptr(unsafe.Pointer(query)), 0, 0, cb, subscribeToFuture)
	if h == 0 {
		return nil, e
	}
	return func() { _, _, _ = procEvtClose.Call(h) }, nil
}

func render(event uintptr) []byte {
	var used, props uint32
	_, _, _ = procRender.Call(0, event, renderEventXML, 0, 0, uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
	if used == 0 {
		return nil
	}
	buf := make([]uint16, used/2+1)
	if r, _, _ := procRender.Call(0, event, renderEventXML, uintptr(used), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props))); r == 0 {
		return nil
	}
	return []byte(windows.UTF16ToString(buf))
}
