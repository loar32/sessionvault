package audit

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const listModulesAll = 3 // LIST_MODULES_ALL: и 32-, и 64-разрядные

// LoadedModules — пути к модулям (exe и DLL), загруженным в процесс. Процесс уже мог выйти или быть недоступен: тогда ошибка.
func LoadedModules(pid uint32) ([]string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	mods := make([]windows.Handle, 1024)
	var need uint32
	if err := windows.EnumProcessModulesEx(h, &mods[0], uint32(len(mods))*uint32(unsafe.Sizeof(mods[0])), &need, listModulesAll); err != nil {
		return nil, err
	}
	n := min(int(need)/int(unsafe.Sizeof(mods[0])), len(mods))
	paths := make([]string, 0, n)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	for _, m := range mods[:n] {
		if err := windows.GetModuleFileNameEx(h, m, &buf[0], uint32(len(buf))); err == nil {
			paths = append(paths, windows.UTF16ToString(buf))
		}
	}
	return paths, nil
}
