package audit

import "golang.org/x/sys/windows"

const accessSystemSecurity = 0x01000000

// Маска 0x3a в SDDL: чтение и запись памяти (0x10, 0x20), операции с памятью (0x8), создание потока (0x2).
// Запрос сведений (QUERY_INFORMATION) и завершение не пишутся: обычный диспетчер задач не должен шуметь.

// WatchProcess ставит на процесс аудит успешных и отказанных обращений с этими правами от учётки who (основной учётки: так
// стилер, запущенный пользователем, виден, а возня процессов самого приложения под своей учёткой журнал не засоряет).
// Нужна привилегия SeSecurityPrivilege; событие приходит, только если включён аудит объектов ядра (EnableMemoryAudit).
func WatchProcess(pid uint32, who *windows.SID) error {
	h, err := windows.OpenProcess(accessSystemSecurity, false, pid)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	sd, err := windows.SecurityDescriptorFromString("S:(AU;SAFA;0x3a;;;" + who.String() + ")")
	if err != nil {
		return err
	}
	sacl, _, err := sd.SACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.SACL_SECURITY_INFORMATION, nil, nil, nil, sacl)
}
