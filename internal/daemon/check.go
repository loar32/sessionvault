//go:build linux

package daemon

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/loar32/sessionvault/internal/checkup"
	"github.com/loar32/sessionvault/internal/i18n"
)

// Проверка системы (sessionvault check): только чтение. Её делает служба — части сведений (sudo, файрвол) без root
// не получить, а владельцу для отчёта пароль не нужен.

type mount struct {
	point, fstype, source string
}

func mounts() []mount {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	return parseMountinfo(b)
}

// parseMountinfo — точка монтирования, тип и источник из /proc/self/mountinfo (поля после « - »).
func parseMountinfo(b []byte) []mount {
	var out []mount
	for _, line := range strings.Split(string(b), "\n") {
		left, right, ok := strings.Cut(line, " - ")
		f, r := strings.Fields(left), strings.Fields(right)
		if !ok || len(f) < 5 || len(r) < 2 {
			continue
		}
		out = append(out, mount{point: unescapeMount(f[4]), fstype: r[0], source: r[1]})
	}
	return out
}

func unescapeMount(s string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(s)
}

// mountOf — файловая система, на которой лежит путь (самая длинная точка монтирования над ним).
func mountOf(ms []mount, path string) mount {
	var best mount
	for _, m := range ms {
		if (path == m.point || m.point == "/" || strings.HasPrefix(path, m.point+"/")) && len(m.point) >= len(best.point) {
			best = m
		}
	}
	return best
}

// encrypted — устройство лежит на dm-crypt (LUKS): само или через LVM, RAID и т. п. (цепочка slaves в sysfs).
func encrypted(sys, dev string, depth int) bool {
	if depth > 8 {
		return false
	}
	name := filepath.Base(dev)
	if real, err := filepath.EvalSymlinks(dev); err == nil && strings.HasPrefix(dev, "/dev/") {
		name = filepath.Base(real)
	}
	if b, err := os.ReadFile(filepath.Join(sys, "class/block", name, "dm/uuid")); err == nil && strings.HasPrefix(string(b), "CRYPT-") {
		return true
	}
	slaves, _ := os.ReadDir(filepath.Join(sys, "class/block", name, "slaves"))
	for _, s := range slaves {
		if encrypted(sys, s.Name(), depth+1) {
			return true
		}
	}
	return false
}

func readTrim(path string) string {
	b, _ := os.ReadFile(path)
	return strings.TrimSpace(string(b))
}

func active(unit string) bool {
	return exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil
}

func output(timeout time.Duration, name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, _ := exec.CommandContext(ctx, name, args...).Output()
	return string(out)
}

// passwordlessSudo — sudo для владельца без пароля на любые команды.
func passwordlessSudo(listing string) bool {
	for _, line := range strings.Split(listing, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "NOPASSWD:") && strings.HasSuffix(line, "ALL") {
			return true
		}
	}
	return false
}

// lastUpgrade — время последнего полного обновления по журналу pacman. Если его не было, отсчёт идёт от установки
// системы (первая запись журнала): свежеустановленная система не устарела.
func lastUpgrade(log []byte) time.Time {
	var first, last time.Time
	sc := bufio.NewScanner(bytes.NewReader(log))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		end := strings.IndexByte(line, ']')
		if !strings.HasPrefix(line, "[") || end < 0 {
			continue
		}
		var t time.Time
		for _, layout := range []string{"2006-01-02T15:04:05-0700", "2006-01-02T15:04:05Z0700", "2006-01-02 15:04"} {
			if p, err := time.Parse(layout, line[1:end]); err == nil {
				t = p
				break
			}
		}
		if t.IsZero() {
			continue
		}
		if first.IsZero() {
			first = t
		}
		if strings.Contains(line, "starting full system upgrade") {
			last = t
		}
	}
	if last.IsZero() {
		return first
	}
	return last
}

func autologin() bool {
	for _, pat := range []string{"/etc/systemd/system/getty@*.service.d/*.conf", "/etc/sddm.conf.d/*.conf", "/etc/sddm.conf",
		"/etc/greetd/config.toml", "/etc/lightdm/lightdm.conf", "/etc/gdm/custom.conf"} {
		files, _ := filepath.Glob(pat)
		for _, f := range files {
			b := readTrim(f)
			if strings.Contains(b, "--autologin") || strings.Contains(b, "initial_session") ||
				strings.Contains(b, "autologin-user=") || strings.Contains(b, "AutomaticLoginEnable=true") ||
				(strings.Contains(b, "[Autologin]") && strings.Contains(b, "User=")) {
				return true
			}
		}
	}
	return false
}

func item(id, title string, l checkup.Level, detail, hint string) checkup.Item {
	return checkup.Item{ID: id, Title: title, Level: l, Detail: detail, Hint: hint}
}

// Check — отчёт о защите системы и самого SessionVault.
func (d *Daemon) Check() checkup.Report {
	var items []checkup.Item
	ms := mounts()
	home := mountOf(ms, d.cfg.OwnerHome)
	root := mountOf(ms, "/")
	diskOK := encrypted("/sys", home.source, 0) && encrypted("/sys", root.source, 0)
	if diskOK {
		items = append(items, item("disk", i18n.T("Шифрование диска"), checkup.OK, i18n.T("система и дом на зашифрованном разделе (LUKS)"), ""))
	} else {
		items = append(items, item("disk", i18n.T("Шифрование диска"), checkup.Warn, i18n.T("диск не зашифрован"),
			i18n.T("Кто получит ноутбук или диск, прочитает всё, кроме хранилищ SessionVault. Omarchy включает LUKS при установке: переустановите с шифрованием диска.")))
	}
	var plain []string
	if b, err := os.ReadFile("/proc/swaps"); err == nil {
		for _, line := range strings.Split(string(b), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) < 2 || strings.HasPrefix(filepath.Base(f[0]), "zram") {
				continue
			}
			dev := f[0]
			if f[1] == "file" {
				dev = mountOf(ms, f[0]).source
			}
			if !encrypted("/sys", dev, 0) {
				plain = append(plain, f[0])
			}
		}
	}
	if len(plain) == 0 {
		items = append(items, item("swap", i18n.T("Файл подкачки"), checkup.OK, i18n.T("нет или зашифрован (zram — в памяти)"), ""))
	} else {
		items = append(items, item("swap", i18n.T("Файл подкачки"), checkup.Warn, i18n.Tf("на незашифрованном диске: %s", strings.Join(plain, ", ")),
			i18n.T("Туда может попасть память запущенных приложений, а с ней расшифрованные данные. Включите шифрование диска или оставьте только zram.")))
	}
	if _, err := os.Stat("/sys/firmware/efi"); err != nil {
		items = append(items, item("secureboot", "Secure Boot", checkup.Info, i18n.T("загрузка без UEFI"), ""))
	} else if b, err := os.ReadFile("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"); err == nil && len(b) == 5 && b[4] == 1 {
		items = append(items, item("secureboot", "Secure Boot", checkup.OK, i18n.T("включён"), ""))
	} else {
		items = append(items, item("secureboot", "Secure Boot", checkup.Info, i18n.T("выключен"),
			i18n.T("Защищает от подмены загрузчика и ядра. Необязателен, но с шифрованием диска закрывает подмену системы, пока вас нет рядом.")))
	}
	ufw := strings.Contains(readTrim("/etc/ufw/ufw.conf"), "ENABLED=yes") && active("ufw")
	if ufw || active("firewalld") || active("nftables") {
		items = append(items, item("firewall", i18n.T("Файрвол"), checkup.OK, i18n.T("включён"), ""))
	} else {
		items = append(items, item("firewall", i18n.T("Файрвол"), checkup.Warn, i18n.T("не включён"),
			i18n.T("Входящие подключения к открытым портам ничто не фильтрует: sudo ufw enable (Omarchy включает ufw по умолчанию).")))
	}
	if b, err := os.ReadFile("/var/log/pacman.log"); err == nil {
		t := lastUpgrade(b)
		switch days := int(time.Since(t).Hours() / 24); {
		case t.IsZero():
			items = append(items, item("updates", i18n.T("Обновления"), checkup.Warn, i18n.T("журнал pacman пуст"), i18n.T("Обновите систему: omarchy-update (или sudo pacman -Syu).")))
		case days > 30:
			items = append(items, item("updates", i18n.T("Обновления"), checkup.Warn, i18n.Tf("последнее обновление %d дн. назад", days), i18n.T("Обновите систему: omarchy-update (или sudo pacman -Syu).")))
		default:
			items = append(items, item("updates", i18n.T("Обновления"), checkup.OK, i18n.Tf("последнее обновление %d дн. назад", days), ""))
		}
	}
	if passwordlessSudo(output(10*time.Second, "sudo", "-l", "-U", d.cfg.OwnerName)) {
		items = append(items, item("sudo", "sudo", checkup.Bad, i18n.T("работает без пароля"),
			i18n.T("Любая программа вашей учётки получает root и с ним доступ ко всему, что защищает SessionVault. Уберите NOPASSWD из /etc/sudoers.d.")))
	} else {
		items = append(items, item("sudo", "sudo", checkup.OK, i18n.T("спрашивает пароль"), ""))
	}
	if scope, _ := strconv.Atoi(readTrim("/proc/sys/kernel/yama/ptrace_scope")); scope >= 1 {
		items = append(items, item("ptrace", i18n.T("Чтение памяти процессов"), checkup.OK, i18n.T("только своих потомков (ptrace_scope ≥ 1)"), ""))
	} else {
		items = append(items, item("ptrace", i18n.T("Чтение памяти процессов"), checkup.Bad, i18n.T("любая программа читает память ваших программ"),
			i18n.T("Так можно подсмотреть мастер-пароль, пока вы его вводите: echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope и kernel.yama.ptrace_scope=1 в /etc/sysctl.d.")))
	}
	idle := false
	for _, pid := range pidsOf(d.cfg.Owner) {
		if c := readTrim(filepath.Join("/proc", strconv.Itoa(pid), "comm")); c == "hypridle" || c == "swayidle" {
			idle = true
		}
	}
	if idle {
		items = append(items, item("idle", i18n.T("Блокировка по бездействию"), checkup.OK, i18n.T("включена"), ""))
	} else {
		items = append(items, item("idle", i18n.T("Блокировка по бездействию"), checkup.Warn, i18n.T("не работает"),
			i18n.T("Оставленный без присмотра компьютер не заблокируется сам, а с ним и хранилище (через 4 часа заблокирует только SessionVault). В Omarchy: меню → Toggle → Idle lock.")))
	}
	if autologin() && !diskOK {
		items = append(items, item("autologin", i18n.T("Автовход"), checkup.Bad, i18n.T("сеанс открывается без пароля, а диск не зашифрован"),
			i18n.T("Кто включит компьютер, получит ваш сеанс. Включите шифрование диска (тогда пароль спрашивается при загрузке) или выключите автовход.")))
	}
	items = append(items, d.selfCheck()...)
	items = append(items,
		item("telegram", i18n.T("Код-пароль Telegram"), checkup.Info, i18n.T("включается в самом Telegram"),
			i18n.T("Настройки → Конфиденциальность → Код-пароль: без него украденные файлы tdata открываются сразу")),
		item("clickfix", "ClickFix", checkup.Info, i18n.T("не запускайте чужие команды"),
			i18n.T("Не вставляйте в терминал команды с сайтов и из «проверок, что вы не робот»: так вы сами запускаете вредонос с вашими правами.")))
	return checkup.Summarize(items, time.Now())
}

// selfCheck — состояние самого SessionVault: приманки, ключ восстановления, забытые открытые копии данных.
func (d *Daemon) selfCheck() []checkup.Item {
	var items []checkup.Item
	d.mu.Lock()
	fan := d.fan
	d.mu.Unlock()
	protected := Protected()
	switch {
	case len(protected) == 0:
		items = append(items, item("protected", i18n.T("Защищённые приложения"), checkup.Warn, i18n.T("нет"),
			i18n.T("Защитите приложение: sudo sessionvault protect telegram (или chromium, brave, chrome, discord), своё — sudo sessionvault add.")))
	case fan == nil:
		items = append(items, item("decoys", i18n.T("Приманки"), checkup.Bad, i18n.T("не под наблюдением"), i18n.T("Посмотрите журнал: journalctl -u sessionvault")))
	default:
		mode := i18n.T("с задержкой открывающего")
		if !fan.perm {
			mode = i18n.T("уведомлениями")
		}
		items = append(items, item("decoys", i18n.T("Приманки"), checkup.OK, i18n.Tf("под наблюдением: %d файлов (%s)", fan.count(), mode), ""))
	}
	var without []string
	for _, a := range protected {
		if !appVault(a).HasRecovery() {
			without = append(without, a.Name)
		}
	}
	if len(protected) > 0 {
		if len(without) == 0 {
			items = append(items, item("recovery", i18n.T("Ключ восстановления"), checkup.OK, i18n.T("открывает все хранилища"), ""))
		} else {
			items = append(items, item("recovery", i18n.T("Ключ восстановления"), checkup.Warn, i18n.Tf("не открывает: %s", strings.Join(without, ", ")),
				i18n.T("Без него забытый мастер-пароль — потерянные данные: sudo sessionvault recovery create (24 слова на бумагу).")))
		}
	}
	var open []string
	for _, a := range protected {
		for _, dir := range a.Dirs {
			parent := filepath.Dir(filepath.Join(d.cfg.OwnerHome, dir))
			for _, n := range ownerList(d.cfg, parent) {
				if strings.HasPrefix(n, filepath.Base(dir)+".before-sessionvault-") {
					open = append(open, filepath.Join(parent, n))
				}
			}
		}
	}
	if len(open) > 0 {
		items = append(items, item("leftovers", i18n.T("Открытые копии данных"), checkup.Warn, strings.Join(open, ", "),
			i18n.T("Это данные приложения, запущенного в обход SessionVault: их читает любой стилер. Перенесите нужное в защищённое приложение и удалите папку.")))
	}
	var unprotected []string
	for _, a := range Apps {
		if appVault(a).Exists() {
			continue
		}
		if fi, err := os.Lstat(filepath.Join(d.cfg.OwnerHome, a.Dirs[0])); err == nil && fi.IsDir() {
			unprotected = append(unprotected, a.Name)
		}
	}
	if len(unprotected) > 0 {
		items = append(items, item("unprotected", i18n.T("Незащищённые сессии"), checkup.Warn, strings.Join(unprotected, ", "),
			fmt.Sprintf(i18n.T("Данные этих приложений лежат открыто: sudo sessionvault protect %s"), unprotected[0])))
	}
	if _, err := os.Stat(dbusProxyPath); err != nil {
		items = append(items, item("dbus", i18n.T("Шина сеанса в песочнице"), checkup.Warn, i18n.T("нет xdg-dbus-proxy"),
			i18n.T("Без него у защищённых приложений нет уведомлений, значка в трее и связки ключей: sudo pacman -S xdg-dbus-proxy")))
	}
	return items
}
