// standin — заглушка вместо Telegram для тестов: живёт, чтобы access-check было к чему тянуться, и один раз
// пробует то, что вредоносному коду внутри приложения должно быть запрещено; итог пишет в probe.txt в рабочей папке.
package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const exchange = `C:\ProgramData\SessionVault\exchange`

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-exit" {
		return
	}
	work := "."
	for i, a := range os.Args {
		if a == "-workdir" && i+1 < len(os.Args) {
			work = os.Args[i+1]
		}
	}
	go probe(work)
	time.Sleep(30 * time.Minute)
}

func probe(work string) {
	self, err := os.Executable()
	if err != nil {
		return
	}
	var out []string
	rep := func(name string, ok bool) {
		v := "no"
		if ok {
			v = "yes"
		}
		out = append(out, name+"="+v)
	}
	for _, where := range []struct{ name, dir string }{{"work", work}, {"exchange", exchange}} {
		dst := filepath.Join(where.dir, "copy.exe")
		rep(where.name+"_write", copyFile(self, dst) == nil)
		// Если копию нельзя исполнить, запуск вернёт ошибку доступа.
		rep(where.name+"_exec", exec.Command(dst, "-exit").Run() == nil)
		// Смена прав: vault не должен уметь разрешить себе запуск.
		rep(where.name+"_chmod", exec.Command("icacls", dst, "/grant", "vault:(RX)").Run() == nil)
	}
	_ = os.WriteFile(filepath.Join(work, "probe.txt"), []byte(strings.Join(out, "\r\n")+"\r\nEND\r\n"), 0o644)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, in)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
