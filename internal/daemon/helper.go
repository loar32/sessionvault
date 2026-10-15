//go:build linux

package daemon

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/loar32/sessionvault/internal/i18n"
	"github.com/loar32/sessionvault/internal/vault"
)

// Всё, что служба делает в домашнем каталоге владельца (перенос данных, приманка, ярлыки, права на папки), выполняет
// помощник с правами владельца: root, идущий по путям чужого каталога, прошёл бы по подставленной ссылке к системным
// файлам. Распаковку копии программы делает помощник с правами учётки приложения — по той же причине.

const desktopMarker = "X-SessionVault=true"

// RunHelper — команда «sessionvault helper ...»; вызывается только службой и командами root с правами владельца или
// учётки приложения.
func RunHelper(args []string) error {
	if os.Geteuid() == 0 {
		return errors.New("helper не запускается от root")
	}
	if len(args) < 2 || !filepath.IsAbs(args[1]) {
		return errors.New("helper: неверные аргументы")
	}
	path := args[1]
	switch args[0] {
	case "pack":
		// Нет папки (приложение ещё не запускалось) — пустой вывод. Кэши приложения в архив не идут.
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		var exclude []string
		if len(args) == 3 {
			if a, ok := FindApp(args[2]); ok {
				exclude = a.Exclude
			}
		}
		_, err := vault.WriteTar(os.Stdout, path, exclude)
		return err
	case "unpack":
		// На месте приманки уже что-то есть (приложение запускали в обход SessionVault): это откладывается рядом, не теряется.
		if entries, err := os.ReadDir(path); err == nil && len(entries) > 0 {
			aside := path + ".before-sessionvault-" + time.Now().Format("20060102-150405")
			if err := os.Rename(path, aside); err != nil {
				return fmt.Errorf(i18n.T("%s уже существует и не пуст: данные не возвращены"), path)
			}
			fmt.Printf(i18n.T("На месте данных были файлы, они перенесены в %s\n"), aside)
		}
		return vault.ExtractTar(os.Stdin, path)
	case "remove":
		return os.RemoveAll(path)
	case "decoy":
		if len(args) != 3 {
			return errors.New("helper decoy: нужна раскладка")
		}
		files, err := makeDecoy(args[2], path)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(files)
	case "undecoy":
		var files []DecoyFile
		if err := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20)).Decode(&files); err != nil {
			return err
		}
		return removeDecoy(path, files)
	case "put", "replace":
		// put пишет ярлык, только если на этом месте нет чужого файла (своё — с меткой SessionVault). replace — после того,
		// как служба сохранила прежний файл владельца.
		if b, err := os.ReadFile(path); err == nil && args[0] == "put" && !bytes.Contains(b, []byte(desktopMarker)) {
			return fmt.Errorf(i18n.T("%s уже есть и это не ярлык SessionVault"), path)
		}
		data, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		_ = os.Remove(path) // ссылка на месте ярлыка заменяется файлом, а не переписывает цель
		return os.WriteFile(path, data, 0o644)
	case "del":
		b, err := os.ReadFile(path)
		if err != nil || !bytes.Contains(b, []byte(desktopMarker)) {
			return nil
		}
		return os.Remove(path)
	case "read":
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		fi, err := f.Stat()
		if err != nil || !fi.Mode().IsRegular() {
			return errors.New(i18n.T("не обычный файл"))
		}
		_, err = io.Copy(os.Stdout, f)
		return err
	case "magic":
		// Первые байты файла: по ним узнаётся AppImage.
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		b := make([]byte, 16)
		n, _ := io.ReadFull(f, b)
		fmt.Println(hex.EncodeToString(b[:n]))
		return nil
	case "list":
		// Имена в каталоге (для поиска ярлыков и папок данных): только имена, без содержимого.
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil
		}
		for _, e := range entries {
			fmt.Println(e.Name())
		}
		return nil
	case "update-db":
		if _, err := os.Stat("/usr/bin/update-desktop-database"); err != nil {
			return nil
		}
		return exec.Command("/usr/bin/update-desktop-database", "-q", path).Run()
	case "packprog":
		return writeProgramTar(os.Stdout, path)
	case "untar":
		return extractProgramTar(os.Stdin, path)
	case "appimage":
		return extractAppImage(os.Stdin, path)
	case "acl":
		// acl <папка> grant|revoke <uid учётки> <uid владельца>: права учётки приложения на папку владельца ставит сам
		// владелец — так права нельзя выдать на чужой файл через ссылку.
		if len(args) != 5 {
			return errors.New("helper acl: неверные аргументы")
		}
		return shareACL(path, args[2], args[3], args[4])
	case "link":
		if len(args) != 3 {
			return errors.New("helper link: нужна цель")
		}
		if fi, err := os.Lstat(path); err == nil {
			if fi.Mode()&os.ModeSymlink == 0 {
				return nil
			}
			_ = os.Remove(path)
		}
		return os.Symlink(args[2], path)
	case "unlink":
		if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return os.Remove(path)
		}
		return nil
	}
	return errors.New("helper: неизвестная команда")
}

// helperBin — исполняемый файл для помощника: установленный (его не может подменить владелец), иначе текущий.
func helperBin() string {
	if _, err := os.Stat(BinPath); err == nil {
		return BinPath
	}
	exe, _ := os.Executable()
	return exe
}

func helperCmd(cred *syscall.Credential, home string, args ...string) *exec.Cmd {
	cmd := exec.Command(helperBin(), append([]string{"helper"}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	cmd.Env = []string{"HOME=" + home, "PATH=/usr/local/bin:/usr/bin", "LANG=C.UTF-8"}
	cmd.Dir = "/"
	return cmd
}

func helperErr(err error, stderr *bytes.Buffer) error {
	msg := strings.TrimSpace(stderr.String())
	if msg == "" {
		msg = err.Error()
	}
	return errors.New(msg)
}

// asOwner запускает помощника с правами владельца (его uid, gid и группы) и возвращает его вывод.
func asOwner(cfg Config, stdin []byte, args ...string) ([]byte, error) {
	var out bytes.Buffer
	var in io.Reader
	if stdin != nil {
		in = bytes.NewReader(stdin)
	}
	if err := ownerStream(cfg, in, &out, args...); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// ownerStream — помощник владельца с потоками: большие данные не собираются в памяти.
func ownerStream(cfg Config, stdin io.Reader, stdout io.Writer, args ...string) error {
	cred, err := ownerCred(cfg)
	if err != nil {
		return err
	}
	cmd := helperCmd(cred, cfg.OwnerHome, args...)
	var errb bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, &errb
	if err := cmd.Run(); err != nil {
		return helperErr(err, &errb)
	}
	return nil
}

// packFromOwner переносит папку владельца src в dst (каталог root) потоком tar. Возвращает false, если переносить было
// нечего: тогда dst не остаётся.
func packFromOwner(cfg Config, src, app, dst string) (bool, error) {
	cred, err := ownerCred(cfg)
	if err != nil {
		return false, err
	}
	cmd := helperCmd(cred, cfg.OwnerHome, "pack", src, app)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return false, err
	}
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		return false, err
	}
	xerr := vault.ExtractTar(out, dst)
	_, _ = io.Copy(io.Discard, out)
	if err := cmd.Wait(); err != nil {
		return false, helperErr(err, &errb)
	}
	if xerr != nil {
		return false, xerr
	}
	if entries, err := os.ReadDir(dst); err == nil && len(entries) == 0 {
		_ = os.Remove(dst)
		return false, nil
	}
	return true, nil
}

// unpackToOwner возвращает папку src (каталог root) владельцу в dst потоком tar; вывод помощника — сообщения для человека.
func unpackToOwner(cfg Config, src string, exclude []string, dst string) ([]byte, error) {
	cred, err := ownerCred(cfg)
	if err != nil {
		return nil, err
	}
	cmd := helperCmd(cred, cfg.OwnerHome, "unpack", dst)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	_, werr := vault.WriteTar(in, src, exclude)
	_ = in.Close()
	if err := cmd.Wait(); err != nil {
		return nil, helperErr(err, &errb)
	}
	return out.Bytes(), werr
}

func ownerCred(cfg Config) (*syscall.Credential, error) {
	u, err := user.LookupId(strconv.Itoa(cfg.Owner))
	if err != nil {
		return nil, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil, err
	}
	cred := &syscall.Credential{Uid: uint32(cfg.Owner), Gid: uint32(gid)}
	if ids, err := u.GroupIds(); err == nil {
		for _, s := range ids {
			if g, err := strconv.Atoi(s); err == nil {
				cred.Groups = append(cred.Groups, uint32(g))
			}
		}
	}
	return cred, nil
}

func ownerGID(cfg Config) int {
	if u, err := user.LookupId(strconv.Itoa(cfg.Owner)); err == nil {
		if g, err := strconv.Atoi(u.Gid); err == nil {
			return g
		}
	}
	return cfg.Owner
}

// ownerList — имена в каталоге владельца (его помощником).
func ownerList(cfg Config, dir string) []string {
	b, err := asOwner(cfg, nil, "list", dir)
	if err != nil || len(bytes.TrimSpace(b)) == 0 {
		return nil
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}
