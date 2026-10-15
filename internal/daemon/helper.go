//go:build linux

package daemon

import (
	"bytes"
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

// Всё, что служба делает в домашнем каталоге владельца (перенос данных, приманка, ярлыки), выполняет помощник с правами
// владельца: root, идущий по путям чужого каталога, прошёл бы по подставленной ссылке к системным файлам.

const desktopMarker = "X-SessionVault=true"

// RunHelper — команда «sessionvault helper ...»; вызывается только службой и командами root с правами владельца.
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
		data, _, err := vault.PackDir(path, exclude)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(data)
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
		data, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<30+1))
		if err != nil {
			return err
		}
		return vault.UnpackDir(data, path)
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
	case "put":
		// Ярлык пишется, только если на этом месте нет чужого файла (своё — с меткой SessionVault).
		if b, err := os.ReadFile(path); err == nil && !bytes.Contains(b, []byte(desktopMarker)) {
			return fmt.Errorf(i18n.T("%s уже есть и это не ярлык SessionVault"), path)
		}
		data, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		return os.WriteFile(path, data, 0o644)
	case "del":
		b, err := os.ReadFile(path)
		if err != nil || !bytes.Contains(b, []byte(desktopMarker)) {
			return nil
		}
		return os.Remove(path)
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

// asOwner запускает помощника с правами владельца (его uid, gid и группы) и возвращает его вывод.
func asOwner(cfg Config, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command(helperBin(), append([]string{"helper"}, args...)...)
	cred, err := ownerCred(cfg)
	if err != nil {
		return nil, err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	cmd.Env = []string{"HOME=" + cfg.OwnerHome, "PATH=/usr/local/bin:/usr/bin", "LANG=C.UTF-8"}
	cmd.Dir = "/"
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(msg)
	}
	return out.Bytes(), nil
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
