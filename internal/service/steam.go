package service

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/loar32/sessionvault/internal/audit"
	"github.com/loar32/sessionvault/internal/decoy"
	"github.com/loar32/sessionvault/internal/i18n"
	"github.com/loar32/sessionvault/internal/ipc"
	"github.com/loar32/sessionvault/internal/isolation"
	"github.com/loar32/sessionvault/internal/profiles"
	"github.com/loar32/sessionvault/internal/vault"
	"golang.org/x/sys/windows"
)

// Steam остаётся в учётке пользователя: игры и их сохранения не должны переезжать в чужую учётку. Поэтому защита другая:
// пока клиент закрыт, файлы сессии лежат зашифрованными в хранилище, а на их местах приманка; при запуске из SessionVault
// служба возвращает файлы на место и запускает клиент от имени пользователя, при выходе последнего процесса клиента и
// игр шифрует и убирает снова. Пока Steam запущен, его файлы открыты (как у любого пользователя без защиты).

const (
	maxPlaceBytes = 256 << 20
	stageKeep     = ".keep" // файл-метка: хранилище с пустыми местами (Steam без входа) не считалось бы пустым архивом
)

var steamProcesses = []string{"steam.exe", "steamwebhelper.exe", "steamservice.exe"}

var errPlaceTooBig = errors.New("данные Steam больше 256 МБ: шифрование отменено")

func placeKey(profile string, i int) string { return fmt.Sprintf("%s#%d", profile, i) }

func stageDir(profile string, i int) string {
	return filepath.Join(isolation.WorkPath(profile), "places", fmt.Sprintf("p%d", i))
}

type placeFile struct {
	rel  string
	data []byte
	mod  time.Time
}

// matches — файлы места-списка (ssfn*): только обычные файлы прямо в папке.
func matches(pl profiles.Place) []string {
	var out []string
	for _, pat := range pl.Files {
		m, _ := filepath.Glob(filepath.Join(pl.Path, pat))
		for _, abs := range m {
			if fi, err := os.Lstat(abs); err == nil && fi.Mode().IsRegular() {
				out = append(out, abs)
			}
		}
	}
	return out
}

// placeHasData — на месте лежит что-то настоящее (пустая папка и приманка не считаются: приманку отличают по записи о ней).
func placeHasData(pl profiles.Place) bool {
	if len(pl.Files) > 0 {
		return len(matches(pl)) > 0
	}
	entries, err := os.ReadDir(pl.Path)
	return err == nil && len(entries) > 0
}

// readPlace читает файлы места в память. Ссылки пропускаются, кэши (Exclude) не берутся.
func readPlace(pl profiles.Place) ([]placeFile, error) {
	var files []placeFile
	var total int64
	add := func(abs, rel string) error {
		fi, err := os.Stat(abs)
		if err != nil {
			return err
		}
		if total += fi.Size(); total > maxPlaceBytes {
			return errPlaceTooBig
		}
		b, err := os.ReadFile(abs)
		if err != nil {
			return err
		}
		files = append(files, placeFile{rel, b, fi.ModTime()})
		return nil
	}
	if len(pl.Files) > 0 {
		for _, abs := range matches(pl) {
			if err := add(abs, filepath.Base(abs)); err != nil {
				return nil, err
			}
		}
		return files, nil
	}
	err := filepath.WalkDir(pl.Path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == pl.Path && errors.Is(err, fs.ErrNotExist) {
				return fs.SkipAll
			}
			return err
		}
		if d.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(pl.Path, p)
		if rel != "." && vault.Excluded(rel, pl.Exclude) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		return add(p, rel)
	})
	return files, err
}

// writePlace кладёт файлы на место; вызывается от имени пользователя, поэтому файлы принадлежат ему.
func writePlace(pl profiles.Place, files []placeFile) error {
	if len(pl.Files) == 0 {
		if err := os.MkdirAll(pl.Path, 0o755); err != nil {
			return err
		}
	}
	for _, f := range files {
		if !filepath.IsLocal(f.rel) {
			return fmt.Errorf(i18n.T("недопустимый путь в архиве: %q"), f.rel)
		}
		dst := filepath.Join(pl.Path, f.rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, f.data, 0o644); err != nil {
			return err
		}
		_ = os.Chtimes(dst, f.mod, f.mod)
	}
	return nil
}

func removePlace(pl profiles.Place) error {
	if len(pl.Files) == 0 {
		return os.RemoveAll(pl.Path)
	}
	var errs []error
	for _, abs := range matches(pl) {
		if err := os.Remove(abs); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func stageRead(profile string, i int) ([]placeFile, error) {
	root := stageDir(profile, i)
	var files []placeFile
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root && errors.Is(err, fs.ErrNotExist) {
				return fs.SkipAll
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		files = append(files, placeFile{rel, b, fi.ModTime()})
		return nil
	})
	return files, err
}

func stageWrite(profile string, i int, files []placeFile) error {
	root := stageDir(profile, i)
	if err := os.RemoveAll(root); err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	if i == 0 {
		if err := os.WriteFile(filepath.Join(filepath.Dir(root), stageKeep), nil, 0o644); err != nil {
			return err
		}
	}
	for _, f := range files {
		dst := filepath.Join(root, f.rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, f.data, 0o644); err != nil {
			return err
		}
		_ = os.Chtimes(dst, f.mod, f.mod)
	}
	return nil
}

// anyProcess — запущен ли процесс с одним из имён (в любой учётке).
func anyProcess(names []string) bool {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(snap) }()
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		name := windows.UTF16ToString(pe.ExeFile[:])
		for _, n := range names {
			if strings.EqualFold(name, n) {
				return true
			}
		}
	}
	return false
}

// asUserOrDirect выполняет работу с папками пользователя от его имени: SYSTEM не должен менять файлы по пути, который
// пользователь мог подменить ссылкой. Без токена (пользователь вышел) работает напрямую, но не по путям со ссылками.
func asUserOrDirect(tok windows.Token, paths []string, fn func() error) error {
	if tok != 0 {
		return isolation.AsUser(tok, fn)
	}
	for _, p := range paths {
		if err := decoy.NoReparse(p); err != nil {
			return err
		}
	}
	return fn()
}

func placePaths(p profiles.Profile) []string {
	var out []string
	for _, pl := range p.Places {
		out = append(out, pl.Path)
	}
	return out
}

func (s *Service) userToken() (windows.Token, error) {
	sid := s.mainUserSID()
	if sid == nil {
		return 0, isolation.ErrNoUser
	}
	return isolation.UserToken(sid)
}

// sealPlaces собирает настоящие файлы с мест в хранилище и шифрует. Место, где лежит приманка или ничего нет, не трогается:
// в хранилище остаётся прежнее содержимое. remove убирает собранное с мест после шифрования.
func (s *Service) sealPlaces(p profiles.Profile, v vault.Vault, dek []byte, remove bool) error {
	tok, terr := s.userToken()
	if terr == nil {
		defer func() { _ = tok.Close() }()
	} else {
		tok = 0
	}
	taken := make([]bool, len(p.Places))
	all := make([][]placeFile, len(p.Places))
	err := asUserOrDirect(tok, placePaths(p), func() error {
		for i, pl := range p.Places {
			if pl.Decoy != "" && decoy.Owned(placeKey(p.Name, i), pl.Path) {
				continue
			}
			if !placeHasData(pl) {
				continue
			}
			files, err := readPlace(pl)
			if err != nil {
				return err
			}
			all[i], taken[i] = files, true
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i := range p.Places {
		if taken[i] {
			if err := stageWrite(p.Name, i, all[i]); err != nil {
				return err
			}
		}
	}
	if err := v.Encrypt(dek); err != nil {
		return err
	}
	if !remove {
		return nil
	}
	return asUserOrDirect(tok, placePaths(p), func() error {
		var errs []error
		for i, pl := range p.Places {
			if taken[i] {
				if err := removePlace(pl); err != nil {
					errs = append(errs, err)
				}
			}
		}
		return errors.Join(errs...)
	})
}

// restorePlaces возвращает файлы из открытого хранилища на места. Место, где уже лежат настоящие данные (Steam запускали
// мимо SessionVault и входили заново), не затирается: свежее берётся оттуда, а при закрытии попадёт в хранилище.
func (s *Service) restorePlaces(p profiles.Profile) (adopted []string, err error) {
	tok, err := s.userToken()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tok.Close() }()
	owned := make([]bool, len(p.Places))
	for i, pl := range p.Places {
		if pl.Decoy == "" {
			continue
		}
		owned[i] = decoy.Owned(placeKey(p.Name, i), pl.Path)
		// Приманку больше не наблюдаем: на её месте будут настоящие данные.
		s.unwatch(placeKey(p.Name, i), pl.Path)
	}
	// Хранилище читает служба: от имени пользователя рабочая папка недоступна.
	staged := make([][]placeFile, len(p.Places))
	for i := range p.Places {
		if staged[i], err = stageRead(p.Name, i); err != nil {
			return nil, err
		}
	}
	err = isolation.AsUser(tok, func() error {
		for i, pl := range p.Places {
			if owned[i] {
				if err := removePlace(pl); err != nil {
					return err
				}
			} else if placeHasData(pl) {
				adopted = append(adopted, pl.Path)
				continue
			}
			if err := writePlace(pl, staged[i]); err != nil {
				return err
			}
		}
		return nil
	})
	for i := range p.Places {
		if owned[i] {
			_ = decoy.Forget(placeKey(p.Name, i))
		}
	}
	return adopted, err
}

func (s *Service) unwatch(key, path string) {
	s.trapMu.Lock()
	defer s.trapMu.Unlock()
	delete(s.watch, path)
	if nt, err := audit.NTPath(path); err == nil {
		delete(s.watch, nt)
	}
	delete(s.watchKeys, key)
}

// newPlaceJob — job с завершением по закрытию и собственным портом: сообщение «процессов не осталось» приходит и тогда, когда
// клиент перезапустил сам себя (обновление) или за ним остались игры.
func newPlaceJob() (job, port windows.Handle, err error) {
	if job, err = killOnCloseJob(); err != nil {
		return 0, 0, err
	}
	if port, err = windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1); err != nil {
		_ = windows.CloseHandle(job)
		return 0, 0, err
	}
	info := jobCompletionPort{Key: 0, Port: port}
	if _, err = windows.SetInformationJobObject(job, jobObjectAssociateCompletionPort, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(job)
		_ = windows.CloseHandle(port)
		return 0, 0, err
	}
	return job, port, nil
}

func waitJobEmpty(port windows.Handle) {
	for {
		var msg uint32
		var key uintptr
		var ov *windows.Overlapped
		if err := windows.GetQueuedCompletionStatus(port, &msg, &key, &ov, windows.INFINITE); err != nil && ov == nil {
			return
		}
		if msg == jobMsgActiveProcessZero {
			return
		}
	}
}

// startPlaces — запуск приложения, которое остаётся в учётке пользователя (Steam). Вызывается, когда хранилище уже
// расшифровано в рабочую папку.
func (s *Service) startPlaces(p profiles.Profile, v vault.Vault, dek []byte, unlock func(), gen int) (string, error) {
	fail := func(err error) (string, error) {
		unlock()
		return "", errors.Join(err, s.sealPlaces(p, v, dek, true))
	}
	if anyProcess(steamProcesses) {
		return fail(errors.New(i18n.T("Steam уже запущен вне SessionVault: закройте его и повторите")))
	}
	adopted, err := s.restorePlaces(p)
	if err != nil {
		return fail(err)
	}
	for _, a := range adopted {
		s.log.Printf("%s: на %s лежат свои данные приложения, использую их", p.Name, a)
	}
	tok, err := s.userToken()
	if err != nil {
		return fail(err)
	}
	defer func() { _ = tok.Close() }()
	job, port, err := newPlaceJob()
	if err != nil {
		return fail(err)
	}
	proc, thread, err := isolation.StartAsUser(tok, p.CommandLine(""), filepath.Dir(p.Exe))
	if err != nil {
		_ = windows.CloseHandle(job)
		_ = windows.CloseHandle(port)
		return fail(err)
	}
	abort := func(err error) (string, error) {
		_ = windows.TerminateProcess(proc, 1)
		_ = windows.CloseHandle(proc)
		_ = windows.CloseHandle(thread)
		_ = windows.CloseHandle(job)
		_ = windows.CloseHandle(port)
		return fail(err)
	}
	if err := windows.AssignProcessToJobObject(job, proc); err != nil {
		return abort(err)
	}
	s.mu.Lock()
	alarmed := s.alarmGen != gen
	s.mu.Unlock()
	if alarmed {
		return abort(errors.New(i18n.T("тревога во время запуска")))
	}
	s.mu.Lock()
	if s.placeJobs == nil {
		s.placeJobs = map[string]windows.Handle{}
	}
	s.placeJobs[p.Name] = job
	s.mu.Unlock()
	_, _ = windows.ResumeThread(thread)
	_ = windows.CloseHandle(thread)
	_ = windows.CloseHandle(proc)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		waitJobEmpty(port)
		_ = windows.CloseHandle(port)
		s.mu.Lock()
		delete(s.placeJobs, p.Name)
		if s.closing == nil {
			s.closing = map[string]bool{}
		}
		s.closing[p.Name] = true
		s.mu.Unlock()
		_ = windows.CloseHandle(job)
		// Клиент могли запустить ещё раз мимо нас: его файлы шифруются в хранилище, но с места не убираются.
		stray := anyProcess(steamProcesses)
		if stray {
			s.log.Printf("%s: клиент запущен вне SessionVault, файлы остаются на месте", p.Name)
		}
		if err := s.sealPlaces(p, v, dek, !stray); err != nil {
			s.log.Printf("%s: шифрование после закрытия: %v", p.Name, err)
		}
		unlock()
		s.finish(p.Name)
		select {
		case s.nudge <- struct{}{}:
		default:
		}
	}()
	return ipc.Ok, nil
}

// closePlaceJob завершает клиент и всё, что он запустил (меню трея «Закрыть», тревога, остановка службы): сообщение job
// о пустоте запускает шифрование. Возвращает, был ли такой запуск.
func (s *Service) closePlaceJob(name string) bool {
	s.mu.Lock()
	job, ok := s.placeJobs[name]
	s.mu.Unlock()
	if ok {
		_ = windows.TerminateJobObject(job, 1)
	}
	return ok
}

func (s *Service) closeAllPlaceJobs() {
	s.mu.Lock()
	jobs := make([]windows.Handle, 0, len(s.placeJobs))
	for _, j := range s.placeJobs {
		jobs = append(jobs, j)
	}
	s.mu.Unlock()
	for _, j := range jobs {
		_ = windows.TerminateJobObject(j, 1)
	}
}

// placeProfiles — профили приложений, которые остаются в учётке пользователя (Steam), с уже созданным хранилищем.
func placeProfiles() []profiles.Profile {
	entries, err := os.ReadDir(isolation.ProfilesDir())
	if err != nil {
		return nil
	}
	var out []profiles.Profile
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !profiles.ValidName(name) {
			continue
		}
		if p, err := profiles.Load(isolation.ProfilesDir(), name); err == nil && len(p.Places) > 0 {
			out = append(out, p)
		}
	}
	return out
}
