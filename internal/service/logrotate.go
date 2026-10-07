package service

import (
	"fmt"
	"os"
	"sync"
)

const maxLogSize = 1 << 20

// Журналы пишет служба от SYSTEM, и без предела они росли бы годами: больше мегабайта уходит в .1 (прежний .1 заменяется).
func rotateLog(path string) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxLogSize {
		_ = os.Remove(path + ".1")
		_ = os.Rename(path, path+".1")
	}
}

// Писатель журнала службы: служба живёт неделями, и ротация только при старте не удержала бы размер.
type rotatingFile struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

func openRotating(path string) (*rotatingFile, error) {
	rotateLog(path)
	r := &rotatingFile{path: path}
	return r, r.open()
}

func (r *rotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	r.f, r.size = f, fi.Size()
	return nil
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size > maxLogSize {
		_ = r.f.Close()
		rotateLog(r.path)
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

// rotateLogKeep хранит несколько прежних частей (.1 — самая свежая): журнал обращений к памяти нужен для разбора, и при долгой
// атаке одной сменившейся части мало.
func rotateLogKeep(path string, keep int) {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() <= maxLogSize {
		return
	}
	_ = os.Remove(fmt.Sprintf("%s.%d", path, keep))
	for i := keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", path, i), fmt.Sprintf("%s.%d", path, i+1))
	}
	_ = os.Rename(path, path+".1")
}
