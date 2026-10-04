package service

import "os"

const maxLogSize = 1 << 20

// Журналы пишет служба от SYSTEM, и без предела они росли бы годами: больше мегабайта уходит в .1 (прежний .1 заменяется).
func rotateLog(path string) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxLogSize {
		_ = os.Remove(path + ".1")
		_ = os.Rename(path, path+".1")
	}
}
