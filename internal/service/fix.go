package service

import (
	"errors"

	"github.com/loar32/sessionvault/internal/asr"
	"github.com/loar32/sessionvault/internal/checkup"
	"github.com/loar32/sessionvault/internal/isolation"
)

// ErrNothingToRevert — `check -fix` ещё не менял правила: откатывать нечего (правила, включённые самим пользователем, не трогаются).
var ErrNothingToRevert = errors.New("правила ASR не менялись этой программой: возвращать нечего")

// FixASR включает правила ASR в режиме блокировки (или с off возвращает прежние значения); прежние значения лежат
// в config.json для отката. Правила работают только при включённом Defender, поэтому при отключённом включать нечего.
func FixASR(off bool) error {
	if !isolation.IsElevated() {
		return errors.New("нужен запуск от администратора")
	}
	cfg, err := LoadConfig()
	if err != nil {
		return errors.New("SessionVault не установлен")
	}
	if off {
		if cfg.ASR == nil {
			return ErrNothingToRevert
		}
		if err := asr.Revert(cfg.ASR); err != nil {
			return err
		}
		return UpdateConfig(func(c *Config) { c.ASR = nil })
	}
	if checkup.DefenderOff() {
		return errors.New("защитник Windows (Defender) отключён: правила ASR без него не работают")
	}
	st, err := asr.Apply(cfg.ASR)
	// Состояние сохраняется и при ошибке: уже записанные значения должны откатываться.
	if e := UpdateConfig(func(c *Config) { c.ASR = st }); e != nil && err == nil {
		err = e
	}
	return err
}
