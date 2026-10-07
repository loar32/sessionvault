package service

import (
	"errors"
	"github.com/loar32/sessionvault/internal/i18n"

	"github.com/loar32/sessionvault/internal/hardening"
	"github.com/loar32/sessionvault/internal/isolation"
)

// Harden включает (или с off выключает) тихие системные меры; прежние значения лежат в config.json для отката.
func Harden(off bool) error {
	if !isolation.IsElevated() {
		return errors.New(i18n.T("нужен запуск от администратора"))
	}
	cfg, err := LoadConfig()
	if err != nil {
		return errors.New(i18n.T("SessionVault не установлен"))
	}
	if off {
		if err := hardening.Revert(cfg.Hardening); err != nil {
			return err
		}
		return UpdateConfig(func(c *Config) { c.Hardening = nil })
	}
	st, err := hardening.Apply(cfg.Hardening)
	// Состояние сохраняется и при ошибке: уже применённые меры должны откатываться.
	if e := UpdateConfig(func(c *Config) { c.Hardening = st }); e != nil && err == nil {
		err = e
	}
	return err
}
