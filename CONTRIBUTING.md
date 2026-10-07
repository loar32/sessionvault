# Как внести вклад / Contributing

## Русский

Спасибо за интерес. Принципы проекта (из них не выходим):

- **Ноль сети.** В коде нет сетевых вызовов; не добавляйте `net/http`, `crypto/tls` и зависимости, которые их тянут. CI это проверяет.
- **Фон тихий.** Новая функция работает по событию или по запросу, не по таймеру; без окон и баллонов, кроме тревоги и ошибок, которые вызвал сам пользователь.
- **Просто.** Прямой код без абстракций «на будущее». Комментарии только про неочевидное «почему».
- **Проверки безопасности не ослабляем** ради удобства.

Как работать:

1. Форк и ветка от `main`; одна тема на pull request.
2. Сборка и проверки (нужны Go 1.27 и Windows): `go build ./...`, `gofmt -l .` (пусто), `go vet ./...`, `golangci-lint run`, `go test ./...`.
3. Новые строки интерфейса оборачивайте в `i18n.T("русский текст")` и добавляйте английский перевод в `internal/i18n/en*.go`; `go test ./internal/i18n` проверяет, что переводы есть и не устарели.
4. Изменения, которые касаются прав, службы или хранилища, проверяются в Hyper-V ВМ: `tools/vm/run-test.ps1` и `tools/vm/run-installer-test.ps1` (описание — в README). Если ВМ нет, напишите об этом в pull request, мы прогоним сами.
5. Обновите README и CHANGELOG, если меняется поведение.

Об уязвимостях сообщайте приватно: [SECURITY.md](SECURITY.md).

## English

Thanks for your interest. The project principles (we do not bend them):

- **Zero network.** The code has no network calls; do not add `net/http`, `crypto/tls` or dependencies that pull them in. CI checks this.
- **A quiet background.** A new feature runs on an event or on request, not on a timer; no windows or balloons except the alarm and errors the user caused.
- **Simple.** Direct code, no abstractions "for the future". Comments only for the non-obvious "why".
- **Security checks are never weakened** for convenience.

How to work:

1. Fork and branch from `main`; one topic per pull request.
2. Build and checks (Go 1.27 and Windows required): `go build ./...`, `gofmt -l .` (empty), `go vet ./...`, `golangci-lint run`, `go test ./...`.
3. Wrap new UI strings in `i18n.T("русский текст")` (Russian is the source language) and add the English translation in `internal/i18n/en*.go`; `go test ./internal/i18n` checks that translations exist and are not stale.
4. Changes that touch permissions, the service or the vault are verified in a Hyper-V VM: `tools/vm/run-test.ps1` and `tools/vm/run-installer-test.ps1` (see the README). If you have no VM, say so in the pull request and we will run it.
5. Update the README and the CHANGELOG when behaviour changes.

Report vulnerabilities privately: [SECURITY.md](SECURITY.md).
