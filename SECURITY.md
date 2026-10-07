# Политика безопасности / Security policy

## Русский

Нашли уязвимость или способ обойти защиту SessionVault? Пожалуйста, **не открывайте публичный issue**. Сообщите приватно: вкладка Security → **Report a vulnerability** в этом репозитории (приватный отчёт GitHub).

В отчёте полезно указать: версию SessionVault, версию Windows, что именно удалось (прочитать данные, обойти приманку, получить ключ, повысить права), шаги воспроизведения. Рабочий код стилеров не присылайте: достаточно описания и минимального примера.

Что считается уязвимостью: чтение защищённых данных из обычной учётки без пароля; обход приманки или блокировки хранилища; выход приложения под `sv-<имя>` к данным соседа; запуск файла из запрещённых мест; вынос данных системными утилитами через заслон; подмена профиля. Что не считается: то, что описано в README в разделе «Границы защиты» и в [модели угроз](docs/THREAT_MODEL.md) (администратор, драйвер ядра, ClickFix, управление запущенным приложением).

Отвечаем в течение недели, исправление и благодарность в CHANGELOG (если не попросите иначе). Поддерживается последняя версия.

## English

Found a vulnerability or a way around SessionVault's protection? Please **do not open a public issue**. Report it privately: the Security tab → **Report a vulnerability** in this repository (GitHub private report).

Useful details: the SessionVault version, the Windows version, what you achieved (read data, bypass the decoy, obtain a key, escalate), and reproduction steps. Please do not send working stealer code; a description and a minimal example are enough.

In scope: reading protected data from a regular account without the password; bypassing the decoy or the vault lock; an app under `sv-<name>` reaching a neighbour's data; running a file from a forbidden location; exfiltrating data with system utilities through the barrier; profile tampering. Out of scope: what the README describes under "Границы защиты" (limits) and the [threat model](docs/THREAT_MODEL.en.md) (administrator, kernel driver, ClickFix, driving a running app).

We reply within a week, fix it and credit you in the CHANGELOG (unless you prefer otherwise). The latest version is supported.
