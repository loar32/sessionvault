#!/bin/bash
# Автотест SessionVault в Omarchy (внутри ВМ, от tester с sudo без пароля). Каждая проверка печатает «  ok ...» или
# «  FAIL ...»; итог — число провалов в коде выхода. Бинарник ждёт в /tmp/sessionvault.
set -u
PW='Test-Password-123'
BIN=/tmp/sessionvault
SV=/usr/local/bin/sessionvault
S=~/bin/sess
VAULT=/var/lib/sessionvault
fails=0
ok()   { echo "  ok   $*"; }
fail() { echo "  FAIL $*"; fails=$((fails+1)); }
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else fail "$name"; fi; }
checknot() { local name=$1; shift; if "$@" >/dev/null 2>&1; then fail "$name"; else ok "$name"; fi; }
waitfor() { local n=$1; shift; for _ in $(seq "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
state() { $SV status 2>/dev/null | head -1 | sed 's/^[^:]*: //'; }
is_locked() { case "$(state)" in locked|заблокировано) return 0;; esac; return 1; }
is_unlocked() { case "$(state)" in unlocked|разблокировано) return 0;; esac; return 1; }
is_alarm() { state | grep -q -e ALARM -e ТРЕВОГА; }
is_running() { $SV status 2>/dev/null | sed -n 3p | grep -q "$1"; }
section() { echo; echo "== $*"; }

section "1. Установка"
check "install" sudo $BIN install
check "служба активна" systemctl is-active sessionvault
check "сокет есть" waitfor 5 test -S /run/sessionvault/sock
check "ярлык меню" grep -q X-SessionVault ~/.local/share/applications/sessionvault.desktop
check "ссылка ~/SessionVault" test -L ~/SessionVault
check "status отвечает" $SV status
check "заперто после установки" is_locked
check "lock без ключей не ломается" $SV lock
checknot "чужая команда отклоняется" bash -c "printf 'rm -rf /\n' | timeout 3 socat - UNIX-CONNECT:/run/sessionvault/sock | grep -q ok"

section "2. Защита Telegram"
mkdir -p ~/.local/share/TelegramDesktop/tdata/D877F783D5D3EF8C
echo "SECRET-TG-KEY" > ~/.local/share/TelegramDesktop/tdata/key_datas
echo "SECRET-TG-MAP" > ~/.local/share/TelegramDesktop/tdata/D877F783D5D3EF8C/maps
echo "SECRET-TG-FILE" > ~/.local/share/TelegramDesktop/sv-secret.txt
checknot "короткий пароль отклонён" bash -c "echo short | sudo $SV protect -yes -password-stdin telegram"
check "protect telegram" bash -c "echo '$PW' | sudo $SV protect -yes -password-stdin telegram"
check "хранилище создано" sudo test -f $VAULT/apps/telegram/data.enc
checknot "в data.enc нет открытого текста" sudo grep -q SECRET-TG $VAULT/apps/telegram/data.enc
checknot "открытого дома нет" sudo test -e $VAULT/apps/telegram/home
# Приманку нельзя читать даже тестом: это тревога. Проверка — по именам и размерам.
check "на старом месте нет настоящих данных" bash -c "[ ! -e ~/.local/share/TelegramDesktop/sv-secret.txt ] && [ $(stat -c %s ~/.local/share/TelegramDesktop/tdata/key_datas) -ne 14 ]"
check "на старом месте приманка" test -f ~/.local/share/TelegramDesktop/tdata/key_datas
check "учётка sv-telegram" id sv-telegram
check "ярлык подменён" grep -q "sessionvault-telegram" ~/.local/share/applications/org.telegram.desktop.desktop
check "команда-ярлык" test -L /usr/local/bin/sessionvault-telegram
checknot "повторная защита отклонена" bash -c "echo '$PW' | sudo $SV protect -yes -password-stdin telegram"
checknot "владелец не читает vault.json" cat $VAULT/apps/telegram/vault.json
check "заперто" is_locked

section "3. Разблокировка и запуск"
checknot "неверный пароль не открывает" bash -c "echo 'wrong-password-1' | $S $SV unlock telegram"
check "unlock + запуск" bash -c "echo '$PW' | $S $SV unlock telegram"
check "Telegram запущен под sv-telegram" waitfor 15 pgrep -u sv-telegram -f "^/usr/bin/telegram-desktop"
check "status: разблокировано" is_unlocked
check "status: запущен telegram" is_running telegram
TGPID=$(pgrep -u sv-telegram -f "^/usr/bin/telegram-desktop" | head -1)
check "данные расшифрованы в дом приложения" sudo grep -q SECRET-TG-FILE $VAULT/apps/telegram/home/.local/share/TelegramDesktop/sv-secret.txt
check "дом принадлежит sv-telegram и закрыт" bash -c "[ \"\$(sudo stat -c '%U %a' $VAULT/apps/telegram/home)\" = 'sv-telegram 700' ]"
checknot "владелец не читает расшифрованные данные" cat $VAULT/apps/telegram/home/.local/share/TelegramDesktop/sv-secret.txt
checknot "владелец не читает память Telegram" head -c1 /proc/$TGPID/mem
checknot "владелец не читает окружение Telegram" cat /proc/$TGPID/environ
check "в песочнице дом — данные приложения" sudo test -f /proc/$TGPID/root/home/tester/.local/share/TelegramDesktop/sv-secret.txt
checknot "в песочнице не виден настоящий дом" sudo test -e /proc/$TGPID/root/home/tester/.ssh
check "в песочнице «Загрузки» — общая папка" sudo test -d /proc/$TGPID/root/home/tester/Downloads
checknot "в песочнице нет системного /home других" sudo test -e /proc/$TGPID/root/root/.bashrc
touch ~/SessionVault/from-owner.txt
check "общая папка видна приложению" sudo test -f /proc/$TGPID/root/home/tester/Downloads/from-owner.txt
check "ACL на сокет Wayland выдан" bash -c "getfacl -p /run/user/1000/wayland-1 2>/dev/null | grep -q 'user:sv-telegram:rw'"
check "повторный запуск передаётся работающему" $S /usr/local/bin/sessionvault-telegram
sleep 3
check "главный процесс Telegram тот же" bash -c "pgrep -u sv-telegram -f '^/usr/bin/telegram-desktop' | grep -qx $TGPID"

section "4. Приманка"
cat ~/.local/share/TelegramDesktop/tdata/settingss >/dev/null 2>&1
check "тревога: Telegram закрыт" waitfor 15 bash -c "! pgrep -u sv-telegram >/dev/null"
check "status: тревога" is_alarm
check "alerts: читатель /usr/bin/cat" bash -c "$SV alerts | grep -q '\"process\":\"/usr/bin/cat\"'"
check "alerts: uid владельца" bash -c "$SV alerts | grep -q '\"uid\":1000'"
check "данные зашифрованы после тревоги" waitfor 20 bash -c "! sudo test -e $VAULT/apps/telegram/home"
checknot "разблокировка во время тревоги отклонена" bash -c "echo '$PW' | $S $SV unlock telegram"
checknot "доступ к сокету Wayland отозван" bash -c "getfacl -p /run/user/1000/wayland-1 2>/dev/null | grep -q sv-telegram"
sudo systemctl restart sessionvault
check "после перезапуска службы заперто" waitfor 10 is_locked
# Метка стоит на inode: переименованная папка приманки не прячет чтение.
mv ~/.local/share/TelegramDesktop/tdata ~/.local/share/TelegramDesktop/tdata-moved
cat ~/.local/share/TelegramDesktop/tdata-moved/key_datas >/dev/null 2>&1
check "тревога и после переименования папки" waitfor 10 is_alarm
mv ~/.local/share/TelegramDesktop/tdata-moved ~/.local/share/TelegramDesktop/tdata
sudo systemctl restart sessionvault
waitfor 10 is_locked

section "5. Блокировка экрана и выход приложения"
check "unlock + запуск" bash -c "echo '$PW' | $S $SV unlock telegram"
check "Telegram запущен" waitfor 15 pgrep -u sv-telegram -f "^/usr/bin/telegram-desktop"
$S omarchy-system-lock >/dev/null 2>&1
sleep 2
check "при запущенном приложении ключ ждёт выхода" is_unlocked
$SV close telegram
check "после выхода приложения заперто" waitfor 20 is_locked
check "данные зашифрованы после выхода" waitfor 10 bash -c "! sudo test -e $VAULT/apps/telegram/home"
check "unlock без запуска приложения" bash -c "echo '$PW' | $S $SV unlock telegram"
$SV close telegram
waitfor 20 bash -c "! pgrep -u sv-telegram >/dev/null"
check "разблокировано, ничего не запущено" is_unlocked
$S omarchy-system-lock >/dev/null 2>&1
check "блокировка экрана сразу запирает" waitfor 5 is_locked

section "6. Браузер Chromium и веб-приложения"
$S chromium --headless --disable-gpu --dump-dom about:blank >/dev/null 2>&1 || true
check "у владельца есть профиль Chromium" test -d ~/.config/chromium
check "protect chromium" bash -c "echo '$PW' | sudo $SV protect -yes -password-stdin chromium"
check "ярлык chromium подменён" grep -q "^Exec=/usr/local/bin/sessionvault-chromium" ~/.local/share/applications/chromium.desktop
check "unlock chromium со ссылкой" bash -c "echo '$PW' | $S $SV unlock chromium https://example.com"
check "Chromium запущен под sv-chromium" waitfor 20 pgrep -u sv-chromium -f /usr/lib/chromium/chromium
check "Chromium без связки ключей" bash -c "pgrep -u sv-chromium -af /usr/lib/chromium/chromium | grep -q password-store=basic"
check "безопасные флаги Omarchy переданы" bash -c "pgrep -u sv-chromium -af /usr/lib/chromium/chromium | grep -q load-extension=/usr/share/omarchy"
echo "--remote-debugging-port=9222" >> ~/.config/chromium-flags.conf
$S omarchy-launch-webapp https://example.org >/dev/null 2>&1
sleep 6
check "веб-приложение открыто защищённым Chromium" bash -c "$S hyprctl clients -j | grep -q 'chrome-example.org'"
checknot "у владельца нет своего Chromium" pgrep -u tester -f /usr/lib/chromium/chromium
checknot "опасный флаг из файла флагов не передан" bash -c "pgrep -u sv-chromium -af chromium | grep -q remote-debugging"
$S xdg-open https://example.net >/dev/null 2>&1
sleep 5
check "ссылка открыта во вкладке защищённого браузера" bash -c "$S hyprctl clients -j | grep -q 'example.net'"
sed -i '/remote-debugging/d' ~/.config/chromium-flags.conf
$S /usr/bin/chromium --headless --disable-gpu --dump-dom about:blank >/dev/null 2>&1
sleep 2
checknot "сам Chromium, открывший свою приманку, не тревога" is_alarm
$SV close chromium
check "Chromium закрыт и зашифрован" waitfor 30 bash -c "! sudo test -e $VAULT/apps/chromium/home"


section "6b. Brave, Google Chrome, Discord"
# Клиент Discord загрузчик Arch скачивает в ~/.config/discord/Discord; в ВМ без сети его заменяет заглушка с окном.
mkdir -p ~/.config/discord
printf '#!/bin/sh\nexec foot --app-id=discord-fake --title=FakeDiscord sh -c "sleep 600"\n' > ~/.config/discord/Discord
chmod +x ~/.config/discord/Discord
echo '{"SKIP_HOST_UPDATE":true}' > ~/.config/discord/settings.json
# app: имя, начало командной строки главного процесса, часть класса или заголовка окна
for spec in "brave|^/usr/bin/brave|brave" "chrome|^/usr/bin/google-chrome-stable|chrome" "discord|app-id=discord-fake|discord"; do
  IFS='|' read -r app main class <<<"$spec"
  check "$app: protect" bash -c "echo '$PW' | sudo $SV protect -yes -password-stdin $app"
  check "$app: unlock + запуск" bash -c "echo '$PW' | $S $SV unlock $app"
  check "$app: запущен под sv-$app" waitfor 30 pgrep -u sv-$app -f "$main"
  check "$app: окно в сеансе" waitfor 30 bash -c "$S hyprctl clients -j | jq -r '.[] | .class + \" \" + .title' | grep -qi $class"
  checknot "$app: процессов под владельцем нет" pgrep -u tester -f "$main"
  $SV close $app
  check "$app: закрыт и зашифрован" waitfor 30 bash -c "! sudo test -e $VAULT/apps/$app/home"
  check "$app: unprotect" bash -c "echo '$PW' | sudo $SV unprotect -password-stdin $app"
  checknot "$app: учётка удалена" id sv-$app
done
check "discord: клиент вернулся владельцу" test -x ~/.config/discord/Discord
section "7. Снятие защиты"
$SV lock
check "unprotect telegram" bash -c "echo '$PW' | sudo $SV unprotect -password-stdin telegram"
check "данные вернулись" grep -q SECRET-TG-FILE ~/.local/share/TelegramDesktop/sv-secret.txt
check "данные принадлежат владельцу" bash -c "[ \"\$(stat -c %U ~/.local/share/TelegramDesktop/sv-secret.txt)\" = tester ]"
checknot "учётка удалена" id sv-telegram
checknot "ярлык убран" test -e ~/.local/share/applications/org.telegram.desktop.desktop
checknot "команда-ярлык убрана" test -e /usr/local/bin/sessionvault-telegram

section "8. Удаление"
check "uninstall" bash -c "echo '$PW' | sudo $SV uninstall"
checknot "служба убрана" systemctl is-active sessionvault
checknot "бинарник убран" test -e $SV
check "профиль Chromium вернулся" test -d ~/.config/chromium/Default
checknot "учётка sv-chromium удалена" id sv-chromium
checknot "ярлык chromium убран" test -e ~/.local/share/applications/chromium.desktop
checknot "ссылка ~/SessionVault убрана" test -L ~/SessionVault

echo
echo "ИТОГ: провалов $fails"
exit $fails
