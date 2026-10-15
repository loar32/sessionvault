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
check "Chromium со связкой ключей владельца (настройка Omarchy)" bash -c "pgrep -u sv-chromium -af /usr/lib/chromium/chromium | grep -q password-store=gnome-libsecret"
check "ключ куки Chromium из связки владельца, новый не создан" bash -c "[ \"$($S secret-tool search --all application chromium 2>/dev/null | grep -c '^label')\" = 1 ]"
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

section "9. Своё приложение (add): шина, трей, камера, звук, ссылки, открытые папки"
sudo modprobe vivid >/dev/null 2>&1
mkdir -p ~/apps/svtest ~/.config/svtest ~/Pictures
cp /tmp/svtest.py ~/apps/svtest/svtest && chmod +x ~/apps/svtest/svtest
echo "старые данные" > ~/.config/svtest/state
echo "картинка владельца" > ~/Pictures/owner.png
printf '%s\n' "[Desktop Entry]" "Type=Application" "Name=SVTest" "Exec=/home/tester/apps/svtest/svtest %U" "MimeType=x-scheme-handler/svtest;" "Icon=security-high" > ~/.local/share/applications/svtest.desktop
check "add svtest.desktop" bash -c "echo '$PW' | sudo $SV add -yes -password-stdin svtest.desktop"
check "описание добавленного приложения" sudo test -f $VAULT/apps/svtest/app.json
check "программа скопирована и принадлежит root" bash -c "[ \"\$(sudo stat -c %U $VAULT/apps/svtest/app/svtest)\" = root ]"
checknot "владелец не может изменить копию программы" bash -c "echo x >> $VAULT/apps/svtest/app/svtest"
check "данные приложения в хранилище" sudo test -f $VAULT/apps/svtest/data.enc
check "на месте данных приманка" bash -c "[ ! -e ~/.config/svtest/state ] && [ -f ~/.config/svtest/config.json ]"
check "свой ярлык переписан на SessionVault" grep -q "^Exec=/usr/local/bin/sessionvault-svtest %U" ~/.local/share/applications/svtest.desktop
check "share ~/Pictures" sudo $SV share svtest ~/Pictures
echo "https://example.com/from-svtest" > ~/SessionVault/svtest-link
touch ~/SessionVault/svtest-autostart
check "запуск svtest из ярлыка" bash -c "echo '$PW' | $S $SV unlock svtest"
R=$VAULT/apps/svtest/home/.config/svtest/result
check "svtest отработал" waitfor 30 sudo grep -q "^xdg-open0=" $R
res() { sudo grep -q "^$1=ok" $R; }
check "шина сеанса в песочнице" res bus
check "уведомление дошло до Quickshell" res notify
check "значок в трее зарегистрирован" res tray
check "значок виден на шине владельца" bash -c "XDG_RUNTIME_DIR=/run/user/1000 busctl --user list --no-pager | grep -q StatusNotifierItem"
check "связка ключей доступна" res secrets
check "выбор файла через портал закрыт" res denied-filechooser
check "чужие службы шины закрыты" res denied-systemd
check "чужое имя на шине не занять" res denied-own
check "портал: настройки оформления" res portal-settings
check "портал: показ экрана (сессия ScreenCast)" res screencast
check "камера (vivid) открывается" res camera
check "микрофон: источники PipeWire видны" res mic
check "открытая папка видна и доступна на запись" res share
check "файл приложения в открытой папке виден владельцу" cat ~/Pictures/from-svtest.txt
check "xdg-open из песочницы принят" res xdg-open0
check "ссылка из песочницы открыта защищённым Chromium" waitfor 20 bash -c "$S hyprctl clients -j | grep -q 'example.com'"
checknot "у владельца нет своего Chromium" pgrep -u tester -x chromium
check "данные расшифрованы в дом приложения" sudo grep -q "старые данные" $VAULT/apps/svtest/home/.config/svtest/state
$SV close svtest
check "svtest закрыт и зашифрован" waitfor 30 bash -c "! sudo test -e $VAULT/apps/svtest/home"
check "новая папка данных получила приманку" bash -c "[ -f ~/.local/share/svtest-new/config.json ] && sudo grep -q svtest-new $VAULT/apps/svtest/app.json"
check "автозапуск из песочницы перенесён через SessionVault" grep -q "sessionvault-svtest" ~/.config/autostart/sessionvault-svtest.desktop
rm -f ~/SessionVault/svtest-autostart ~/SessionVault/svtest-link
echo "# изменено" >> ~/apps/svtest/svtest
checknot "изменённый оригинал не попадает в копию" sudo grep -q "# изменено" $VAULT/apps/svtest/app/svtest
check "refresh" sudo $SV refresh svtest
check "после refresh копия обновлена" sudo grep -q "# изменено" $VAULT/apps/svtest/app/svtest
check "unshare ~/Pictures" sudo $SV unshare svtest ~/Pictures
cat ~/.config/svtest/session >/dev/null 2>&1
check "тревога по приманке своего приложения" waitfor 10 is_alarm
sudo systemctl restart sessionvault
waitfor 10 is_locked

section "10. AppImage из домашней папки"
rm -rf /tmp/AppDir && mkdir -p /tmp/AppDir/usr/bin ~/Applications ~/.config/SVImg
printf '%s\n' '#!/usr/bin/python3' 'import os' 'from gi.repository import GLib' 'd = os.path.expanduser("~/.config/SVImg")' 'os.makedirs(d, exist_ok=True)' 'open(os.path.join(d, "state"), "a").write("appimage\n")' 'GLib.MainLoop().run()' > /tmp/AppDir/usr/bin/svimg
printf '%s\n' '#!/bin/sh' 'HERE=$(dirname "$(readlink -f "$0")")' 'exec "$HERE/usr/bin/svimg" "$@"' > /tmp/AppDir/AppRun
chmod +x /tmp/AppDir/usr/bin/svimg /tmp/AppDir/AppRun
printf '%s\n' "[Desktop Entry]" "Type=Application" "Name=SVImg" "Exec=svimg %U" "Icon=svimg" "Categories=Utility;" "MimeType=x-scheme-handler/svimg;" > /tmp/AppDir/svimg.desktop
cp "$(find /usr/share/icons -name '*.png' -size +1k | head -1)" /tmp/AppDir/svimg.png
chmod +x /tmp/appimagetool-x86_64.AppImage
(cd /tmp && ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1 ./appimagetool-x86_64.AppImage --runtime-file runtime-x86_64 AppDir ~/Applications/SVImg-1.0.0-x86_64.AppImage >/dev/null 2>&1)
check "тестовый AppImage собран" test -x ~/Applications/SVImg-1.0.0-x86_64.AppImage
echo "старое" > ~/.config/SVImg/state
check "add AppImage" bash -c "cd ~/Applications && echo '$PW' | sudo $SV add -yes -password-stdin SVImg-1.0.0-x86_64.AppImage"
check "AppImage распакован в копию root" bash -c "[ \"\$(sudo stat -c %U $VAULT/apps/svimg/app/AppRun)\" = root ]"
check "ярлык AppImage со значком и схемой ссылок" bash -c "grep -q 'MimeType=x-scheme-handler/svimg;' ~/.local/share/applications/sessionvault-svimg.desktop && grep -q '^Icon=$VAULT/apps/svimg/app/' ~/.local/share/applications/sessionvault-svimg.desktop"
check "AppImage запущен в песочнице" bash -c "echo '$PW' | $S $SV unlock svimg"
check "AppImage пишет свои данные" waitfor 20 sudo grep -q appimage $VAULT/apps/svimg/home/.config/SVImg/state

section "11. Данные больше 1 ГиБ"
sudo dd if=/dev/urandom of=$VAULT/apps/svimg/home/.config/SVImg/big.bin bs=1M count=1100 status=none
sudo chown sv-svimg: $VAULT/apps/svimg/home/.config/SVImg/big.bin
BIG=$(sudo sha256sum $VAULT/apps/svimg/home/.config/SVImg/big.bin | cut -d' ' -f1)
$SV close svimg
check "1,1 ГиБ зашифрованы" waitfor 120 bash -c "! sudo test -e $VAULT/apps/svimg/home"
check "data.enc больше 1 ГиБ" bash -c "[ \$(sudo stat -c %s $VAULT/apps/svimg/data.enc) -gt 1100000000 ]"
check "служба не держала данные в памяти" bash -c "[ \$(sudo awk '/VmHWM/ {print \$2}' /proc/\$(systemctl show -p MainPID --value sessionvault)/status) -lt 800000 ]"
check "повторный запуск" bash -c "echo '$PW' | $S $SV unlock svimg"
check "1,1 ГиБ расшифрованы без потерь" waitfor 120 bash -c "[ \"\$(sudo sha256sum $VAULT/apps/svimg/home/.config/SVImg/big.bin 2>/dev/null | cut -d' ' -f1)\" = $BIG ]"
$SV close svimg
waitfor 120 bash -c "! sudo test -e $VAULT/apps/svimg/home"

section "12. Ключ восстановления"
PW2='New-Password-456'
printf '%s\n' "$PW" "$PW" "$PW" "$PW" "$PW" | sudo $SV recovery create -password-stdin > /tmp/rc.txt 2>&1
WORDS=$(tail -1 /tmp/rc.txt)
check "recovery create: 24 слова" bash -c "[ \$(echo '$WORDS' | wc -w) = 24 ]"
check "recovery status: открывает все" bash -c "sudo $SV recovery status | grep -q -e 'opens' -e 'открывает'"
check "recovery verify" bash -c "echo '$WORDS' | sudo $SV recovery verify -password-stdin"
checknot "verify с чужими словами" bash -c "echo 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art' | sudo $SV recovery verify -password-stdin"
$SV lock
check "вход словами вместо пароля" bash -c "echo '$WORDS' | $S $SV unlock svtest"
check "svtest запущен по словам" waitfor 20 pgrep -u sv-svtest
$SV close svtest
waitfor 30 bash -c "! sudo test -e $VAULT/apps/svtest/home"
check "recovery reset: новый пароль" bash -c "printf '%s\n%s\n' '$WORDS' '$PW2' | sudo $SV recovery reset -password-stdin"
$SV lock
checknot "старый пароль больше не подходит" bash -c "echo '$PW' | $S $SV unlock svimg"
check "новый пароль подходит" bash -c "echo '$PW2' | $S $SV unlock svimg"
$SV close svimg
waitfor 60 bash -c "! sudo test -e $VAULT/apps/svimg/home"
PW=$PW2

section "13. Перенос: export → unprotect → import"
rm -rf /tmp/exp && mkdir /tmp/exp
check "export svtest" sudo $SV export svtest /tmp/exp/svtest.svx
check "файл переноса отдан владельцу" bash -c "[ \"\$(stat -c %U /tmp/exp/svtest.svx)\" = tester ]"
checknot "в файле переноса нет открытых данных" grep -q "старые данные" /tmp/exp/svtest.svx
check "unprotect svtest" bash -c "echo '$PW' | sudo $SV unprotect -password-stdin svtest"
check "данные svtest вернулись" grep -q "старые данные" ~/.config/svtest/state
check "ярлык svtest вернулся прежним" grep -q "^Exec=/home/tester/apps/svtest/svtest %U" ~/.local/share/applications/svtest.desktop
checknot "автозапуск SessionVault убран" test -e ~/.config/autostart/sessionvault-svtest.desktop
checknot "учётка sv-svtest удалена" id sv-svtest
checknot "копия программы удалена" sudo test -e $VAULT/apps/svtest
rm -rf ~/.config/svtest ~/.local/share/svtest-new
echo '{"App":"telegram"}' > /tmp/exp/win.svx
checknot "файл Windows-версии отвергается" bash -c "echo '$PW' | sudo $SV import -password-stdin /tmp/exp/win.svx"
check "import svtest" bash -c "echo '$PW' | sudo $SV import -yes -password-stdin /tmp/exp/svtest.svx"
check "после импорта на месте данных приманка" test -f ~/.config/svtest/config.json
check "импортированное запускается" bash -c "echo '$PW' | $S $SV unlock svtest"
check "данные после переноса целы" waitfor 20 sudo grep -q "старые данные" $VAULT/apps/svtest/home/.config/svtest/state
$SV close svtest
waitfor 30 bash -c "! sudo test -e $VAULT/apps/svtest/home"

section "14. Проверка системы"
check "check отвечает" bash -c "$SV check > /tmp/check.txt"
check "check видит sudo без пароля стенда" grep -q "sudo: " /tmp/check.txt
check "check видит приманки" grep -q -e "Decoys: watched" -e "Приманки: под наблюдением" /tmp/check.txt
check "check видит ключ восстановления" grep -q -e "Recovery key: opens all" -e "Ключ восстановления: открывает все" /tmp/check.txt

section "7. Снятие защиты"
$SV lock
check "unprotect telegram" bash -c "echo '$PW' | sudo $SV unprotect -password-stdin telegram"
check "данные вернулись" grep -q SECRET-TG-FILE ~/.local/share/TelegramDesktop/sv-secret.txt
check "данные принадлежат владельцу" bash -c "[ \"\$(stat -c %U ~/.local/share/TelegramDesktop/sv-secret.txt)\" = tester ]"
checknot "учётка удалена" id sv-telegram
checknot "ярлык убран" test -e ~/.local/share/applications/org.telegram.desktop.desktop
checknot "команда-ярлык убрана" test -e /usr/local/bin/sessionvault-telegram

section "8. Удаление"
check "uninstall" bash -c "printf '%s\n' '$PW' '$PW' '$PW' '$PW' '$PW' '$PW' | sudo $SV uninstall"
checknot "служба убрана" systemctl is-active sessionvault
checknot "бинарник убран" test -e $SV
check "профиль Chromium вернулся" test -d ~/.config/chromium/Default
checknot "учётка sv-chromium удалена" id sv-chromium
checknot "ярлык chromium убран" test -e ~/.local/share/applications/chromium.desktop
checknot "ссылка ~/SessionVault убрана" test -L ~/SessionVault
check "данные AppImage вернулись" grep -q appimage ~/.config/SVImg/state
check "данные svtest вернулись" grep -q "старые данные" ~/.config/svtest/state
checknot "ярлык AppImage убран" test -e ~/.local/share/applications/sessionvault-svimg.desktop
checknot "учётки добавленных приложений удалены" bash -c "id sv-svimg || id sv-svtest"

echo
echo "ИТОГ: провалов $fails"
exit $fails
