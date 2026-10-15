#!/bin/bash
# Внутри ВМ: тестовые приложения так, как их раскладывают пакеты Arch/AUR (/opt + ссылка в /usr/bin, ярлык в
# /usr/share/applications), помощник для команд в графическом сеансе и выключенная блокировка по бездействию.
set -euo pipefail
cd /tmp

sudo mkdir -p /opt/telegram
sudo tar -xJf telegram.tar.xz -C /opt/telegram --strip-components=1
sudo ln -sf /opt/telegram/Telegram /usr/bin/telegram-desktop

# Discord как в пакете Arch (1.0.x): /usr/bin/discord — загрузчик, клиент он скачивает в ~/.config/discord при первом запуске.
mkdir -p /tmp/dsc && tar -xzf discord.tar.gz -C /tmp/dsc
sudo install -Dm755 /tmp/dsc/Discord/discord /usr/bin/discord
sudo install -Dm755 /tmp/dsc/Discord/updater_bootstrap /usr/share/discord/updater_bootstrap
sudo install -Dm644 /tmp/dsc/Discord/discord.desktop /usr/share/applications/discord.desktop

sudo mkdir -p /opt/brave-bin
sudo bsdtar -xf brave.zip -C /opt/brave-bin
sudo ln -sf /opt/brave-bin/brave /usr/bin/brave
printf '[Desktop Entry]\nType=Application\nName=Brave Web Browser\nExec=/usr/bin/brave %%U\nIcon=brave-browser\nCategories=Network;WebBrowser;\n' | sudo tee /usr/share/applications/brave-browser.desktop >/dev/null

# .deb распаковывается в отдельный каталог: его корневые записи затёрли бы права системных каталогов.
rm -rf /tmp/chr && mkdir -p /tmp/chr && cd /tmp/chr
bsdtar -xf ../chrome.deb
mkdir data && tar -xf data.tar.xz -C data
sudo cp -a data/opt/google /opt/
sudo ln -sf /opt/google/chrome/google-chrome /usr/bin/google-chrome-stable
sudo cp data/usr/share/applications/google-chrome.desktop /usr/share/applications/
cd /tmp

sudo chown -R root:root /opt/telegram /opt/brave-bin /opt/google
sudo chmod -R go-w /opt/telegram /opt/brave-bin /opt/google

mkdir -p ~/bin
cat > ~/bin/sess <<'EOF'
#!/bin/bash
# Команда в окружении графического сеанса (для тестов по ssh)
while IFS= read -r line; do
  case "$line" in
    WAYLAND_DISPLAY=*|DISPLAY=*|HYPRLAND_INSTANCE_SIGNATURE=*|OMARCHY_PATH=*|XDG_*=*|DBUS_SESSION_BUS_ADDRESS=*|PATH=*|LANG=*|ELECTRON_*=*|QT_*=*|GDK_*=*) export "$line" ;;
  esac
done < <(systemctl --user show-environment)
exec "$@"
EOF
chmod +x ~/bin/sess
~/bin/sess omarchy-toggle-idle >/dev/null 2>&1 || true
ls -la /usr/bin/telegram-desktop /usr/bin/discord /usr/share/discord/updater_bootstrap /usr/bin/brave /usr/bin/google-chrome-stable /usr/bin/chromium
