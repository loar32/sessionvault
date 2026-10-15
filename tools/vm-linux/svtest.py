#!/usr/bin/python3
# Тестовое приложение для автотеста SessionVault: добавляется командой add и изнутри песочницы проверяет то, что ей
# разрешено и запрещено. Итоги пишет в ~/.config/svtest/result (в доме приложения), тест читает их через sudo.
import os
import subprocess
import sys

from gi.repository import Gio, GLib

home = os.path.expanduser("~/.config/svtest")
os.makedirs(home, exist_ok=True)
results = []


def put(name, ok, detail=""):
    results.append(f"{name}={'ok' if ok else 'no'} {detail}".strip())
    with open(os.path.join(home, "result"), "w") as f:
        f.write("\n".join(results) + "\n")


with open(os.path.join(home, "state"), "a") as f:
    f.write("запуск\n")
put("argv", True, " ".join(sys.argv[1:]))

bus = None
try:
    bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    put("bus", True)
except GLib.Error as e:
    put("bus", False, e.message)


def call(dest, path, iface, method, args, reply=None):
    return bus.call_sync(dest, path, iface, method, args, reply, Gio.DBusCallFlags.NONE, 5000, None)


if bus:
    try:
        r = call("org.freedesktop.Notifications", "/org/freedesktop/Notifications", "org.freedesktop.Notifications", "Notify",
                 GLib.Variant("(susssasa{sv}i)", ("svtest", 0, "", "svtest", "уведомление из песочницы", [], {}, 3000)))
        put("notify", True, str(r.unpack()[0]))
    except GLib.Error as e:
        put("notify", False, e.message)

    # Значок в трее: имя с pid процесса (его разрешает фильтр шины), объект и регистрация у StatusNotifierWatcher.
    sni = f"org.kde.StatusNotifierItem-{os.getpid()}-1"
    xml = """<node><interface name="org.kde.StatusNotifierItem">
      <property name="Category" type="s" access="read"/><property name="Id" type="s" access="read"/>
      <property name="Title" type="s" access="read"/><property name="Status" type="s" access="read"/>
      <property name="IconName" type="s" access="read"/><method name="Activate"><arg type="i" direction="in"/>
      <arg type="i" direction="in"/></method></interface></node>"""
    props = {"Category": "ApplicationStatus", "Id": "svtest", "Title": "svtest", "Status": "Active", "IconName": "security-high"}

    def get_prop(conn, sender, path, iface, name):
        return GLib.Variant("s", props[name])

    def method(conn, sender, path, iface, name, params, inv):
        with open(os.path.join(home, "activated"), "w") as f:
            f.write("1\n")
        inv.return_value(None)

    try:
        info = Gio.DBusNodeInfo.new_for_xml(xml)
        bus.register_object("/StatusNotifierItem", info.interfaces[0], method, get_prop, None)
        r = call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "RequestName",
                 GLib.Variant("(su)", (sni, 4)), GLib.VariantType("(u)"))
        if r.unpack()[0] != 1:
            raise GLib.Error(f"RequestName {r.unpack()[0]}")
        call("org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher", "org.kde.StatusNotifierWatcher",
             "RegisterStatusNotifierItem", GLib.Variant("(s)", (sni,)))
        put("tray", True, sni)
    except GLib.Error as e:
        put("tray", False, f"{sni} {e.message}")

    try:
        call("org.freedesktop.secrets", "/org/freedesktop/secrets", "org.freedesktop.DBus.Peer", "Ping", None)
        put("secrets", True)
    except GLib.Error as e:
        put("secrets", False, e.message)

    # Запрещено: выбор файла через портал, чужие службы сеанса, владение чужим именем.
    for name, dest, path, iface, meth, args in [
        ("filechooser", "org.freedesktop.portal.Desktop", "/org/freedesktop/portal/desktop", "org.freedesktop.DBus.Properties", "Get",
         GLib.Variant("(ss)", ("org.freedesktop.portal.FileChooser", "version"))),
        ("systemd", "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.DBus.Peer", "Ping", None),
        ("own", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "RequestName", GLib.Variant("(su)", ("org.example.Evil", 4))),
    ]:
        try:
            r = call(dest, path, iface, meth, args)
            put("denied-" + name, name == "own" and r.unpack()[0] != 1, str(r.unpack()))
        except GLib.Error as e:
            put("denied-" + name, True, e.message.split(":")[0])

    try:
        r = call("org.freedesktop.portal.Desktop", "/org/freedesktop/portal/desktop", "org.freedesktop.portal.Settings", "ReadOne",
                 GLib.Variant("(ss)", ("org.freedesktop.appearance", "color-scheme")))
        put("portal-settings", True)
    except GLib.Error as e:
        put("portal-settings", False, e.message)

    # Показ экрана: сессия портала ScreenCast (дальше портал показал бы выбор экрана человеку).
    try:
        token = "svtest1"
        req = "/org/freedesktop/portal/desktop/request/%s/%s" % (bus.get_unique_name()[1:].replace(".", "_"), token)
        loop = GLib.MainLoop()
        got = {}

        def on_response(conn, sender, path, iface, signal, params):
            got["code"] = params.unpack()[0]
            loop.quit()

        bus.signal_subscribe("org.freedesktop.portal.Desktop", "org.freedesktop.portal.Request", "Response", req, None,
                             Gio.DBusSignalFlags.NONE, on_response)
        call("org.freedesktop.portal.Desktop", "/org/freedesktop/portal/desktop", "org.freedesktop.portal.ScreenCast",
             "CreateSession", GLib.Variant("(a{sv})", ({"handle_token": GLib.Variant("s", token),
                                                         "session_handle_token": GLib.Variant("s", "svs1")},)))
        GLib.timeout_add(8000, loop.quit)
        loop.run()
        put("screencast", got.get("code") == 0, str(got))
    except GLib.Error as e:
        put("screencast", False, e.message)

dev = "/dev/video0"
try:
    os.close(os.open(dev, os.O_RDWR))
    put("camera", True)
except OSError as e:
    put("camera", False, str(e))

p = subprocess.run(["pactl", "list", "short", "sources"], capture_output=True, text=True)
put("mic", p.returncode == 0 and p.stdout.strip() != "", p.stdout.strip().replace("\n", " | ")[:200])

# Открытая приложению папка (sessionvault share): видно содержимое владельца, можно писать.
pics = os.path.expanduser("~/Pictures")
if os.path.isdir(pics):
    try:
        names = sorted(os.listdir(pics))
        with open(os.path.join(pics, "from-svtest.txt"), "w") as f:
            f.write("svtest\n")
        put("share", True, ",".join(names)[:100])
    except OSError as e:
        put("share", False, str(e))

# Новая папка данных после первого запуска: SessionVault находит её по имени и ставит приманку у владельца.
new = os.path.expanduser("~/.local/share/svtest-new")
os.makedirs(new, exist_ok=True)
with open(os.path.join(new, "data"), "w") as f:
    f.write("новые данные\n")

# Автозапуск, включённый внутри песочницы, SessionVault переносит владельцу через себя.
if os.path.exists(os.path.expanduser("~/Downloads/svtest-autostart")):
    os.makedirs(os.path.expanduser("~/.config/autostart"), exist_ok=True)
    with open(os.path.expanduser("~/.config/autostart/svtest.desktop"), "w") as f:
        f.write("[Desktop Entry]\nType=Application\nName=svtest\nExec=svtest\n")

# Ссылки и файлы из песочницы: что открыть, тест кладёт в общую папку (в песочнице это ~/Downloads).
link_file = os.path.expanduser("~/Downloads/svtest-link")
if os.path.exists(link_file):
    for i, link in enumerate(open(link_file).read().split()):
        p = subprocess.run(["xdg-open", link])
        put(f"xdg-open{i}", p.returncode == 0, link)
        GLib.usleep(800000)

GLib.MainLoop().run()
