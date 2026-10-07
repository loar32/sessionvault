# SessionVault

English · [Русский](README.md)

A quiet background guardian of sessions for Windows: against infostealers that steal your Telegram and browser logins. It works completely offline; the program makes no network calls.

Status: v1.0. Protected: Telegram Desktop, Chrome, Edge, Brave and Discord; your own apps are added with `add`. It protects session files, not the window of a running app (see "Limits of protection" and the [threat model](docs/THREAT_MODEL.en.md)). The installer is not code-signed: SmartScreen may warn you, compare the SHA-256 from the release notes.

The idea: set it up once, live in the tray and forget about it until there is a threat. Apps start from the SessionVault tray icon; the service does everything else itself.

## How it works

- Every app runs under its own Windows account `sv-<name>` (no administrator rights), and its data lives in a folder closed to all other accounts, including the accounts of other protected apps. A stealer in your account cannot read the files, and a compromised app cannot read its neighbour's data.
- While the app is closed, its data is encrypted (AES-256-GCM, the key is derived from the master password with Argon2id). The Windows service decrypts the data on start and encrypts it again on exit.
- The vault is unlocked with Windows Hello (fingerprint, face or PIN in the system dialog) or the master password in a service window; this is needed only after the vault locks. While it is unlocked, apps start from the tray without prompts.
- The vault locks itself: on session lock (Win+L), user switch, session disconnect (RDP), sign-out and sleep. If an app is still running, it needs the key to encrypt on exit, so the lock happens right after it closes. An idle timer (4 hours by default) is a safety net: `idle_minutes` in `config.json` changes it, a negative value turns it off.
- The vault is protected against rollback: each record number is part of the authentication, and replacing `data.enc` with an old copy or the key parameters is rejected. The previous archive is kept as `data.enc.bak`; restore it with `sessionvault restore-backup <profile>` (as administrator, the master password is required).
- The master password must be at least 10 characters when the vault is created.
- Launch requests and the password window are rate-limited, so a process in your session cannot flood you with windows.
- The background footprint is minimal: the tray icon asks the service for its state every 10 seconds (every 2 seconds only for a minute after your action), the service checks decoys and auditing every 5 minutes, and the rest happens on events (start, app exit, session lock). There are no pop-ups except the alarm and password windows you triggered yourself.
- The `service.log` and `alerts.log` logs in `C:\ProgramData\SessionVault` are capped at a megabyte (the older part is in `.1`).

## Installation

Run `SessionVaultSetup.exe` under a regular (non-administrator) account and confirm UAC. The installer, in Russian or English (by the Windows language), offers one checkbox to enable the quiet system hardening (see below), then starts the tray icon and opens the first-time setup. Start apps from the SessionVault tray icon: a menu item appears for every protected app.

The program is not installed under an administrator account: an administrator bypasses file permissions.

Uninstalling through "Apps" decrypts the data and returns it to its original places (the master password is required), then reverts the system measures and removes the service and the accounts.

## First-time setup

After installation (once per account, and later from the tray menu: "First-time setup…") a window with four steps opens; it takes about five minutes:

1. **Check protection**: the result for the system measures (Defender, BitLocker, etc.) with hints on what to turn on.
2. **Protect apps**: a button next to each of Telegram, Chrome, Edge, Brave and Discord opens an administrator window (UAC) with the `protect` command, where you set the master password. The button changes to "Protected" once the service confirms the vault (the window checks every 3 seconds while open).
3. **Windows Hello**: sign in with a fingerprint, face or PIN instead of the password (available when at least one app is protected).
4. **Recovery key**: 24 words on paper.

The wizard protects nothing by itself and holds no secrets: every button runs the same command as a tray menu item or the console. You can close it at any moment; nothing breaks.

## Interface language

The tray, the windows (password, alarm, protection check, wizard), the installer and the command output are in Russian or English. The language comes from the Windows display language (Russian, Ukrainian and Belarusian give Russian, everything else English); you can set it in `config.json`: `"language": "en"` or `"ru"`. The service logs (`service.log`, `alerts.log`, `memory.log`) and some internal error messages stay in Russian; translation is never used for comparisons or protocols.

## Telegram

The installer checks the `Telegram.exe` signature (publisher Telegram FZ-LLC); an unsigned or foreign file stops the installation. The `tdata` folder is moved into the vault and a decoy stays in its place. Protect Telegram in the first-time setup or with `sessionvault protect telegram` (as administrator, with Telegram closed).

## Browsers: Chrome, Edge, Brave

A command as administrator: `sessionvault protect chrome` (or `edge`, `brave`; `-yes` skips the question). The browser must be installed for all users (in Program Files) and closed.

- The browser runs under its own account (`sv-chrome` etc.) with a profile in a closed folder; while it is closed, the profile is encrypted. Caches are not archived; the archive limit is 1 GiB.
- The profile is created new: the browser's cookies and passwords are encrypted with your account key (DPAPI), and the app account cannot read them. You sign in again (account sync brings bookmarks and passwords back).
- The old profile in your account is **deleted** after confirmation (type `delete`): while it exists, a stealer reads it as before. A Chromium-style decoy stays in its place.
- A regular browser launched from your account (a link in an email, autostart, a shortcut) creates a real profile in the place of the decoy. There is no alarm (signed browser exes are allowlisted), but that profile is not protected. Open the browser from the tray.
- A link can be opened in the protected browser with `sessionvault open https://example.com`: if the vault is locked, the service shows an unlock window (Hello or password) and opens the link; if the browser is running, the link opens in a new tab without a password. The first of Chrome, Edge, Brave is chosen; set another in `config.json`: `"link_profile": "edge"`. Only `http://` and `https://` links are accepted. SessionVault does not become the default browser (Windows 11 does not allow changing that silently); the command can be called from a shortcut or another program.

## Decoy

At the old data location lies a folder with a similar structure and random contents (created with the user's own rights: while working with the folder the service takes the user's token, so replacing a subfolder with a link cannot redirect its operations to system files; refreshed every 6 hours; if a program has written real data into it, the service leaves it alone). The audit is set by the handle of the verified folder, not by the path: a link or junction in the decoy's place cannot redirect the audit to someone else's folder. A replaced folder (deletion, rename, junction) is noticed by the service through a Windows change event on the parent folder and the decoys are checked at once; the 5-minute check remains as a fallback. The decoy files are remembered by FileId, so a read through a hard link or from a renamed folder also raises the alarm. Local State, Preferences and settings.json in the decoy are real JSON. Windows audits reads of this folder and the service parses event 4663 from the Security log. If a foreign process (not allowlisted) reads the decoy, the service immediately closes the protected apps, encrypts the data, wipes the keys from memory and shows an alarm window with the process, the exe path and the SHA-256. The tray icon turns red and the record stays in `C:\ProgramData\SessionVault\alerts.log` (read it with `sessionvault alerts` as administrator).

If an alarm happens while an app is starting, the start is cancelled too (the alarm counter is checked before the process starts; keys are wiped). An allowlisted process is additionally checked by its loaded modules: a DLL from folders a regular account can write to is accepted only with a valid Authenticode signature (this is how OneDrive shell extensions load, for example). An unsigned DLL planted next to an allowed exe or injected into Explorer takes away its right to read the decoy; code injected without loading a module is not visible this way. A process that exited before the check is not considered the culprit (short antivirus scans).

The default allowlist: Windows Search, Explorer, Windows Defender, signed browsers and third-party antivirus (Kaspersky, ESET, Avast, Malwarebytes, Norton; the publisher is verified by signature, the publisher names were not checked against live installations). Add your own entries to `config.json` in `decoy_allow`: `{"path": "C:\\Path\\program.exe", "publisher": "Publisher"}`. Outside the Windows and Program Files folders an entry is accepted only with a publisher; the signature is verified offline.

## Windows Hello sign-in

Right-click the tray icon → "Turn on Windows Hello sign-in". For each protected app the service asks the master password once, then Windows Hello creates a key and asks for a gesture (fingerprint, face or PIN). After that the system Hello window appears instead of the password window at start. Cancelling Hello, a failure, a different PC, or a gesture not made within ~70 seconds bring back the master password window: it stays as the fallback. Turn off: `sessionvault hello disable [profile]` as administrator.

- How it works: the Hello key (owned by your account, in the TPM if present) signs a fixed challenge; the signature yields a key that wraps the same data key a second time. For this the service launches a short helper under your account: the Hello key belongs to you, not SYSTEM. The helper returns the signature to the service over a closed pipe; nothing is written to disk.
- What it gives you: you do not type the password into a window a keylogger in your session could watch. The signature can be stolen from your session only by deception (showing a fake Hello window and persuading you to confirm), and without `vault.json` (closed to your account) it is useless.
- Requirements: Windows Hello (PIN, face or fingerprint) set up for the main account. Without it only the password works.
- The Hello key is reset when the PIN is changed with TPM clearing or Hello is reset: then sign in with the password and turn Hello on again.

## Recovery key and moving to a new PC

- `sessionvault recovery create` (as administrator; also in the tray menu, "Create a recovery key…") asks the master password of every protected app and prints 24 BIP-39 words. Write them on paper: they are never shown again. One key opens all apps without a password or Windows Hello. A repeated `create` issues a new key and the old one stops working; an app protected later joins the key only after another `create` (`recovery status` shows what is covered).
- Wherever a password is asked (the service window, uninstall, `restore-backup`) you can enter the same 24 words. The words are checked by a checksum: a typo is rejected before decryption.
- Forgot the master password: `sessionvault recovery reset` asks for the words and a new password and sets it for all vaults the key opens.
- `sessionvault recovery verify` checks the words from paper without changing anything: it shows which vaults the key opens. `recovery create -file D:\key.txt` writes the words to a file (for example on a USB drive) instead of the screen so they do not stay in the console buffer; the file is not overwritten, copy the words to paper and delete it. `recovery revoke <app>` removes the key from one app, the others keep it. If `create` breaks in the middle, the previous slots are returned to all vaults: some do not stay on the old key and some on the new one.
- How it works: the recovery key is 256 random bits; together with the vault salt it derives the key that wraps the data key once more (like the Hello slot). The slot is bound to its `vault.json` and does not transfer to another vault. The key is kept only on your paper: it is never written to disk or log.
- Moving to a new PC: `sessionvault export telegram D:\telegram.svx` (app closed) writes `vault.json` without the Hello slot and `data.enc`, both already encrypted. On the new PC, after installing SessionVault and the app itself: `sessionvault import D:\telegram.svx` asks for the master password or the recovery key, checks that the archive opens, and turns the protection on. Windows Hello sign-in is set up again on the new PC. If the app already had a session on the new PC, it stays in place unprotected: delete it manually. Custom apps (`add`) move together with the profile description (data folder, launch arguments, data path): on the new PC you need `sessionvault import -exe "C:\path\app.exe" [-copy-dir] file`; the command verifies the exe signature, shows the profile from the file and asks for `yes` (the launch arguments come from outside, so a human confirms them); the rights to launch files from the profile are not transferred.
- The export file is as strong as the master password: a thief of the file and a weak password have unlimited guesses. The password is at least 10 characters, and the recovery key cannot be guessed.

## FIDO2 key sign-in (YubiKey)

Right-click the tray icon → "Turn on FIDO2 key (YubiKey) sign-in". For each protected app the service asks the master password once, then Windows asks you to insert the key, enter its PIN and touch it (twice: when creating the credential and when first obtaining the secret). After that the system key window appears when an app starts; cancelling, a failure or a missing key lead to Windows Hello (if on) and then to the master password window. Order: FIDO2 key, Windows Hello, password; the recovery key fits wherever a password is asked. Turn off: `sessionvault fido disable [profile]` as administrator.

- How it works: a credential with the `hmac-secret` extension is created on the key (not stored on the key: no resident key needed). For a random per-profile salt the key returns 32 bytes on each unlock that depend on the key, the credential and the salt; they derive the key that wraps the same data key a third time. The key window is shown by Windows itself through `webauthn.dll`, the service launches a short helper under your account (as for Hello), PIN and touch are always required.
- What it gives you: a stolen key without its PIN does not open the vault; the PIN without the key does not either. The slot is bound to its `vault.json`; the credential and the salt are part of the authentication. The slot stays in the export file: on a new PC the vault opens with the same key.
- Requirements: Windows 11 (WebAuthn API version 6 and up), an external FIDO2 key with `hmac-secret` and a PIN (YubiKey 5, Security Key and similar). The built-in Windows Hello does not replace or use this method.
- If the key is lost: the vault opens with the master password, Windows Hello or the recovery key; `fido disable` removes the slot. SessionVault does not delete the credential on the key itself: the key's owner erases it.
- FIDO2 key sign-in has so far been verified only without a physical key (Windows calls and cancellation); if there are problems, the password, Windows Hello and the recovery key work.
- Checking a key without SessionVault: `fido-spike.exe` from the build folder (not part of the installer) creates a credential, obtains the secret twice and compares.

## Network barrier and interpreter ban

A protected app runs under its own account. If it is compromised, malicious code could exfiltrate data through system utilities. The installer closes this loophole for all app accounts (they are in the `SessionVaultApps` group; your account and Windows updates are not affected):

- Windows Firewall rules (created through the firewall COM interface, rule group `SessionVault`, outbound, block, only for the `SessionVaultApps` group): PowerShell (and 7), `curl`, `bitsadmin`, `certutil`, `regsvr32`, `rundll32`, `msiexec`, `ftp`, `tftp`, `finger`, `nslookup`, `telnet`, `ssh`, `scp`, `sftp`, `wscript`, `cscript`, `mshta`.
- Interpreters cannot be launched by the app group: `powershell.exe`, `powershell_ise.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `wmic.exe`, `cmstp.exe`, `wsl.exe`, `bash.exe`, the .NET Framework build tools (`MSBuild`, `csc`, `vbc`, `jsc`, `InstallUtil`, `RegAsm`, `RegSvcs`: they execute code from a project file) and `pwsh.exe` if installed get a deny entry `SessionVaultApps:(DENY)(X)`; the owner and other rights are unchanged. The entry is set at install and before every protected app launch: a Windows update replaces files and resets permissions.
- A rule for SessionVault itself: `sessionvault.exe` (service, tray, helpers) cannot reach the network for any user. The "zero network" principle is now also held at the system level.

`sessionvault lockdown` (as administrator) repeats the setup, `lockdown -off` removes everything; uninstalling also restores the permissions and removes the rules. `sessionvault check` has a "Network barrier for apps" item.

- What it does not do: the app's own network access (a browser, Telegram) is not restricted: it needs the network. There is no default-deny mode: it would flood you with confirmation prompts. Running scripts from the working folder is closed since v0.13 (no execute right); here the system interpreters are closed.
- Limits: the rules work while Windows Firewall is on (a third-party antivirus also turns it off); the firewall does not filter traffic to the computer itself. Python, Node.js, Git Bash and Perl are closed at typical install paths (Program Files, `C:\Python*`, `AppData\Local\Programs\Python`); those installed elsewhere are not closed. `schtasks`, `at`, `forfiles`, `esentutl`, `expand`, `makecab`, `extrac32` are also closed. The app itself (a browser, Telegram) can exfiltrate data through its own channel: the barrier closes foreign tools, not the app's own channel.

## Discord

`sessionvault protect discord` (as administrator; Discord must be installed and started at least once). Discord installs into the user profile (`AppData\Local\Discord\app-<version>`), where `vault` has no access, so the service copies the latest version folder into the program folder (`apps\discord`), verifies the `Discord.exe` signature (publisher Discord Inc.) and launches the copy under its own account with `--user-data-dir`. The Discord token lives in Local Storage and is encrypted with your account's DPAPI key, which the app account cannot read: the protected Discord profile is new (sign in again, as with browsers), the old `AppData\Roaming\discord` is deleted after confirmation, and a decoy lies in its place.

- After Discord itself updates, the protected copy gets outdated: `sessionvault refresh discord` (app closed) copies the fresh version.
- Discord minimizes to the tray when its window is closed and keeps running: the data stays decrypted until "Quit" is chosen in its icon menu. Faster: the SessionVault tray item "Close Discord and encrypt its data" ends the app processes and the data is encrypted as on a normal exit (every running protected app has such an item).
- `sessionvault check` has an "App copies" item: if Discord (or an added app) updated and its protected copy did not, a hint about `refresh` appears. The copy is updated entirely (~400 MB): the files of a new version have new dates, so incremental copying would save nothing.
- Discord sign-in and copy refresh were verified on a stand-in installation in a VM; the real Discord (Squirrel updates, the client's version check) cannot be verified in a VM without a network.

## Your own apps: add

`sessionvault add` protects an app that is not built in:

```
sessionvault add [-yes] [-copy-dir] [-data name] -arg "--user-data-dir={data_path}\data" name "C:\path\app.exe" "C:\Users\you\AppData\Roaming\App"
```

- The app must be able to take its data folder from a launch argument: `-arg` (repeatable) needs `{data_path}` (the app's working folder under its account). Without it the app would write data to the account profile, bypassing the encryption.
- The data folder (the last argument) must be inside the main account profile; its contents are moved under the app account and encrypted (the app must be closed), and returned on uninstall. If the folder does not exist, an empty one is created.
- Before adding, the command shows the exe, the publisher (Authenticode signature), the data folder and the arguments and asks for `yes` (`-yes` skips it): the app will run with access to its decrypted data. A data folder inside OneDrive is flagged with a warning: it syncs to the cloud in plain form. If the exe lives in a user profile, its copy is placed in the SessionVault folder (`-copy-dir` copies the whole exe folder; after the app updates: `refresh`).
- A generic decoy is created for custom apps (a few typical files: Local State, Preferences, a database, a cache): the structure of their data is unknown, so it is weaker than the dedicated ones. Moving to a new PC: `export`/`import -exe` (see above).
- `sessionvault unprotect <app>` (as administrator, app closed) removes the protection from one app: the data is decrypted and returned to its place; the profile, the `sv-<name>` account, the app copy and the WER exclusion are deleted. Other apps and the service are not affected.

## Profile signature

An app profile (`ProgramData\SessionVault\profiles\<name>.json`) defines what runs under the app account and with which arguments. Every profile is signed (HMAC-SHA256, the key is in the closed data folder, readable only by SYSTEM and administrators): the service and the commands do not read a profile without a valid signature, for example a file edited by hand or moved from another profile. Install, `protect`, `add` and `trust` sign profiles; profiles of earlier versions are signed on update. A file you edited yourself is confirmed with `sessionvault trust <profile>` (it shows the path and asks for `yes`). Built-in app profiles are signed automatically, custom ones (`add`) by explicit confirmation when added. This protects against accidental and indirect tampering, not against an administrator: they have access to the key.

## Windows Error Reporting

A crash dump of a protected app contains its memory with decrypted data, and the error reporting service writes dumps to disk. Before each protected app launch the service adds its exe to the reporting exclusions (for all users, by file name); uninstalling removes the exclusions. The exclusion also applies to your regular launch of the same exe (its crashes also stay out of Windows reports).

## Steam

Steam is not supported yet. The Steam session (`ssfn*` files, `config\config.vdf`, `loginusers.vdf`, `local.vdf`, registry keys) lies right in the client folder (`Program Files (x86)\Steam`), where the app account cannot write, and the client updates and keeps games there and in libraries on other drives. Protecting the session needs the whole client under the app account with access to the game libraries and sign-in through an app with its own rights; such a rework cannot be verified without a real Steam and a network, so it is moved to a separate version.

## A separate account per app

Every protected app runs under its own Windows account: `sv-telegram`, `sv-chrome`, `sv-discord` and so on (a name longer than 20 characters is shortened: `sv-<8 characters>-<6 hash characters>`). The account is created at the app's first start: no administrator rights, hidden from the sign-in screen, no network or remote sign-in, with a long random password kept in `ProgramData\SessionVault\accounts.json` (readable only by SYSTEM and administrators), needed only by the service to launch. The app's working folder is accessible only to its account: an app compromised while another is open cannot read the neighbour's decrypted data. The rules common to all (exchange folder, interpreter ban, firewall) are granted to the local group `SessionVaultApps`, which contains all such accounts.

- Moving from versions before v0.19: the shared `vault` account is replaced by per-app accounts. Install (or the service start after the program is replaced in place) lifts the bans from `vault`, moves the rules to the group and deletes `vault` with its password; vaults are not touched: only ciphertext is on disk, and the working folder gets the new account's rights at launch.
- Uninstalling deletes all app accounts, their profiles in `C:\Users`, the passwords and the group. Remove the protection from one app: `sessionvault unprotect <app>`.
- Account passwords in `accounts.json` are encrypted with this computer's DPAPI key: a file copied separately (a drive without BitLocker, a backup) does not open on another machine. This computer's administrator reads the passwords just like the service. Passwords are not rotated: the account cannot be signed into, the password is needed only by the service. Only an account in the `accounts.json` list counts as "ours": a regular account named `sv-something` does not get into the memory read log.
- Apps still share your Windows session: the desktop, windows and clipboard are common (see "Limits of protection"); the file and process side is isolated.

## Quiet system measures

The data of a running app lives in the memory of its process and can reach disk through the page file, hibernation and crash dumps. `sessionvault harden` (as administrator; the installer offers it as a checkbox) turns on page file encryption and turns off hibernation (and with it Windows fast startup) and memory dumps. A restart is needed. The previous values are kept in `config.json`; `sessionvault harden -off` and uninstalling restore them. The rest of the drive contents is protected only by BitLocker.

## Protection check

`sessionvault check` shows which system measures are missing: the main account is not an administrator, the Windows version and edition (Home is an info item: it is an edition limit), Defender (by the real real-time protection state, not only the registry; a working third-party antivirus is an info item, not red), BitLocker (and whether a recovery key exists), memory integrity (HVCI: on and currently running), Secure Boot, the vulnerable driver blocklist, ASR rules, the decoy audit, `harden`, Windows Hello, the network barrier (and whether the firewall is on), browser extensions, the memory read log, the Windows Security log size and app copies. The state of Defender, BitLocker, HVCI and third-party antivirus is learned by the service in one PowerShell run for the whole report. If BitLocker was not determined at start (WMI answers late after boot), the service repeats the check once after a minute. After `check -fix` and other administrator commands the service refreshes the report itself. Every yellow and red item has a hint on what to do. `check -json` prints the same report for scripts. The report only reads: it turns on and changes nothing. The service builds the report once at start and on the `check` command, no timers; the last report is in `check.json` (administrators can read it; from an administrator account `check` shows exactly it). The report also reminds you to set the passcode in Telegram itself and has a note about ClickFix.

Fixes only on an explicit administrator command: `sessionvault check -fix` shows a list of four ASR rules (obfuscated scripts, JS/VBS launching a downloaded exe, executable content from email, credential theft from LSASS), asks for confirmation (`-yes` skips it) and turns the rules on in Defender in block mode. Defender must be on. `check -fix -off` and uninstalling restore the previous values.

Chromium extensions (Chrome, Edge, Brave under protection) are checked at the moment the browser starts, when its profile is already decrypted: an extension with access to cookies and all sites appears in the report as a yellow item. This is not an accusation but a reason to check that you trust it. There are no timers; until the first launch of a protected browser the item shows a note.

The same in a window: the tray item "Check protection" (or `sessionvault check -window`) shows the result with yellow and red items and, if there is something to improve, offers to open "Windows Security". While the check runs, the menu item reads "Checking protection…"; if the service is unavailable, the window tells "stopped" from "busy" and "access denied". The window itself appears once after installation and only if there are red items; without them, and at other times, there are no windows or balloons.

## No execution and the exchange folder

A protected app runs under its own account. In its working folder this account can read, write and delete files but not execute them or change permissions: malicious code inside the app cannot save an exe and run it from there. The exception is the `widevinecdm.dll` module in a browser profile (copy-protected video loads it from there): the service verifies the Google LLC signature before every browser start and gives the file only read and execute, the app cannot rewrite it. A new module version works at the next browser start. Permissions are set at each app start, there is no background work.

To hand a file to a protected app (or take a download), there is the exchange folder `C:\ProgramData\SessionVault\exchange`; it opens from the tray menu ("Exchange folder…"). You read, write and run files from there, `vault` reads and writes but does not run. Uninstalling leaves the files of the exchange folder. Do not put secrets there: any process of your account reads this folder.

## Memory read log

The service puts Windows auditing on the processes of protected apps and quietly records in `C:\ProgramData\SessionVault\memory.log` which foreign process read or wrote the app's memory or tried to (a regular account is denied, but the attempt is visible): time, account, program, rights, a "denied" mark. There are no windows, sounds or alarms: the log is for analysis, and ordinary programs (a debugger, an antivirus) also sometimes read memory. Own processes (app accounts, the service, SYSTEM) are not recorded, repeats from one process are merged. `sessionvault check` has an "App memory reads" item (the count of accesses in the last 24 hours and the last one, always info, never yellow; the counter survives a service restart: it is rebuilt from the log). Auditing is set on accesses by the main account (the stealer runs in it), not on everyone: the exchange between the app's own processes does not clutter the log. Auditing is set on a process at the moment it appears: a job object tells the service about every new app process (including browser children), no polling or timers. The log keeps four previous one-megabyte parts (`memory.log.1`…`.4`), at most 60 records per minute. The log does not name the target process by PID (Windows gives only the exe name in the event): for a browser with ten processes you see that the browser was read but not which of its processes. A log write error gets into `service.log` once. Windows object auditing is turned on together with the rest of auditing and reverted on uninstall.

## Commands

```
sessionvault install [-user name] [-telegram-exe path]   (called by the installer)
sessionvault protect [-yes] [-password-stdin] <telegram|chrome|edge|brave|discord>
sessionvault add [-yes] [-copy-dir] [-data name] -arg "...{data_path}..." name path-to-exe data-folder
sessionvault refresh <app>
sessionvault trust [-yes] <profile>
sessionvault harden [-off]
sessionvault lockdown [-off]
sessionvault hello disable [profile]
sessionvault fido disable [profile]
sessionvault recovery create [-file path]|reset|verify|revoke <app>|status
sessionvault export <app> <file>
sessionvault import [-exe path-to-exe [-copy-dir] [-yes]] [-password-stdin] <file>
sessionvault unprotect [-password-stdin] <app>
sessionvault restore-backup <profile>
sessionvault run <profile>
sessionvault open <link>
sessionvault status
sessionvault check [-json|-window]
sessionvault check -fix [-yes|-off]
sessionvault alerts
sessionvault tray
sessionvault uninstall
```

## Limits of protection

What the program does not cover. These are honest limits, not unfinished work:

- ClickFix: if you paste a command from a website or an "I am not a robot" check into Run, PowerShell or Terminal, the malware runs with your rights and file protection does not stop it. Do not run strangers' commands; the reminder is in `sessionvault check` and in the check window.
- The no-execute rule covers the app's working folder, the exchange folder and the app account's own profile (`C:\Users\sv-<name>`: Temp, Downloads etc.; permissions are set at each launch). An app that needs to run files from there will be hindered: report such a case.
- The no-execute rule concerns programs (exe, dll), not scripts: an interpreter from a system folder (PowerShell, cmd, Python etc.) reads and executes a script lying in the working folder. The interpreter ban and the network barrier close this (see "Network barrier").
- The exchange folder is available to all protected apps (the `SessionVaultApps` group): a compromised app can drop a file there that another reads, and read what you put there. Put there only what you are ready to show to any of them.
- The protection works against processes of a regular account. An administrator, a kernel driver and physical access to an unencrypted drive bypass it.
- While an app runs, its data is open to the app itself. A process of your session sees its window, screen and clipboard and can send keystrokes to the window. It protects against stealing session files, not against driving a running app. If an app under its account is compromised (for example, through a browser vulnerability), it gets the abilities of a regular program in your session: window, input, screen, shared `Local` object names. Keep browsers updated.
- While an app runs, decrypted data lies in its working folder on disk (after closing it is encrypted and the folder deleted, but traces on an SSD may physically remain). A RAM disk cannot be made in Windows without a third-party driver, so it is not part of the program; drive encryption (BitLocker, `sessionvault check` reminds you) helps.
- While the vault is unlocked, a process of your session can launch a protected app with `run` without a password. It does not receive the data this way. Likewise it can open any http(s) link in the protected browser with `open`: the page opens under your sign-ins.
- Until Windows Hello is on, the master password is typed on the regular desktop: a keylogger in your session can intercept it. With Hello the password is only a fallback.
- If an app is running when the computer sleeps, its key stays in memory until the app closes (`harden` closes hibernation).
- A rollback of both vault files at once (`data.enc` and `vault.json`) is visible only with administrator rights, and with them the protection is bypassed anyway.

Decoy limits:

- Auditing fires after the read: a stealer manages to read the decoy but not the real data. If a group policy or an administrator turned off file system auditing, the decoy is silent; `sessionvault alerts` shows whether auditing works.
- The decoy does not protect against an allowlisted process into which foreign code is injected without loading a module (for example, writing code straight into Explorer's memory): the image check sees only planted and loaded DLLs. A stealer can read the decoy without an alarm, but it still gets no real data.
- While the service is not running (stopped or restarting), the decoy is not watched; if the user is not signed in, the service cannot create a decoy: it appears after sign-in.
- The Windows audit log from which the service takes events is size-limited: check it in `sessionvault check` (the "Windows Security log" item).

## What next

v1.0 is released. Next, as a separate version: Steam (the client keeps its session in its own folder and needs a rework of the launch). After that, on demand: behavioural detection, service self-protection, wallets, Linux and macOS versions. Not verified on hardware or on a network: a FIDO2 key (YubiKey), fingerprint and face in Windows Hello, sleep and RDP, real network blocking, real Discord and Steam, Windows 10 and Home. Anything that needs constant action or makes noise is not part of the product.

## Project security and contributing

[Threat model](docs/THREAT_MODEL.en.md) · [Report a vulnerability](SECURITY.md) · [How to contribute](CONTRIBUTING.md). The code is open and has no network calls: the "zero network" check (no `net/http` or `crypto/tls` among the dependencies) runs in CI on every commit.

## Checks and build

`access-check` runs from a regular account and tries to read data, process memory and control the service through the pipe; any successful read is a bug.

Build: `tools/build.ps1` (Go 1.27), the installer is Inno Setup 6 (`installer\sessionvault.iss`). Tests: `go test ./...`; the full service and installer autotest runs in a Hyper-V VM (`tools/vm/run-test.ps1`, `tools/vm/run-installer-test.ps1`).

The change history is in `CHANGELOG.md`.
