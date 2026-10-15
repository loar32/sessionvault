# SessionVault threat model

English · [Русский](THREAT_MODEL.md)

This document says who and what SessionVault protects against, what the protection rests on, and what it does not cover. The project principle: protection rests on architecture, not secrecy; the code is open and both defenders and attackers can read it.

## What is protected

Application session files on disk: Telegram Desktop (`tdata`), Chrome, Edge, Brave and Discord profiles, and apps you add yourself (cookies, tokens, local databases). The goal: stolen files cannot be opened on another computer, and a theft is noticeable.

## Against whom

The main adversary is an **infostealer**: malware running in your regular Windows account (from an attachment, a cracked program, a browser extension, a ClickFix trick) without administrator rights and without a driver. It walks the standard data locations, reads files and process memory with user rights, and sends the loot over the network.

Out of scope (the protection does not stop these; see the README, "Границы защиты" / limits):

- an administrator, a kernel driver, physical access to an unencrypted drive;
- malware that drives the running app itself (window, input, screen, clipboard);
- ClickFix: you run a stranger's command with your own rights;
- a vulnerability in the app itself (a browser) exploited while it runs.

## How the protection works

| Measure | Against |
|---|---|
| Data is stored encrypted (AES-256-GCM, key derived from the master password with Argon2id); each record number is part of the authentication | file theft; replacing the archive with an older copy (rollback) |
| Decrypted data lives only in a working folder that one account `sv-<name>` can access; it is encrypted and deleted when the app closes | a stealer in the main account reading data; one app reading another app's data |
| Each app runs under its own account without administrator rights; no executing files from its folder; interpreters blocked; network barrier for utilities | running a dropped exe or scripts; exfiltration with system utilities |
| A decoy at the old data location + Windows auditing | a stealer walking standard paths: a read decoy closes the apps, encrypts data, wipes keys and raises an alarm |
| The vault key lives in the memory of the SYSTEM service; locked on Win+L, user switch, sleep, idle | a stealer in the user session getting the key |
| Windows Hello sign-in (key tied to the account, in the TPM) and FIDO2/YubiKey, recovery key | a keylogger watching the password; a lost password |
| Memory read log for protected apps | incident analysis, no alarms |
| System protection check (Defender, BitLocker, HVCI, Secure Boot) | the user not knowing what is missing; fixes only on explicit command |
| Profile signature (HMAC), Authenticode signature for launched exes | replacing a protected profile or exe |

## Trust boundaries

- The **SYSTEM service** is the only holder of keys. Its interface (a private pipe) accepts only a profile name, no arguments, and never returns decrypted data.
- The **main account** (not an administrator) is an untrusted environment: the stealer runs exactly there. It cannot read the vault, the working folders or the app account passwords (`accounts.json` is closed to it and protected with DPAPI).
- **`sv-<name>` accounts** do not trust each other: a compromised app must not read its neighbour's data.
- The **password, alarm and Hello windows** are started by the service in the user session as SYSTEM: user processes cannot read or replace them (UIPI).
- **Network**: the program has no network calls; the firewall also forbids it any outbound access.

## Linux (Omarchy)

The same vault and the same model: your account is the untrusted environment, the `sessionvault daemon` service (root) is trusted. Differences:

| Measure | Against |
|---|---|
| The app runs under `sv-<name>` in a bubblewrap sandbox (own PID namespace, read-only system, the decrypted app home `0700` in place of your home folder) | a stealer reading the app's data and memory; a compromised app reaching your home and a neighbour's data |
| The service socket accepts only the owner's uid and root (`SO_PEERCRED`); the protocol is a word and an app name, links are validated | forged requests, passing arguments to the app |
| The app's access to the session is an ACL only on the Wayland socket and passage to PipeWire/Pulse; the object is opened without following links, its type and owner are checked; the socket must be served by a known compositor from `/usr` | granting rights to a foreign file via a planted link; a fake "compositor" |
| Actions in the owner's home folder are done by a helper with the owner's rights | link attacks on root |
| A decoy with fanotify marks by inode and permission events | a stealer reading the old paths, including via a hard link or after a rename |
| Locking on a screen locker or systemd-sleep start (kernel process connector), on compositor exit and on a timer | the key staying in memory after the user leaves |
| Only safe flags are taken from the browser flags file | `--remote-debugging-port` and the like from a file the stealer can write |
| The session bus goes through `xdg-dbus-proxy` with a filter: notifications, tray, MPRIS, the keyring and, of the portals, screen sharing, settings and sleep inhibition; no file chooser portal and no other services. The service moves the proxy socket into its own folder and verifies that the proxy it started is listening | a compromised app reaching session services (systemd, file managers, launching portals); a fake "bus server" from an owner process |
| Inside the sandbox the uid equals the owner's, outside it is `sv-<name>` | the bus accepts the app, while file and process rights stay with the app account |
| Links from the sandbox go through the app's socket at the service (`SO_PEERCRED`, rate limit): only http(s), mail and protected apps' schemes; files only from the exchange folder and folders shared with the app, never programs or launcher entries | a compromised app starting owner programs via `file://`, `smb://`, `steam://` and the like |
| An app of your own (add) from a place someone other than root can change is copied into a root folder; the owner's helper writes the archive, the app account's helper unpacks it, an AppImage is unpacked with its own command in a sandbox without network | a stealer swapping the program file; root writing through links in the archive |
| Folders shared with an app: the owner's helper sets the ACL, the service mounts the folder by a descriptor opened without following links into a `0700` folder of the app account | rights on foreign files and access to a foreign folder via a planted link |
| The vault is a stream of AES-GCM blocks (STREAM: block number and a last-block flag in the AAD) | truncating, reordering or swapping `data.enc` blocks; data larger than memory |

Limits: a process of your account sees windows and the screen (Wayland does not stop screenshots); the password is typed in a terminal of your session; the shared `~/SessionVault` folder is available to all protected apps, a shared folder to the app it was shared with; the sandbox shares the network (abstract Unix sockets are reachable for both you and the app); the browser key in your keyring is visible to your processes but useless without the data in the sandbox; root bypasses the protection.

## Known limits

The full list is in the README ("Границы защиты", "Ограничения приманки"). The main ones: it protects session files, not the window of a running app; decrypted data sits in the working folder while the app runs; an administrator and a kernel driver bypass it; not verified on hardware (YubiKey, fingerprint/face, sleep, RDP) or with real Discord and Steam; the installer is not code-signed.

## How to verify

- `access-check` (from the build folder) tries to read data, process memory and control the service from a regular account; any successful read is a bug.
- A full service and installer test in a Hyper-V VM: `tools/vm/run-test.ps1`, `tools/vm/run-installer-test.ps1`.
- CI: `go vet`, `golangci-lint`, `go test`, `govulncheck`, the "zero network" check, CodeQL.

Found a hole? See [SECURITY.md](../SECURITY.md).
