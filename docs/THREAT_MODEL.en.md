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

## Known limits

The full list is in the README ("Границы защиты", "Ограничения приманки"). The main ones: it protects session files, not the window of a running app; decrypted data sits in the working folder while the app runs; an administrator and a kernel driver bypass it; not verified on hardware (YubiKey, fingerprint/face, sleep, RDP) or with real Discord and Steam; the installer is not code-signed.

## How to verify

- `access-check` (from the build folder) tries to read data, process memory and control the service from a regular account; any successful read is a bug.
- A full service and installer test in a Hyper-V VM: `tools/vm/run-test.ps1`, `tools/vm/run-installer-test.ps1`.
- CI: `go vet`, `golangci-lint`, `go test`, `govulncheck`, the "zero network" check, CodeQL.

Found a hole? See [SECURITY.md](../SECURITY.md).
