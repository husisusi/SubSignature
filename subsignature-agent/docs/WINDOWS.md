# Windows: Thunderbird, classic Outlook, new Outlook

This document describes what the agent does on Windows, where it writes and what it deliberately cannot do.

> **Status 0.4.0-alpha:** the Windows programs are **built** on Linux (amd64, arm64) and statically checked. The logic
> (finding accounts, creating files, setting and reverting registry values) runs in the tests against an in-memory
> registry. **Nothing has been run on a real Windows with a real Outlook yet.** The thin part that really talks to
> Windows (`internal/outlook/registry_windows.go`, the lock file, `install.ps1`) is therefore untested. Please start
> with `check` on a test machine.

## What is supported

| Mail client | Status | How |
|---|---|---|
| Thunderbird (installer) | as on Linux | file in the profile + marked block in `user.js` |
| Thunderbird (Microsoft Store) | profile is found | it lives under `%LOCALAPPDATA%\Packages\MozillaThunderbird.…\LocalCache\Roaming\Thunderbird` |
| Classic Outlook (2013 to 2024, Microsoft 365) | supported | signature files + default signature per account in the registry |
| **New Outlook** (`olk.exe`) | **not possible**, detected and reported | see below |

## Classic Outlook

### Files

Outlook looks for signatures in `%APPDATA%\Microsoft\Signatures`. The agent reads the folder name from the registry
(`HKCU\Software\Microsoft\Office\<version>\Common\General`, value `Signatures`) because it can differ by Office
language. If that value contains a path with `..\` or a drive, the agent does **not** use it and reports an error:
it never writes outside `%APPDATA%\Microsoft`.

For each address a signature with the fixed name `<signature-name> <address>` is created, for example
`SubSignature max.mustermann@example.com`, consisting of three files:

| File | Content |
|---|---|
| `.htm` | the checked HTML from the server as **pure ASCII**: umlauts and other characters as character references (`&#252;`), inside `<style>` as CSS escapes. Outlook renders with the Word engine, which does not reliably guess encodings; this way the encoding does not matter. |
| `.txt` | plain-text version (field `text` of the API; if missing, a simple derivation from the HTML), UTF-16 with BOM |
| `.rtf` | plain Rich Text version made from the text |

The name depends only on the address. If the signature changes on the server, only the file is replaced; new messages
get the new version immediately.

### Default signature per account

Outlook keeps the accounts of a profile under

```
HKCU\Software\Microsoft\Office\<version>\Outlook\Profiles\<profile>\9375CFF0413111d3B88A00104B2A6676\<0000000N>
```

The agent reads the address there (value `Email`, for Exchange accounts `Account Name`) and sets `New Signature` and
`Reply-Forward Signature` of the matching account to the name of the signature. Rules:

* It writes **only** into such account keys and **only** these two values; keys are never created.
* Without an existing signature file nothing is registered.
* The data type stays the way Outlook uses it (`REG_SZ` since Outlook 2016, `REG_BINARY` in Outlook 2013).
* Before its first change the agent remembers the previous value (in `%LOCALAPPDATA%\subsignature-agent\state.json`).
* Outlook reads these values at start. A new default signature therefore applies after the next Outlook start.
* `<set-new>`/`<set-reply>` set to `false`: the signature is merely available, the user chooses.

As with Thunderbird: on every sync the agent restores the server's state. Whoever picks a different default signature
in Outlook gets the central one back on the next sync. An address can be excluded with `<exclude-email>`.

### Roaming signatures (Microsoft 365 / Outlook.com only)

For mailboxes in Microsoft 365 or Outlook.com, Outlook (from build 2303) stores signatures in the mailbox. Local
signatures then appear under "Signatures on this device", and Outlook may ignore the local default signature.
On-premises Exchange, IMAP and POP are **not** affected.

* `<roaming-signatures>keep</roaming-signatures>` (default): the agent changes nothing and prints a note.
* `<roaming-signatures>disable</roaming-signatures>`: the agent sets `DisableRoamingSignatures = 1` (documented by
  Microsoft) and `DisableRoamingSignaturesTemporaryToggle = 1` (older builds) for the user under
  `HKCU\Software\Microsoft\Office\<version>\Outlook\Setup`. If this is already set by group policy, it does nothing.
  It never writes the policy branch.

## The new Outlook

The new Outlook stores signatures in the mailbox and reads neither the signature folder nor the registry. As far as
research in November 2026 shows, there is no interface through which a local program could set signatures there (not
in Microsoft Graph either). The agent therefore cannot configure **anything** there. It detects the new Outlook (app
package `Microsoft.OutlookForWindows`, switch `UseNewOutlook`) and says so clearly in `check`, `sync` and `status`.

Ways that actually work for the new Outlook lie outside a local agent:

1. **Outlook add-in** (web add-in with event-based activation and `setSignatureAsync`): it runs in the new Outlook, in
   Outlook on the web and in classic Outlook, fetches the signature from the SubSignature server while composing and
   is deployed centrally in the Microsoft 365 admin center. That would be a separate component on the SubSignature server.
2. **Exchange Online PowerShell** by an Exchange administrator. That is nothing for a program that runs at the user
   with a read-only token.

## Undo: `subsignature-agent remove`

`remove check` only shows, `remove` executes:

* **Outlook:** default signatures that still point to the agent's signature are reset to the value from before the
  first change (or removed if there was none). Whatever the user has chosen in the meantime stays. The three files per
  signature are deleted, a roaming switch set by the agent is reverted.
* **Thunderbird:** the block in `user.js` and the files in `<profile>\subsignature` are removed. The account settings
  still contain the reference "Attach the signature from a file instead"; it then points to a deleted file and can be
  switched off there.
* File names and folders from the state file are checked before deleting (only names the agent assigns, only inside
  `%APPDATA%\Microsoft`).

If the agent keeps running (autostart), it sets the signature up again on the next sync. To remove it for good use
`uninstall.ps1`.

## Installation

`make dist-windows` creates one folder `dist/windows-<arch>/` per architecture containing:

| File | Purpose |
|---|---|
| `subsignature-agent.exe` | console program: `ping`, `check`, `sync`, `status`, `remove`, `init` |
| `subsignature-agentw.exe` | the same without a console window, for autostart (`run`) |
| `mocksubsig.exe` | test server |
| `install.ps1`, `uninstall.ps1` | set up and remove for the logged-in user, without administrator rights |
| `config.example.xml` | template |

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1      # copies to %LOCALAPPDATA%\Programs\SubSignatureAgent, autostart
notepad $env:APPDATA\subsignature-agent\config.xml           # enter <url>
notepad $env:APPDATA\subsignature-agent\token                # only the token (ssg_...), one line
& "$env:LOCALAPPDATA\Programs\SubSignatureAgent\subsignature-agent.exe" ping
& "$env:LOCALAPPDATA\Programs\SubSignatureAgent\subsignature-agent.exe" check
```

Without installation it also works directly from a folder: `.\subsignature-agent.exe -c .\config.xml check`.

| Location | Content |
|---|---|
| `%APPDATA%\subsignature-agent\config.xml`, `token` | the user's configuration (the same file as on Linux) |
| `%ProgramData%\subsignature-agent\config.xml` | machine-wide configuration (used if the user has none of their own) |
| `%LOCALAPPDATA%\subsignature-agent\` | `state.json`, lock file, `agent.log` (daemon; from 1 MiB one generation `.1`) |

Autostart: `install.ps1` registers `"…\subsignature-agentw.exe" run` under
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. The agent then syncs after logon and afterwards at the interval
from `config.xml`. It re-reads the configuration before every sync.

## Security on Windows

* The agent needs **no administrator rights** and only works inside the user profile and below `HKEY_CURRENT_USER`.
* Registry: read-only below `Software\Microsoft\Office` and `Software\Policies\Microsoft\Office`; it writes only four
  values (two per account, two roaming switches), each checked against a fixed pattern, and additionally restricted
  to the branch `Software\Microsoft\Office` in the Windows-specific code.
* No third-party library is loaded: registry access uses the Go standard library and two functions from
  `advapi32.dll` (a Windows "KnownDLL", always loaded from the system folder).
* Token: the file lives in the user profile (`%APPDATA%`), which only the user, SYSTEM and administrators may read.
  If it lies outside, the agent warns because it cannot judge Windows access rights. **Not built in yet:** encryption
  with the Windows account key (DPAPI) or the Windows Credential Manager.
* The `.exe` is **not signed**. SmartScreen and virus scanners may therefore warn. For a rollout it should be signed
  with the company's code-signing certificate.
* Everything else applies as on Linux (mandatory TLS, no redirects, HTML tripwire, abort on token errors).

## To verify on a real Windows

1. Does `status` find the Outlook accounts? Especially **Exchange accounts**: the address is read from `Account Name`;
   if the account has been renamed, the agent does not recognize it.
2. Does the signature appear in Outlook under File → Options → Mail → Signatures, and is it set for new messages and
   replies after restarting Outlook?
3. Umlauts, images (the API delivers absolute image URLs) and the look in Outlook.
4. Microsoft 365 mailbox: behaviour with `roaming-signatures` `keep` and `disable`.
5. `remove`: is everything as before afterwards?
6. Thunderbird on Windows (installer and Store version): signature in the compose window.
7. `install.ps1`, autostart without a window, `agent.log`.
8. Does a virus scanner or SmartScreen flag the unsigned `.exe`?
