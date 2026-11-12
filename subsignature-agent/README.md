# SubSignature Agent for Linux and Windows — 1.0.0-rc1

A small Go program (standard library only, one file per system) that

1. fetches the **HTML signature** for each of the user's e-mail addresses from the **SubSignature server** via its API (v1, bearer token),
2. applies it in the mail client,
3. repeats this **every 2 hours** (configurable) and only changes what has changed,
4. reports back to the server, after each real sync, whether applying it worked — so the admin's **All Signatures** page can show a per-signature sync-status badge (grey/green/yellow/red). Off with `<report-status>false</report-status>`; a `check` (dry run) never reports.

| System | Mail clients |
|---|---|
| Linux | Thunderbird (native, Snap, Flatpak) |
| Windows | Thunderbird (installer and Microsoft Store) and **classic Outlook** (2013 to 2024, Microsoft 365) |

The same `config.xml` works on both systems. The agent runs as a normal user, needs neither root nor
administrator rights, and can undo everything with `remove`.

> **The new Outlook** (`olk.exe`) cannot be configured by a local program: it stores signatures in the mailbox and
> reads neither files nor the registry. The agent detects it and says so. Background and alternatives: [`docs/WINDOWS.md`](docs/WINDOWS.md).

> **Status 1.0.0-rc1 (release candidate):**
> * **Linux / Thunderbird:** in use by the project owner against the real server and a real Thunderbird.
> * **Windows:** confirmed by the project owner on a real PC with Thunderbird and classic Outlook from Microsoft 365
>   (IMAP account): signature files, default signature for new messages and replies, updates after a change on the
>   server and `remove`. Exchange accounts, `install.ps1` and the autostart have not been run on a real Windows yet –
>   see "Still to be verified".
> * **Outlook needs roaming signatures switched off**, otherwise Outlook ignores and overwrites the agent's signature
>   (also for IMAP). The agent does that by default (`<roaming-signatures>disable</roaming-signatures>`).
>   **Configurations created by `init` before 0.6.1 say `keep` - change that line to `disable`.**
> * Changes per version: [`CHANGELOG.md`](CHANGELOG.md). The API usage: [`docs/API.md`](docs/API.md). Windows details:
>   [`docs/WINDOWS.md`](docs/WINDOWS.md).

## Quick start (Linux)

```bash
make build                                  # or: go build ./cmd/subsignature-agent
install -Dm755 bin/subsignature-agent ~/.local/bin/subsignature-agent

subsignature-agent init                     # writes ~/.config/subsignature-agent/config.xml (mode 600)
$EDITOR ~/.config/subsignature-agent/config.xml   # server/url, token-file, ca-file if needed
install -m600 /dev/stdin ~/.config/subsignature-agent/token <<< "ssg_…"   # token from "API Tokens"; lives next to config.xml

subsignature-agent ping                     # check server, TLS and token (GET /api/v1/)
subsignature-agent check                    # dry run: shows what would happen
subsignature-agent sync                     # sync once
subsignature-agent status                   # profiles, identities, last state
subsignature-agent run                      # daemon (every 2 h)
subsignature-agent remove                   # undo everything ("remove check" only shows it)
```

Running as a user service: `packaging/systemd/subsignature-agent.service` (instructions at the top of the file).
Alternatively via cron: `0 */2 * * * ~/.local/bin/subsignature-agent sync`.

## Quick start (Windows)

```bash
make dist-windows        # builds dist/windows-amd64/ and dist/windows-arm64/ (works on Linux too)
```

Copy the folder to the Windows machine, then in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1      # to %LOCALAPPDATA%\Programs\SubSignatureAgent, autostart without a window
notepad $env:APPDATA\subsignature-agent\config.xml           # enter <url>, <ca-file> if needed
notepad $env:APPDATA\subsignature-agent\token                # only the token (ssg_…), one line
cd $env:LOCALAPPDATA\Programs\SubSignatureAgent
.\subsignature-agent.exe ping
.\subsignature-agent.exe check                               # shows what would happen in Thunderbird and Outlook
.\subsignature-agent.exe sync
```

It also works without installation from any folder: `.\subsignature-agent.exe -c .\config.xml check`.
Everything else (locations, Outlook registry, roaming signatures, removal): [`docs/WINDOWS.md`](docs/WINDOWS.md).

## How it works (Thunderbird)

```
find Thunderbird profile(s) ──► read identities (e-mail addresses)
        │                                   │
        │             per address (once, even with several identities)
        │                                   ▼
        │        GET /api/v1/signatures?email=…  (page by page, always in full)
        │                                   ▼
        │        select signature (address, account, template, duplicates)  ► check + normalize HTML
        │                                   ▼
        └──► <profile>/subsignature/<address>-<hash>.html  (atomic, mode 600)
             + marked block in <profile>/user.js (sig_file, sig_file-rel, attach_signature …)
```

* **Why `user.js` instead of `prefs.js`?** Thunderbird rewrites `prefs.js` on exit; changes made in the meantime are
  lost. `user.js` is read on every start. The agent only maintains a **marked block** there
  (`BEGIN/END subsignature-agent`), everything else stays untouched; before the first change a one-time
  `user.js.pre-subsignature` is created. If the block is damaged, the agent leaves the file alone.
* **Consequence:** what is in `user.js` wins on every Thunderbird start. Switching the signature off in Thunderbird's
  settings therefore does not last. To get rid of it use `subsignature-agent remove` or `<exclude-email>`.
* **Why the file inside the profile?** Thunderbird may always read there – also as Snap or Flatpak.
* **The file name depends only on the address.** If only the signature text changes, only the file is replaced and
  `user.js` stays the same.
* **Self-healing:** every run compares the prepared HTML with the file in the profile. If the file is deleted or
  modified by hand, the next run restores it. (The API has no ETag; the request per address is small.)
* **Error pacing:** with a wrong token, `429` or an unreachable server the run aborts after **one** request (the
  server blocks an address after 20 invalid tokens in 5 minutes); with a wrong token the agent only asks again after
  the full interval, with `429` after `Retry-After`. After fixing the configuration:
  `systemctl --user kill -s HUP subsignature-agent`.
* **Profiles:** native `~/.thunderbird`, Snap `~/snap/thunderbird/common/.thunderbird`, Flatpak
  `~/.var/app/org.mozilla.Thunderbird/.thunderbird` (plus the Betterbird Flatpak and a speculative XDG path).
  The same profile reachable through two paths (Snap link) is handled only once. Default: the default profile of
  each installation (`<profiles>all</profiles>` for all).

## Status reporting

After a real sync (not `check`) that finished without being rate-limited or aborted, the
agent calls `POST /api/v1/status` once per run **and mail client** with the outcome for every
address it resolved to a signature: `ok`, `warn` (e.g. no matching Outlook account was found) or
`error` (the write itself failed), plus a short message for `warn`/`error`, and the
`html_sha256` of the version it applied. Nothing about the signature's *content* is sent — only
that one small status line per signature ID, and a `device_id` that only labels which install
and mail client reported it (`<device ID> Thunderbird`, `<device ID> Outlook`).

On the server, **All Signatures** compares the reported `html_sha256` with the current version:
after an admin edits a signature (or its template, or the company details), every device shows
**out of date** until its next run fetched and applied the new version. With several devices the
badge counts them, e.g. **2/3 up to date**; a click on the badge lists every device. Thunderbird
and Outlook on one PC are two devices, so an error in Outlook does not mark Thunderbird as failed.

* The `device_id` is a random value generated once with `crypto/rand` and kept in the local
  state file; it does not reveal the hostname alone (a random suffix is appended), and it is
  never used for authentication — only the bearer token is.
* Needs a token scoped `status:write` (separate from `signatures:read`, see
  [`docs/API.md`](docs/API.md)); without that scope the agent logs a warning and carries on —
  a missing or wrong scope never blocks the actual signature sync.
* Addresses the server has no matching signature for are never reported — there is nothing
  server-side to attach a status to.
* Turn it off per install with `<report-status>false</report-status>` in `config.xml`.
* `subsignature-agent status` prints this installation's device ID and, under `Reported as:`, the
  names its mail clients have in the server's sync-status list.

## Configuration (XML)

Fully commented in [`internal/config/config.example.xml`](internal/config/config.example.xml)
(also written by `subsignature-agent init`). The most important elements:

| Element | Purpose |
|---|---|
| `server/url`, `api-path` (default `/api/v1`), `timeout` | Where to ask |
| `server/allow-insecure-http` | Safety switch for **http** (test only) |
| `server/tls/ca-file`, `insecure-skip-verify` | Your own CA (intranet) / verification off (test only) |
| `server/auth/token-env`, `token-file`, `token` | **Required:** `ssg_…` token: environment variable → file → clear text |
| `sync/interval`, `jitter`, `retry-interval`, `run-on-start` | Pacing (default 2 h + up to 5 min jitter; after errors again after 10 min) |
| `sync/report-status` | Push a per-signature `ok`/`warn`/`error` status to the server after each real sync (default `true`; `check` never reports regardless). Needs a token with the `status:write` scope. |
| `signature/template`, `username`, `override`, `duplicate-policy`, `prefer-source`, `html-policy` | Which template/account, what to do with duplicates, HTML check |
| `thunderbird/enabled`, `profiles`, `profile-path`, `sig-on-reply` … | Thunderbird: on/off, which profiles, reply/forward behaviour |
| `outlook/enabled`, `profiles`, `signature-name`, `set-new`, `set-reply`, `roaming-signatures` | Windows only, classic Outlook: on/off, name of the signature, whether it becomes the default, roaming signatures (`disable` by default since 0.6.1) |
| `exclude-email` (under `thunderbird` or `outlook`) | Addresses the agent does not touch **in any mail client** |
| `logging/level`, `file` | Log (Windows daemon without a setting: `%LOCALAPPDATA%\subsignature-agent\agent.log`) |

**Paths** in the configuration: `~` is the home directory, `$VAR` (Linux) and `%VAR%` (Windows) are expanded, and a
**relative path is relative to the folder of `config.xml`** – not to the working directory. So
`<token-file>token</token-file>` means on both systems: the file `token` next to the configuration.

Missing elements keep safe defaults (TLS required, verification on, proxy off). Typos in element names are
**silently ignored** by the XML parser – for safety switches that is the safe direction (stays "off"); for other
options double-check with `check` and `-v`.

### With and without TLS (for testing)

| Goal | Setting |
|---|---|
| Production, public certificate | `<url>https://…</url>` |
| Production, own intranet CA | `https://…` + `<ca-file>/path/ca.pem</ca-file>` (only this CA is accepted) |
| Test without TLS | `<url>http://host:port</url>` **and** `<allow-insecure-http>true</allow-insecure-http>` — otherwise the agent refuses to start; a warning appears on every run |
| Test with a self-signed certificate | `<insecure-skip-verify>true</insecure-skip-verify>` (warning on every run) — better: `ca-file` |

A mock server that mimics the API v1 is included: `mocksubsig -listen 127.0.0.1:8080` (HTTP) or
`mocksubsig -tls -ca-out mock-ca.pem` (HTTPS; enter the generated PEM file as `ca-file`). It prints its token at start
(`ssg_0123…`, changeable with `-token`). Further switches: `-https-required` (like a server without `API_ALLOW_HTTP`),
`-rate-limit`, `-data file.json`. The demo data contains duplicates within one template, a second template, a shared
mailbox with two accounts and a deactivated account.

## Duplicate signatures: which cases exist and how they are handled

In the API `template` is the template name (e.g. `signature_pro.html`); `name` is the name of the **person**. There is
neither a "default" marker nor a defined order. The agent therefore chooses itself – deterministically.

| Case | Handling |
|---|---|
| **Same address and template several times** (created twice, CSV import plus manual, LDAP plus manual) | `duplicate-policy=newest` (default): optionally first by source (`prefer-source`, e.g. `manual,csv,ldap`), then **most recently changed**, on a tie the one **created later** (higher `id`). `skip`: change nothing and warn. |
| **Exact duplicates** (same `id` or identical HTML) | Merged beforehand; they do not count as "ambiguous", not even with `skip`. |
| **Several templates of the same person** | Set `<template>` (globally or per `<override>`). Without it the most recently changed one wins and the log suggests `<template>`. If the template does not exist, **nothing is changed**. |
| **The same address on two accounts** (shared mailbox, old and new account) | The agent **changes nothing and reports it**, because it could otherwise use another person's name, role and phone. Solution: `<username>` (globally or per `<override>`) or `<template>`. |
| **Server returns entries of other addresses** | Every entry is checked against the address by the agent itself; foreign ones are ignored (tested with a server that "forgets" the filter). |
| **Entry without HTML** | Ignored; an empty signature would delete the one in the mail client. |
| **Order of the response / several pages** | Does not matter; the selection is independent of the order, IDs delivered twice at page boundaries are merged. |
| **Several Thunderbird identities with the same address** (also `Max@…` vs. `max@…`) | The address is normalized and queried **once**; all identities get the same file. |
| **The same address in several profiles / in Thunderbird and Outlook** | Each profile and client gets its own file; the server is still queried only once. |
| **The same profile via two paths** (Snap link) | Detected by the resolved path, handled only once. |
| **Identities without an account** (leftovers of deleted accounts) | Ignored. |
| **Different addresses, same file name after sanitizing** (`a+b@x.de` vs. `a_b@x.de`) | The file name contains a hash of the address – no collision. |
| **Account deactivated on the server / signature deleted** | The API then returns nothing; the agent reports "no signature on the server" and **leaves the local file unchanged** (nothing is deleted automatically). |
| **Error for one address** | Affects only that address; the others are still synced. The existing signature stays. (Exception: errors that hit all addresses – token, TLS, network, `429` – abort the run.) |

## Security (principles)

* **TLS is mandatory**, `http://` only with an explicit switch + a permanent warning. TLS ≥ 1.2; with `ca-file` only that CA.
* **No redirects** (the token never goes to another host); responses at most 8 MiB per page, HTML at most 1 MiB;
  fixed timeouts; at most 1000 entries per address.
* **The agent does not blindly trust the server's filter:** every entry is checked against the address. The
  `html_sha256` value is not defined in the server documentation and is therefore **not** used as an integrity check –
  protection comes from TLS and the HTML tripwire.
* **No guessing on ambiguity:** the same address on several accounts ⇒ change nothing.
* **Respecting the server's brute-force protection:** a wrong token costs at most one request per run; then the full interval.
* Text from server error messages is stripped of control characters and shortened before logging (no log injection).
* **Token** preferably from an environment variable or a file (warning if permissions are too open), never in the
  URL, never in the log. Reading the token from the operating system's keyring (recommended by the server
  documentation) is not built in yet.
* **HTML tripwire** (`html-policy=reject`): `<script>`, `<iframe>`, `<object>`, `<embed>`, `<form>`, `<base>`, `on…=`
  handlers, `javascript:`/`data:text/html`, meta refresh are rejected. This is an additional safeguard, **not** a
  full sanitizer – the server is considered trustworthy.
* **Read only, and write only inside the profile:** `prefs.js` is read, never written. Only
  `<profile>/subsignature/*` and the marked block in `user.js` are written (atomically via temp file + rename,
  symlinks of dotfile managers are preserved, mode 600).
* **On any error the old state stays** (server gone, TLS error, rejected HTML, no matching template, ambiguity).
* A lock prevents parallel runs (service + manual call).
* **Windows/Outlook:** no administrator rights; registry only below `HKEY_CURRENT_USER`, read-only except for four
  fixed value names that are checked against a pattern before every write; keys are never created; a redirected
  signature folder (`..\`) is rejected; `remove` does not blindly trust its own state file. Details: [`docs/WINDOWS.md`](docs/WINDOWS.md).
* **Removal:** `subsignature-agent remove` deletes everything the agent has set up and restores the previous default
  signature in Outlook.
* **Status reporting is a narrow, separate write:** `status:write` is its own token scope (never implied by
  `signatures:read` and vice versa); only `ok`/`warn`/`error` plus a short, length-capped message and a
  non-authenticating device id are sent — never signature content, and never a client-supplied timestamp (the
  server stamps `synced_at` itself).

## Tests

```bash
make all         # gofmt, go vet for Linux AND Windows, go test -race (181 test functions, 238 cases), build
make dist        # Linux amd64/arm64, Windows amd64/arm64
```

Included: configuration checks (also old element names, the same file for both systems), API client (paging, error
format, `Retry-After`, redirects, TLS with/without CA), selection rules, HTML check, `prefs.js`/`profiles.ini`/`user.js`
handling (also with Windows paths and line endings) and end-to-end tests with a rebuilt Thunderbird profile against
HTTP and HTTPS servers.

The **Windows side** is played through on Linux: an environment with `GOOS=windows`, an in-memory registry, files in a
temp folder. Checked among other things: finding accounts (POP/IMAP, Exchange, Outlook 2013 with binary values), files
and encoding, setting the default signature, a dry run without any write access, removal with restore, roaming
switches, the new Outlook, Thunderbird and Outlook together. This does **not** cover the part that really talks to Windows.

Fault injection: in 0.2.0, 16 places were deliberately broken (15 noticed, one without effect). For 0.3.0, 24 places
of the new logic were added; 23 were noticed at once, for one (name check on deletion) the test had to be tightened first.

## Still to be verified

**Windows** – confirmed on a real PC (Microsoft 365, IMAP): Thunderbird, Outlook signature files, default signature for
new messages and replies, updates, `remove`. The checklist is in [`docs/WINDOWS.md`](docs/WINDOWS.md). Open:

1. **Exchange accounts** (on-premises and Microsoft 365): the address is read from `Account Name`; does `status` find them?
2. Outlook 2016/2019/2021 without Microsoft 365, and Outlook 2013 (`REG_BINARY` values).
3. Umlauts and images in Outlook.
4. `install.ps1`, `uninstall.ps1`, autostart without a window (`subsignature-agentw.exe run`), `agent.log`.
5. The server's sync status with Thunderbird and Outlook on one PC (two devices, "2/2 up to date").

**Linux/Thunderbird** is in use by the project owner. Not confirmed individually:

1. Pick-up of a changed signature file **without** restarting Thunderbird.
2. Snap and Flatpak.
3. Embedded `data:` images; the API delivers remote images (`https://…`) as absolute URLs.
4. The systemd unit on a real systemd.

Open questions about the API are in [`docs/API.md`](docs/API.md).

## Ideas for later versions

**New Outlook:** an Outlook add-in served by the SubSignature server (the only way that works there) ·
encrypting the token with DPAPI / Credential Manager on Windows, keyring (libsecret) on Linux ·
signed `.exe` and MSI · mapping by `username` alone (alias and shared-mailbox addresses that are not stored on the account) ·
a token per user (the server returns only that user's addresses) · certificate pinning · `on-missing`: remove the
signature again when the account or signature is gone on the server · storing all variants as files · image embedding ·
`.deb`/`.rpm`/AppImage · autostart entry for systems without systemd · macOS.

## Sources behind the decisions

* Classic Outlook: Microsoft help "Outlook roaming signatures" (switch `DisableRoamingSignatures`, affected mailbox
  types); Slipstick and Petri on the account values `New Signature` / `Reply-Forward Signature` and the value
  `Signatures` under `Common\General`; older Microsoft forum posts on `REG_BINARY` in Outlook 2013.
* New Outlook: Microsoft Q&A (signatures live in the mailbox, no Graph interface), the Microsoft sample
  "Set your signature using Outlook event-based activation" (`setSignatureAsync`), vendor documentation (Exclaimer,
  CI-Solution): agents that write local files have no effect in the new Outlook.
* Thunderbird in the Microsoft Store: Mozilla Bugzilla 1878276 and the Mozilla forum (profile under `%LOCALAPPDATA%\Packages\MozillaThunderbird.…`).
* SubSignature API documentation `docs/API.md` (API v1, SubSignature 1.6.0): endpoints, fields, errors, limits and the
  recommendations for agents (query by e-mail, paging, change detection, token handling, running as the logged-in user,
  and — since 1.6.0 — the `POST /status` status-report endpoint).
* Mozilla help "Signatures": signature from a file (text or HTML). A Mozilla forum post additionally mentions that this file can be maintained centrally on a server.
* Mozilla help on profile locations; Mozilla forum on Snap/Flatpak paths.
* Mozilla Bugzilla 1986555 (comment) and forum posts on `sig_file`/`sig_file-rel`: both settings are stored, the relative one takes precedence according to the comment → the agent sets both.
* Mozilla forum (company rollout via WPKG): settings via `user.js` instead of editing `prefs.js` directly; Bugzilla 444476 shows the spelling of the identity settings.
* Mozilla Bugzilla 597060 on the profile lock (symlink `lock` with target `<host>:+<pid>`) – only for the hint "Thunderbird is running".
* NC Connector for Thunderbird (admin documentation): central signature only for identities with a matching address, others stay untouched – the same principle here.
* Commercial agent solutions also apply the signature locally with a small agent.
