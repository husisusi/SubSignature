# Changelog – SubSignature Agent

## 1.0.0-rc2

### Added
- **Device name with every request.** The agent sends its installation ID (host name plus a random suffix, the same
  ID that `status` shows and that status reports use) in the header `X-SubSignature-Device` with every API request.
  SubSignature 1.8.0 shows it under **System Logs -> API Requests**, so the administrator sees which PC fetched
  signatures, not only the program name. The header is informational only; the server never uses it to authenticate
  or decide anything. Invalid values are never sent.
- A real `sync` creates the installation ID on its first run (before, only when status reporting was on). A dry run
  (`check`) and `ping` use an existing ID but never create one.

### Changed
- Documentation: the header is described in `README.md` and `docs/API.md`; vendor names were removed from the
  sources section of `README.md`.
- Tests: 5 new test functions (header on GET and POST, invalid values, dry run, ping).

### Compatibility
- Works with every SubSignature server version: older servers ignore the header.

## 1.0.0-rc1

Release candidate for the first stable version. No functional changes compared to 0.6.1-beta.

- Windows confirmed by the project owner on a real PC with Thunderbird and classic Outlook from Microsoft 365 (IMAP
  account): signature files, default signature for new messages and replies, updates after a change on the server,
  `remove`.
- Documentation: status and checklists updated (`README.md`, `docs/WINDOWS.md`), this changelog added.
- What is still open before 1.0.0 is listed under "Still to be verified" in `README.md`.

## 0.6.1-beta

### Fixed
- **Outlook (Microsoft 365) ignored the agent:** signature updates did not arrive, `remove` had no effect, the default
  signature stayed off (field report with 0.6.0, IMAP account). Cause: Outlook's **roaming signatures**, which the
  agent left on for IMAP/POP. They are now switched off by default (`<roaming-signatures>disable</roaming-signatures>`,
  only for Office versions where the agent's signature file is in place; `remove` restores the previous values).
  **Configurations created by `init` before 0.6.1 say `keep` - change that line to `disable`.**

### Added
- Running Outlook is detected (own Windows session only): `sync` says that changes apply after an Outlook restart,
  `status` shows it, `remove` leaves Outlook alone until it is closed (Thunderbird is cleaned up anyway).
- `sync` and `status` report when the Outlook signature file was overwritten by something else
  ("CHANGED OUTSIDE THE AGENT"); the next sync rewrites it.
- `sync` and `status` warn when a group policy or a leftover setting (`Common\MailSettings`, `NewSignature` /
  `ReplySignature`) fixes the default signature. The agent never writes there.
- `uninstall.ps1` stops if Outlook is running or `remove` fails, so `remove` can be run again.

## 0.6.0-beta

### Fixed
- **Outlook 2016 and later did not use the signature as the default** (listed, but not selected for new messages and
  replies): the value was written as `REG_BINARY` when the account's other values were binary (typical for IMAP).
  Outlook 2016+ only reads `REG_SZ`; values written by 0.5.0 are corrected by the next sync, `status` flags them.

### Added
- Every mail client is reported to the server as its own device (`<device ID> Thunderbird`, `<device ID> Outlook`):
  "2/2 up to date" with both on one PC, and an error in one client no longer marks the other as failed. `status` shows
  the names under `Reported as:`. Reports of 0.5.0 under the bare device ID stay on the server until its
  "forget silent devices" period has passed.

## 0.5.0-alpha

### Added
- The status report sends the version that was applied (`html_sha256`), so the server (SubSignature 1.7.0) can show
  "up to date" / "out of date" per device.
- `status` shows the device ID and whether status reporting is on.

### Changed
- The last German program output is now English.

## Earlier versions (0.1.0 – 0.4.0-alpha)

0.1.0 ran against a self-designed contract; the move to the real SubSignature API v1 is summarized under "History" in
[`docs/API.md`](docs/API.md). Since 0.4.0 documentation, comments and all program output are in English. The status
report to the server (`POST /api/v1/status`, scope `status:write`, `<report-status>`) was added for SubSignature 1.6.0.
