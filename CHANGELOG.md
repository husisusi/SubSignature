# Changelog

## 1.8.0

### Added (System Logs: API requests of the clients)
- **New tab System Logs -> API Requests.** Every request of a client - the desktop agent (Outlook / Thunderbird, Windows and Linux), the HCL Domino agent or your own scripts - is logged with time, result, endpoint, token, client (device name for status reports, otherwise the program's User-Agent), IP address, number of signatures and duration.
- **Exact reason for refused requests.** The client still only receives a generic `unauthorized`; the log shows whether no token was sent, the token is unknown, **revoked** or **expired** - so an agent that still uses an old token is found in seconds.
- **"Clients in the last 24 hours"** overview on the same tab: one row per client, token and address with last-seen time, number of requests and errors.
- New statistic **API Requests (24h)** (with the number of errors) on the System Logs page; filter **Only errors**.
- **Admin -> Configuration -> API request log:** log *all requests* (default), *only errors* or *off*, and keep them 1-365 days (default 30).

### Added (API: device name and embedded images)
- **Device name in the API log.** Clients can send the header `X-SubSignature-Device`; the desktop agent 1.0.0-rc2 sends its installation ID with every request, so **API Requests** shows which PC fetched signatures (before, only status reports carried a device name). Informational only.
- **Images of a signature Base64-encoded through the API**, for clients that cannot download images themselves (HCL Notes/Domino):
  - `GET /api/v1/signatures?images=meta` lists every image of a signature (`src` as in the HTML, status, SHA-256, type, size); `images=inline` also returns the data, once per image and response.
  - `GET /api/v1/images/{sha256}` returns one image - for clients with small response limits.
  - Images from **Manage Images** (`img/...`) and `data:` images are always delivered; images on other servers only from the hosts listed under **Admin -> Configuration -> Image hosts for embedding** (empty by default).
- System status: the `curl` extension (optional, needed for images from other hosts).

### Changed (messages)
- **All messages look the same on every page.** Success messages are green, errors red, warnings yellow and notes blue - with the same box, icon and position at the top of the page, in light and dark mode. This fixes **System Configuration**, where "Configuration saved successfully." (and other messages) appeared as plain text, and the same problem on **API Tokens**, **Images** and **Templates**.
- One shared implementation: `alertBox()` / `flashAlerts()` in PHP and `js/alerts.js` for messages created in the browser. The pages' own message styles (login, installer, export, CSV import, user management, ...) were removed.
- Browser pop-ups (`alert()`) for errors and hints (copy failed, template name missing, CSV file too large, passwords do not match, CSV requirements) are now shown as the same in-page message.
- Messages on Images and Templates no longer disappear after 5 seconds; an error stays until you leave the page, as everywhere else.
- The CSV import result page starts with a summary message (green, or yellow when rows failed).
- Messages no longer carry their own emoji (the icon of the message box shows the type); the four affected texts were renamed in all languages, their translations are kept.

### Security / privacy
- **No request leaves your server from the interface.** All assets (scripts, styles, icons) were already hosted locally; the template editor now also pins Jodit's optional helpers explicitly: the code editor (Ace) is loaded from this server, the external HTML beautifier and Google Fonts are switched off. Before, they were only blocked by the Content-Security-Policy.
- `Permissions-Policy` additionally disables the browser's ad-topic API (`browsing-topics=()`).
- API log: the token itself is never stored (only its ID and label), query values are shortened, only known parameters are recorded. Refused requests from a blocked address or a throttled token are recorded at most once per minute, and the table is capped (retention setting plus at most 200,000 rows), so the log cannot be flooded.
- System Logs show all times converted from the database's UTC to the server's time zone.
- Image embedding cannot be used to reach internal systems: remote images only over https from listed host names (no IP literals, ports or user names), no redirects, no proxy, the host's addresses must all be public (no loopback, private, link-local, carrier-grade NAT, multicast, documentation or reserved ranges) and the checked address is pinned for the connection (no DNS rebinding). Size limit 1 MiB, PNG/JPEG/GIF detected from the content (SVG is never delivered), at most 3 new downloads per request, results cached (24 h, failures 10 min). Changes to the host list are written to the audit log.

### Changed (requirements)
- **PHP 8.0 or newer** is now the documented requirement (as in the README badge); the installer checks for it. PHP 7.4 no longer receives security fixes from the PHP project - an existing installation on 7.4 keeps running, the system status panel shows a warning.

### Added (database)
- Schema v8: table `api_request_log`, settings `api_log_mode` and `api_log_retention_days`.
- Schema v9: table `image_cache`, setting `image_embed_hosts`.

### Changed (documentation)
- README rewritten for clarity and search: what SubSignature is in one sentence, central signature management and the desktop clients for Windows and Linux first in the feature list, a FAQ, and consistent requirements (PHP 8.0+).
- `docs/API.md`: how API requests are logged, the device header, embedded images. `docs/SECURITY_REVIEW.md`: controls for 1.8.0.
- The 41 new interface texts are translated into all 18 languages.

### Upgrade notes
- Copy the files, keep `private_data/`, reload once. The migration to schema v8 runs automatically; logging starts with the next API request.
- The desktop agent works unchanged; update to 1.0.0-rc2 to see the PC names of signature fetches in the API log.

## 1.7.0

### Added (sync status)
- **"Out of date" after an edit.** The agent now reports which version of a signature it applied (`html_sha256`); All Signatures compares it with the current version. As soon as a signature - or its template, or the company details - changes, the badge turns yellow **Out of date** and turns green again once the agent has fetched and applied the new version.
- **Several devices per signature.** Every agent installation (device) is tracked separately; the badge counts them, e.g. **2/2 up to date** or **1/3 up to date**. With one device it names the state (*Up to date*, *Out of date*, *No recent sync*, *Synced with warning*, *Sync error*).
- **Sync details dialog:** click a badge to see every device with its state, last report time, agent version and message (also works on touch screens, where tooltips do not exist).
- **Admin -> Configuration: forget silent devices after N days** (`status_device_retention_days`, default 30, 1-365) - a replaced laptop stops counting and is removed.
- Agent 0.5.0-alpha: sends `html_sha256` with every status item; `subsignature-agent status` shows the device ID (the name in the server's device list) and whether status reporting is on.

### Fixed
- **API Tokens page aborted with "An internal error occurred"** (1.6.0): a translation helper was called without its parameters. Fixed; `eth()` now tolerates a missing parameter list so this cannot break a page again.
- **Edit signature dialog:** the text fields showed a dropdown arrow; they are plain text fields now.
- Agent: the last German program output (`status` header, a configuration error) is now English.

### Added (database)
- Schema v7: table `signature_device_status` (one row per signature and device, with `html_sha256`), replacing 1.6.0's `signature_sync_status`; existing reports are carried over. Setting `status_device_retention_days`.

### Security / behaviour
- At most 25 devices are stored per signature and silent devices are pruned, so a `status:write` token cannot grow the table without bound.
- `html_sha256` is validated (64 hex characters) and only compared with the server's own hash; it never affects what clients receive.

### Changed
- `POST /api/v1/status`: optional `items[].html_sha256`; reports are stored per `device_id`.
- Docs: `docs/API.md`, `README.md`, `docs/SECURITY_REVIEW.md`, `subsignature-agent/README.md` and `subsignature-agent/docs/API.md` (which had not mentioned the status report yet).
- The 15 new interface texts are translated into all 18 languages.

### Upgrade notes
- Copy the files, keep `private_data/`, reload once. The migration to schema v7 runs automatically and keeps the 1.6.0 status reports (they show as the device that reported them).
- Update the agents to 0.5.0 to get "Out of date" detection for template and company-detail changes; agents from the 1.6.0 package (0.4.0-alpha) keep working, but for them only edits of the signature itself are detected (by comparing timestamps).

## 1.6.0 (Never Released)

### Added (desktop agent integration)
- **The desktop agent now reports back.** After a real sync (not `check`), the Go agent (`subsignature-agent/`, Windows and Linux) tells the server whether each signature it applied actually worked - `ok`, `warn` (e.g. no matching Outlook account) or `error` - via the new `POST /api/v1/status` endpoint. Configurable per install with `<report-status>` in `config.xml` (default on); a dry-run `check` never reports, and neither does an aborted/rate-limited run.
- **New API token scope `status:write`**, separate from `signatures:read`. **Admin -> API Tokens** now shows a checkbox per scope instead of a single implied one; a token can have either, both, or be revoked independently of the other.
- Agent: a stable per-install `device_id` (random, generated once with `crypto/rand`, kept in the local state file) is sent with every status report so the admin can tell installs apart; it is never used for authentication.

### Added (All Signatures)
- **Edit a single signature** directly from All Signatures (pencil icon): name, role, email, phone and template, plus tags for administrators and technicians. Normal users can edit their own signatures. Editing an LDAP-sourced signature warns that the next LDAP re-import will overwrite the change.
- **Sync-status badge** on every signature (grey = never reported, green = synced and fresh, yellow = synced but outdated or reported a warning, red = the agent reported an error), with a tooltip showing the last report time, device and message.
- **Admin -> Configuration: sync freshness window** (`status_freshness_hours`, default 6, 1-168) - how long a successful report stays "green" before turning "yellow".

### Added (database)
- Schema v6: new table `signature_sync_status` (one row per signature, written only by `POST /api/v1/status`), setting `status_freshness_hours`. Migrated automatically.

### Security / behaviour
- **Closed a defense-in-depth gap in the new edit action:** `update_one`'s `UPDATE` statement now repeats the same `AND user_id = ...` ownership condition that `delete_one` already enforced directly on its SQL statement, instead of relying only on a `SELECT` check beforehand; a `0`-row update rolls back and reports "not found". Found and fixed before release - see `docs/SECURITY_REVIEW.md`.
- `POST /api/v1/status` can only write the sync-status columns of a signature that already exists, never its content; all fields are validated and length-capped server-side, timestamps are server-set, and it has its own, smaller rate-limit bucket.

### Changed
- `docs/API.md` rewritten: no longer describes a hypothetical Python agent - it documents the real Go agent that already exists, plus the new `POST /api/v1/status` endpoint and the `status:write` scope.
- The 23 new interface texts (edit dialog, sync-status badges and tooltips, the freshness-window setting, token permission checkboxes) are translated into all 18 languages.

### Upgrade notes
- Copy the files, keep `private_data/`, reload once. The migration to schema v6 runs automatically.
- Existing API tokens keep their current scope (`signatures:read`); grant `status:write` explicitly to any token whose agent should report sync status.
- Agents built before 1.6.0 keep working against the read endpoints unchanged; update them (and give their token the `status:write` scope) to get the sync-status badge filled in.

## 1.5.0

### Added
- **Multi-language interface (18 languages):** en, de, es, fr, it, pt, nl, pl, tr, ru, uk, ar (right-to-left), hi, id, zh, ja, ko and bs (Bosanski). One JSON file per language in `public_html/lang/`; English text is the key, missing keys fall back to English. New module `includes/i18n.php` (`t()`, `et()`, `eth()`, `tj()`, `langSwitcher()`, ...).
- Language detection (cookie, then browser, then administrator default), language switcher in the sidebar and on the login / install pages (`set_language.php`, POST + CSRF), per-user language stored in `users.language`, system-wide default language in Admin -> Configuration.
- RTL layout support (`dir="rtl"`, mirrored sidebar and controls); signature previews always stay left-to-right.
- Template editor follows the interface language (Jodit).
- **Company-wide placeholders** `{{COMPANY}}`, `{{WEBSITE}}`, `{{ADDRESS}}`, `{{DISCLAIMER}}`, maintained in Admin -> Configuration -> Company details; usable in every template, in the generator preview, downloads and mails.
- **System status** panel in Admin -> Configuration (PHP version/extensions, writable directories, data directory location, secret key, installer leftovers).
- Drop-in languages: a new `lang/<code>.json` appears in the menu automatically once `"name"` (and optionally `"dir": "rtl"`) is set in its `@meta` block; no code change needed.
- Contributor tooling: `tools/i18n.php` (`extract`, `check`, `new <code>`, `sync`) and `docs/TRANSLATING.md`.

### Added (roles)
- **New role "Technician"** between user and administrator. A technician has access to everything except **Users**, **System Configuration** and **System Logs**: template editor / manager, images, template backup, LDAP import, API tokens, sending signatures, All Signatures for all users (filters, bulk actions, tags), CSV import / export and ZIP download for any user. The role matrix is in the README (*Roles*).
- Administrators assign the role under **Users -> Change role** (modal with User / Technician / Administrator; replaces the promote / demote buttons) and when creating a user (new *Role* field). Public self-registration always creates a normal user, whatever is posted.
- The sidebar shows the role (Administrator / Technician / User); the admin block of the menu is split so a technician only sees the entries they may use; the Users page has a *Technicians* counter.
- Central helpers in `includes/config.php`: `isAdmin()` (administrators only, unchanged meaning), `isTechnician()`, `isStaff()`, `requireStaff()`, `requireAdmin()`, `roleLabel()`; an unknown role value counts as "user".
- No schema change: `users.role` simply accepts the value `technician`.

### Added (imports)
- **Tag for imports:** the CSV import and the LDAP import can put an existing or a new tag on every imported signature (administrators only; a new tag is created when the import runs, not while previewing). The tag shows up in All Signatures and can be used as a filter.
- **LDAP import: sortable preview** - click a column header (status, name, email, role, phone, assigned user) to sort; the selection is kept.
- **LDAP import: green "Import successful" summary** with created / updated / unchanged / tagged counts and a link to the imported signatures. (The message was shown before, but the page had no styling for it.)
- Docs: the desktop agent is now planned in **Python** for **Windows, Linux and macOS** (docs/API.md rewritten accordingly); Bosnian (`bs.json`) is listed as the 18th language.

### Added (signature overview)
- The sidebar entry **"My Signatures" is now "All Signatures"**.
- **New filters** in All Signatures: by **template** (only templates in use, with counts), by **tag** (including "Without tag") and by **source** (manual / CSV / LDAP), plus sorting (newest, oldest, name, email, template). The filter state survives infinite scroll, deleting and bulk actions; template and source badges on each signature are clickable filters.
- **Tags:** coloured labels managed by administrators (Manage tags; 1-32 characters, 8 colours, max. 100), bulk *Add tag* / *Remove tag*, shown as chips on each signature. Normal users see the tags of their own signatures read-only.
- **Bulk "Change template"** for the selected signatures (administrators: any, users: their own).
- Database schema v5: tables `signature_tags` and `signature_tag_map`, indexes on `template` and `source`; migrated automatically.

### Security / behaviour
- **"Delete All" now deletes exactly the signatures the current filter shows** (previously the whole selected user scope, even when a search was active). The audit log records the scope and the number of deleted signatures.
- Tag operations are administrator-only on the server side (403 otherwise), POST + CSRF, prepared statements only; colour and sort values are whitelisted, tag names are validated and always escaped; template changes accept only existing template files.

### Security (roles and templates)
- Every privileged page and action checks the role on the server: the Users, System Configuration and System Logs pages (and every POST action on them) stay administrator-only; a technician who requests them is redirected and an `UNAUTHORIZED_ACCESS` event is written to the audit log. Role changes are audit-logged (`ADMIN_ROLE_CHANGED`, old and new role).
- **Last administrator protection is now atomic:** demoting, deactivating or deleting an administrator only succeeds while another active administrator exists (checked inside the SQL statement, so two administrators acting at the same moment cannot lock the system out).
- **LDAP bind password:** changing server, port, encryption, certificate verification, CA file or bind DN now requires entering the bind password again; the stored password is never sent to a changed connection. This prevents anyone who may edit the LDAP settings from redirecting the service account to a rogue server.
- **Template sanitizer rewritten (`sanitizeTemplateHtml()`).** The old regular-expression filter could be bypassed (for example `<img/onerror=...>`, `<img src="x"onerror=...>`, `<svg/onload=...>`, a `>` inside an attribute value, HTML-entity encoded `javascript:` URLs, `<!-->` comment tricks). The new one tokenises the HTML, rebuilds every tag from the attributes it actually parsed (always double-quoted), drops `on*` and `srcdoc`, allow-lists URL schemes (`data:` only for raster images), cleans `<style>` blocks and `style=""` attributes, removes scripts, frames, plug-ins, forms, SVG/MathML, templates and other raw-text elements together with their content, escapes an incomplete `<` and fails closed. It runs on save, import, preview, send and render, so templates stored by older versions are cleaned as well, and the finished signature is sanitized again after the placeholders are filled in. Checked with 100+ attack strings in a real browser (no script execution, idempotent); the shipped templates render unchanged.
- The browser-side sanitizer (`js/safe-html.js`) uses the same URL allow-list, also removes SVG/MathML, `<template>`, media and raw-text elements and cleans `<style>` text.
- Inline `<svg>` / MathML, `<title>`, `<link>`, `<form>` and media elements are removed from templates (mail clients do not render them anyway).

### Changed
- **LDAP import reworked - signatures only.** The import no longer creates, updates or deactivates user accounts; it creates signatures from the directory data (name, role, email, phone). The options "Create a signature for each user", "New accounts are active" and "Deactivate accounts missing in the directory" were removed.
- **Selection in the preview:** choose which directory entries are imported (checkboxes, filter, *Select all* / *Only new and changed* / *Select none*, live counter).
- **Target user dropdown:** assign the imported signatures to a specific SubSignature user, or *Automatically by email address* (matches the active user with the same email, others are skipped). Preselected from the new configuration value "Assign signatures to".
- **Template dropdown:** choose the template for imported signatures (default: system default template); optionally apply it to signatures that were imported earlier.
- Re-import is idempotent: imported signatures remember the directory's unique ID (or DN) and are updated instead of duplicated; manually created and CSV-imported signatures are never touched. The target/template can be changed in the preview without querying the directory again.
- The directory result is limited to 5000 entries per run, with a notice when truncated.
- Database schema v4 (`user_signatures.ldap_key`); migrated automatically on first request.
- Database schema v3 (`users.language`); migrated automatically on first request.
- `.htaccess` also denies direct access to `/lang/`.
- README credits list the licence of each third-party asset.

### Upgrade notes
- Copy the files (for example `rsync -avc`), keep `private_data/`, reload once with Ctrl+F5. The migrations to schema v3, v4 and v5 run automatically.
- The technician role needs no migration. Existing users keep their role; assign the new role under Users -> Change role.
- The stricter template sanitizer is applied when a template is rendered. If a template of yours used inline SVG, `<link>` or `<title>`, re-check its preview.
- Changing the LDAP server, port, encryption, certificate settings or bind DN now asks for the bind password again.
- Nginx users: add `/lang/` to the deny list.
- Users that were created by an earlier LDAP import stay as they are (they can be kept or deleted under Admin -> Users); the import does not touch accounts any more.
- The translations are machine-quality; native-speaker review is welcome.

## 1.4.0

### Added
- LDAP / Active Directory **import** (no LDAP login): presets, free attribute mapping, LDAPS/STARTTLS with certificate verification, test connection, preview before import, transactional apply, optional signature creation, optional deactivation of accounts that left the directory.
- Read-only **token API** (`/api/v1/`) and token management (Admin -> API Tokens) as preparation for the Outlook/Thunderbird desktop agent; documentation in `docs/API.md`.
- Central bootstrap (`includes/bootstrap.php`), versioned database migrations (`PRAGMA user_version`), optional `private_data/config.local.php`.
- DB-backed rate limiting, audit events for admin actions, log retention.
- Encrypted storage of the SMTP and LDAP bind passwords.
- Option to disable self-registration.
- Light / dark / system **colour theme** (`css/theme.css`, `js/theme.js`) with a switch in the sidebar; template editor and signature previews are theme-aware (previews stay white). Works in Chrome, Firefox and Safari; Jodit and Ace follow the theme.
- **Cache busting:** all local CSS/JS URLs carry `?v=<file mtime>` (`assetUrl()` in `includes/helpers.php`) and `.htaccess` sends `Cache-Control: no-cache` for `*.css` / `*.js`, so browsers never keep a stale stylesheet after an update (a cached old `style.css` combined with the new theme showed white elements in Firefox).
- `docs/SECURITY_REVIEW.md`, `SECURITY.md`, `private_data/config.local.php.example`.

### Security
- All state-changing actions are POST + CSRF protected (previously many were GET links).
- Content-Security-Policy and a complete set of security headers; sandboxed template preview.
- XSS fixes (reflected messages, `innerHTML` sinks, CSV double encoding), server- and client-side HTML sanitizing for templates.
- Hardened sessions (private directory, idle/absolute timeout, DB re-validation per request, invalidation on password change).
- Brute-force protection per IP and per username; no user enumeration by timing or messages.
- CSV formula-injection protection, import limits, upload validation.
- Removed a hard-coded privileged login name.
- Apache: dotfiles/databases/logs denied, `Authorization` header passed through, API routing.

### Fixed
- "Account deactivated" notice never shown; wrong "Administrator" label for normal users; `{{PHONE_CLEAN}}` not replaced in downloads and mails; `email_notification.html` listed as a signature template; registration rate limit counted page views; typo in the default template image URL.

### Changed
- All code comments are in English. The UI layout is unchanged (small fixes only).
- Rollout and bulk download no longer use unauthenticated or GET-driven batches.

### Removed
- Unused/legacy files: `template_manager.php`, `clear_preview.php`, `clear_import_session.php`, `get_signature_count.php`. `login.php` now redirects to `index.php`.

### Upgrade notes
- After copying the files, reload once with Ctrl+F5 (Ctrl+Shift+R) if the layout still looks wrong; later updates refresh automatically.
- Back up `private_data/` first. The database is migrated automatically on first request.
- Back up `private_data/secret.key` together with the database from now on.
- CSV rows imported with earlier versions were stored HTML-encoded; re-import them if they show `&amp;`-style text.
