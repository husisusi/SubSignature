# Changelog

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
