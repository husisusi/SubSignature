# Changelog

## 1.5.0

### Added
- **Multi-language interface (17 languages):** en, de, es, fr, it, pt, nl, pl, tr, ru, uk, ar (right-to-left), hi, id, zh, ja, ko. One JSON file per language in `public_html/lang/`; English text is the key, missing keys fall back to English. New module `includes/i18n.php` (`t()`, `et()`, `eth()`, `tj()`, `langSwitcher()`, ...).
- Language detection (cookie, then browser, then administrator default), language switcher in the sidebar and on the login / install pages (`set_language.php`, POST + CSRF), per-user language stored in `users.language`, system-wide default language in Admin -> Configuration.
- RTL layout support (`dir="rtl"`, mirrored sidebar and controls); signature previews always stay left-to-right.
- Template editor follows the interface language (Jodit).
- **Company-wide placeholders** `{{COMPANY}}`, `{{WEBSITE}}`, `{{ADDRESS}}`, `{{DISCLAIMER}}`, maintained in Admin -> Configuration -> Company details; usable in every template, in the generator preview, downloads and mails.
- **System status** panel in Admin -> Configuration (PHP version/extensions, writable directories, data directory location, secret key, installer leftovers).
- Contributor tooling: `tools/i18n.php` (`extract`, `check`, `new <code>`, `sync`) and `docs/TRANSLATING.md`.

### Changed
- Database schema v3 (`users.language`); migrated automatically on first request.
- `.htaccess` also denies direct access to `/lang/`.
- README credits list the licence of each third-party asset.

### Upgrade notes
- Copy the files (for example `rsync -avc`), keep `private_data/`, reload once with Ctrl+F5. The migration to schema v3 runs automatically.
- Nginx users: add `/lang/` to the deny list.
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
