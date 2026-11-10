# SubSignature - Security Review (release 1.5.0)

Scope: the complete PHP code base of the repository (`public_html/`, `private_data/`
layout, Apache configuration). Method: manual code review of every page, plus functional
checks of the fixes against a running instance (installer, login, CSRF behaviour, XSS
payloads, CSV import/export, token API) and unit tests of the LDAP importer with a
simulated directory.

Limits of this review: the LDAP client (`includes/LdapService.php`) was only syntax
checked because the `ldap` extension was not available in the test environment; the
import logic itself was tested with a fake directory. A penetration test with a real
browser matrix and a dependency audit of the bundled JavaScript libraries (Jodit, Ace) were
not part of this review.

## Findings in version 1.3.x and how they were resolved

| # | Severity | Finding | Resolution |
|---|----------|---------|------------|
| 1 | High | State-changing actions (delete one/all/selected signatures, activate/deactivate/promote/delete users, delete images/templates, template import) were reachable by **GET** links - CSRF by simply embedding an image or link. | All such actions are POST with a CSRF token (`requireCsrf()`, `js/post-action.js`). |
| 2 | High | Stored/reflected **XSS**: `?error=` / `?message=` parameters echoed into pages; signature data written into `innerHTML` (live preview, mail log stream); CSV import double-encoded values and previews trusted stored HTML. | Messages travel as session flash, never in URLs. Output uses `e()` everywhere; client side uses DOMParser-based `SafeHtml`; log lines use `textContent`; the stored template HTML is sanitized on the server before rendering. |
| 3 | High | Template HTML (admin-authored) was rendered unsanitized in every user's browser, and previews executed in the application origin. | `sanitizeTemplateHtml()` on save/import/render; preview and template loading are admin-only; previews run in a sandboxed iframe with a `sandbox` CSP. |
| 4 | High | SMTP password stored in plain text in the settings table. | Encrypted with libsodium/AES-GCM (`private_data/secret.key`, mode 0600); legacy plain values are still readable and re-encrypted on the next save. The same mechanism protects the LDAP bind password. |
| 5 | Medium | Weak session handling: sessions in the shared temp directory, no idle timeout, role changes and deactivation only effective at next login, no invalidation after a password change. | Private session directory, strict cookie flags, idle (15 min) and absolute (8 h) timeout, role/active re-read from the database per request, `pw_fp` password fingerprint ends other sessions on password change. |
| 6 | Medium | Brute-force protection kept in the session (bypassed by dropping cookies); user enumeration through timing and error texts. | Database backed throttling per IP and per username; dummy bcrypt verification for unknown users; the "deactivated" notice is shown only after a correct password. |
| 7 | Medium | No Content-Security-Policy; inconsistent headers. | Strict CSP on all pages (`'unsafe-eval'` only on the template editor, which needs it for the code editor), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, HSTS on HTTPS, `X-Powered-By` removed. |
| 8 | Medium | CSV export vulnerable to **formula injection** (`=`, `+`, `-`, `@` prefixes). CSV import without size limits. | `csvSafeCell()` neutralizes formula prefixes; import capped at 2 MB / 2000 rows with per-row validation inside one transaction. |
| 9 | Medium | Hard-coded privileged login name in `login.php`; open registration could not be disabled; registration rate limit counted page views. | Hard-coded login removed; `allow_registration` setting; creating accounts as admin requires an admin session; limit applies to POST only; password policy shared by all password forms. |
| 10 | Medium | Image upload relied on extension/MIME sent by the client; mail rollout could attach arbitrary paths. | Extension allow list plus content sniffing (`finfo`); file count/size caps; attachments restricted to `img/`. |
| 11 | Low | Legacy template handling: path checks by string comparison, `email_notification.html` listed as signature template. | Strict name validation (`isValidTemplateName`), `isPathInside()` via `realpath`, separate "editable" rule for the mail wrapper. |
| 12 | Low | Audit trail gaps and unbounded log growth. | Security events for admin actions, imports, token handling; retention via `LOG_RETENTION_DAYS`. |
| 13 | Low | `htmlspecialchars()` without flags (does not escape `'` on PHP < 8.1) in attributes. | Replaced by `e()` (`ENT_QUOTES | ENT_SUBSTITUTE`, UTF-8) everywhere. |
| 14 | Low | Several bugs: deactivated-account message never matched, administrator label shown to normal users, `{{PHONE_CLEAN}}` not replaced in downloads/mails. | Fixed. |

## Roles: administrator, technician, user (1.5.0)

The technician may use everything except **Users**, **System Configuration** and **System Logs**. Because that is a
partly trusted role, the review looked at how a technician could reach administrator rights, and closed these paths:

| Path | Control |
|------|---------|
| Direct URL / crafted POST to Users, System Configuration, System Logs, other users' profiles, user creation | `requireAdmin()` (server side, role re-read from the database per request); `isAdmin()` is true for administrators only. A technician is redirected and an `UNAUTHORIZED_ACCESS` event is logged. |
| Giving oneself or someone else a role | Only `admin_users.php` / `register.php?admin=1` (administrator only) write roles; the value is checked against a whitelist (`user`, `technician`, `admin`); public registration always creates `user`. Role changes are audit-logged. |
| Locking everybody out / removing the last administrator | Demote / deactivate / delete of an administrator only succeeds while another active administrator exists (inside the SQL statement, atomic). Own account cannot be changed on that page. |
| LDAP settings: redirecting the stored bind password to a rogue server or weakening certificate checks | Changing host, port, encryption, certificate verification, CA file or bind DN requires the bind password to be typed again (`LdapConfig::fromInput`); test / preview use the stored configuration only. The import cannot create users or roles. |
| Stored XSS through templates (a technician writes a template that an administrator opens) | `sanitizeTemplateHtml()` (tokenizer based, attribute rebuild, URL allow-list, raw-text/foreign elements removed, fail closed) on save, import, preview, send and render, plus the DOM based sanitizer in the browser; standalone previews run under a `sandbox` CSP, modal previews in `sandbox=""` iframes. 100+ attack strings (event handlers with odd separators, entity-encoded schemes, comment and raw-text tricks, SVG/MathML mutation vectors) were checked in a real browser: no script executes, output is idempotent. |
| Template or image upload leading to code execution | Template names are validated (`signature_*.html`), content with `<?` is refused, images are limited to JPG/PNG/GIF/WEBP with content sniffing and re-named files; no SVG, no PHP. |
| API tokens | Read-only scope (`signatures:read`) - a technician can already read all signatures, so a token gives no additional data; tokens are hashed, shown once, revocable and every creation / revocation is audit-logged. |
| Reading logs / users to cover tracks or find targets | Not reachable: logs, users and system configuration (SMTP, security settings) are administrator-only. The user drop-down in All Signatures lists usernames, which is needed to manage signatures. |

Remaining trust assumption: a technician can change templates that all users see and can read every signature. Assign the
role only to people who are allowed to do that. Their actions (template changes, imports, token handling, LDAP settings,
bulk deletes) are written to the audit log, which only administrators can read.

## Controls for the new features

**LDAP import**

* Import only - no code path authenticates against the directory.
* TLS certificate verification is on by default; LDAPS/STARTTLS; bind with an empty password is refused (it would be an anonymous bind).
* Attribute names and the filter are validated before use; the filter is a configuration value controlled by administrators, not by users.
* The import creates **signatures only** - never users, roles or passwords. A signature is assigned only to an existing, active user (chosen by the administrator or matched by email); only signatures with `source = 'ldap'` are ever updated, manually created signatures are never touched.
* Preview/apply separation: the plan is stored server side (private temp directory, random token, bound to the admin, 30 min lifetime); the selection is validated against the stored plan (only validated directory rows can be selected) and re-evaluated inside a transaction at apply time.
* All directory values are validated and escaped on output like any other input.

**All Signatures (filters, tags, bulk actions)**

* Every filter value is validated (whitelists for sort, source and colour, numeric tag id, length-limited text) and only bound as a prepared-statement parameter; the sort clause comes from a fixed map, never from user text.
* Normal users are always scoped to their own `user_id` on the server, whatever `user_id` says in the URL; bulk delete / template change add `AND user_id = ?` for them.
* Creating, deleting and assigning tags is limited to administrators and technicians (403 for others), POST + CSRF; tag names are restricted to letters, digits, spaces and `. _ - / &`, unique case-insensitively, and escaped on output. Colours are keys that map to CSS classes - no user-controlled CSS.
* "Delete All" uses the same WHERE clause as the list, so it removes exactly what is shown; destructive admin actions are audit-logged.
* Template changes only accept names of existing template files (no path input).
* The tag option of the CSV and LDAP import is restricted to administrators and technicians on the server too (ignored for everybody else); a new tag name goes through the same validation, the tag is created inside the import transaction (CSV) or right before it (LDAP), and the tag id is always bound as a parameter.

**Token API**

* 256-bit random tokens, stored as SHA-256 only, shown once, optional expiry, revocable.
* HTTPS enforced, read-only scope, per-IP failure throttling and per-token rate limit, no cookies/session, restrictive headers and a `default-src 'none'` CSP.
* Responses contain rendered, sanitized HTML; only active users' signatures are exposed.

## Residual risks and recommendations

* **Run behind HTTPS.** Without it, session cookies lose the `Secure` flag and the API refuses to work by design.
* **Administrators and technicians are trusted with templates.** Both can edit template HTML and configure the LDAP filter. Sanitizing is defence in depth, not a substitute for trust. Restrict access to the tooling by network if possible and give the technician role sparingly.
* **`secret.key` protects stored secrets.** Anyone who can read both the database and `secret.key` can decrypt the SMTP/LDAP passwords. Keep `private_data/` outside the web root with mode 0750 and back both up together.
* **Directory users do not get accounts.** Users who should log in to SubSignature must be created locally (or register); the LDAP import only fills their signatures.
* **Bundled JavaScript libraries** (Jodit, Ace, Font Awesome) are third-party code and need to be updated by the project maintainers; they were not audited here.
* **`install.php` is reachable until the first administrator exists.** Create the admin right after deployment, or remove the file.
* **No two-factor authentication** is implemented. Consider SSO/VPN in front of the application for sensitive environments.
* **SQLite** is file based: protect the data directory with correct file system permissions.
