# SubSignature - Security Review (release 1.4.0)

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

## Controls for the new features

**LDAP import**

* Import only - no code path authenticates against the directory.
* TLS certificate verification is on by default; LDAPS/STARTTLS; bind with an empty password is refused (it would be an anonymous bind).
* Attribute names and the filter are validated before use; the filter is a configuration value controlled by administrators, not by users.
* Directory data can only create/update accounts with `auth_source = 'ldap'` and role `user`; local accounts (including administrators) are never touched; new accounts have an unusable random password.
* Preview/apply separation: the plan is stored server side (private temp directory, random token, bound to the admin, 30 min lifetime); the import is a single transaction.
* All directory values are validated and escaped on output like any other input.

**Token API**

* 256-bit random tokens, stored as SHA-256 only, shown once, optional expiry, revocable.
* HTTPS enforced, read-only scope, per-IP failure throttling and per-token rate limit, no cookies/session, restrictive headers and a `default-src 'none'` CSP.
* Responses contain rendered, sanitized HTML; only active users' signatures are exposed.

## Residual risks and recommendations

* **Run behind HTTPS.** Without it, session cookies lose the `Secure` flag and the API refuses to work by design.
* **Admins are trusted.** Administrators can edit templates (HTML) and configure the LDAP filter. Sanitizing is defence in depth, not a substitute for admin trust. Restrict admin access by network if possible.
* **`secret.key` protects stored secrets.** Anyone who can read both the database and `secret.key` can decrypt the SMTP/LDAP passwords. Keep `private_data/` outside the web root with mode 0750 and back both up together.
* **Imported LDAP users have no usable password.** An administrator can set one if a directory user should also use the local login.
* **Bundled JavaScript libraries** (Jodit, Ace, Font Awesome) are third-party code and need to be updated by the project maintainers; they were not audited here.
* **`install.php` is reachable until the first administrator exists.** Create the admin right after deployment, or remove the file.
* **No two-factor authentication** is implemented. Consider SSO/VPN in front of the application for sensitive environments.
* **SQLite** is file based: protect the data directory with correct file system permissions.
