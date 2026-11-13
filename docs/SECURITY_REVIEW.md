# SubSignature - Security Review (release 1.5.0, updated for 1.6.0 and 1.7.0)

The findings and role analysis below cover the code base as of 1.5.0. The 1.6.0 additions
(single-signature editing, the sync-status badge and its `POST /api/v1/status` endpoint,
multi-scope API tokens) and the 1.7.0 changes (per-device sync status with version
comparison) were reviewed separately; see "Findings addressed before the 1.6.0 / 1.7.0
release" and "Controls for the 1.6.0 / 1.7.0 features" further down, which extend rather
than replace the sections above them.

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
| API tokens | A technician can grant a token `signatures:read` and/or `status:write`. `signatures:read` gives no additional data (a technician can already read all signatures); `status:write` only ever lets a request overwrite the four sync-status columns of a signature row that already exists - never its content, never other tables. Tokens are hashed, shown once, revocable and every creation / revocation / scope choice is audit-logged. |
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

## Findings addressed before the 1.6.0 release

| # | Severity | Finding | Resolution |
|---|----------|---------|------------|
| 15 | Medium | The new single-signature edit (`update_one`) checked ownership with a separate `SELECT` before the `UPDATE`, the same pattern used elsewhere in the code base - but, unlike `delete_one`, the `UPDATE` statement itself did not repeat the `user_id` condition, leaving a (narrow, same-request) window between check and act. | The `UPDATE` now carries `AND user_id = :uid` directly (when the request is scoped to one user), matching `delete_one`; a post-update `$db->changes() === 0` check rolls the transaction back and reports "not found" instead of silently succeeding on zero rows. |

## Findings addressed in 1.7.0

| # | Severity | Finding | Resolution |
|---|----------|---------|------------|
| 16 | Low (availability) | 1.6.0's API Tokens page called the HTML translation helper `eth()` without its parameter array; the resulting `ArgumentCountError` reached the global exception handler, which aborts the page ("An internal error occurred") - the token list and its revoke/delete buttons were no longer reachable. No data exposure. | The call uses `et()`; `eth()` now defaults its parameters to `[]`, so the same mistake elsewhere degrades to plain escaped text instead of aborting the page. |
| 17 | Low (resource use) | With per-device status rows, a holder of a `status:write` token could invent unlimited `device_id` values and grow the status table without bound. | At most 25 devices are kept per signature (the most recently reporting ones); devices silent for longer than the retention setting (default 30 days, 1-365) are deleted on every status report and with the regular log cleanup. |

## Controls for the 1.6.0 features

**Single-signature edit (`update_one`)**

* Same role scoping as the rest of All Signatures: normal users can only edit their own signature; the owner is re-verified on the actual write (see finding 15), not only in the form shown to the user.
* Tag assignment on edit is restricted to administrators and technicians on the server, independent of whether the field is shown in the form; tag ids are validated against `signature_tags` before being written.
* Editing an LDAP-sourced signature is allowed (it is still the administrator's/technician's/user's own row) but the UI warns that a future LDAP re-import overwrites manual changes - the import logic itself is unchanged and still only updates rows with `source = 'ldap'`.
* POST + CSRF like every other state-changing action here; validation (name/role/email/phone format and length) reuses the same `validateSignatureFields()` as signature creation.

**Sync-status badge and `POST /api/v1/status`**

* The endpoint needs its own `status:write` scope, separate from `signatures:read` - a token leaked from an agent's config can be scoped to read-only or status-only, never both by default, so a compromised read token cannot inject fake status and a compromised status token cannot read signature content.
* The write is narrow by construction: the `UPSERT` only ever targets the status table (`signature_device_status` since 1.7.0: `status`, `message`, `agent_version`, `html_sha256`, `synced_at` per `signature_id` + `device_id`) for a `signature_id` that already exists in `user_signatures` (the `SELECT ... WHERE id = :id` source produces no row otherwise); it cannot create, rename or change the content of a signature.
* All fields are validated server-side (length caps, character allow-lists, `status` restricted to `ok`/`warn`/`error`, at most 200 items and 64 KiB per request) before anything is written; `device_id`/`agent_version` are free text shown only in an admin tooltip, escaped on output like any other field, and never trusted for authentication.
* The timestamp (`synced_at`) is set by the server (`datetime('now')`), not taken from the request - an agent (or an attacker replaying a captured request) cannot backdate or future-date a status report.
* The endpoint has its own, smaller rate-limit bucket (120/min per token) so it cannot be starved by - or starve - ordinary read traffic from the same rollout.
* The admin-configurable freshness window (`status_freshness_hours`, used only to colour the badge) is validated and clamped server-side (1-168) in `admin_config.php`; an out-of-range value cannot be stored.

## Controls for the 1.7.0 features

**Per-device status and version comparison**

* The reported `html_sha256` must be exactly 64 hex characters; it is only ever compared (`hash_equals`) with the server's own hash of the current HTML and shown as "up to date"/"out of date". A forged value can at worst make a badge wrong - which a `status:write` token could already do - it never influences what any client receives.
* "Out of date" is computed from the server's rendered HTML (`renderStoredSignature()` - the same function the API uses), so template and company-detail changes are detected without trusting the client.
* The sync-details dialog builds its table with `textContent` from a JSON block (`JSON_HEX_TAG|APOS|QUOT|AMP`), so device ids and messages from agents cannot inject markup; the tooltip text goes through `e()`.
* The device retention setting (`status_device_retention_days`) is validated and clamped server-side (1-365).
* Migration from 1.6.0 copies the old one-row-per-signature table into the new per-device table inside the migration transaction and then drops it.

## Controls for the 1.8.0 features

**API request log (System Logs -> API Requests)**

* Written in exactly one place (`apiRespond()`), so every response - successful or refused - is logged the same way; logging is best effort and can never fail or change a response.
* The bearer token is never stored. Rows contain the token's ID and a snapshot of its label; for refused requests the exact internal reason (`token_missing`, `token_unknown`, `token_revoked`, `token_expired`) is logged while the client still only receives the generic `unauthorized` - the log helps the administrator without telling an attacker whether a guessed token exists.
* Only the path and the known query parameters (`username`, `email`, `updated_since`, `limit`, `offset`, values shortened to 64 characters) are recorded; every text field is cleaned and length-capped before it is stored and escaped on output.
* Flooding: a blocked address (too many invalid tokens) or a throttled token is recorded at most once per minute and reason; rows older than the retention setting (1-365 days, default 30) are pruned on about 1 % of API requests and with the regular log cleanup; a hard cap keeps at most 200,000 rows. Logging can be limited to errors or switched off.
* The page is administrator-only like the rest of System Logs; the client overview groups by device/User-Agent, token and address only.

**Embedded images (`images=meta|inline`, `GET /api/v1/images/{sha256}`)**

This is the only place where the server makes outgoing HTTP requests on behalf of an API client, so it is built against server-side request forgery (SSRF):

* Image URLs come only from the rendered (sanitised) signature HTML, i.e. from templates that administrators and technicians maintain - an API client cannot pass a URL.
* Remote images are fetched only from host names that an administrator listed (setting `image_embed_hosts`, empty by default; IP literals, ports, wildcards and user names are rejected; every change is in the audit log), only over https (`CURLPROTO_HTTPS`), with certificate verification, without redirects and without a proxy.
* Every address the host name resolves to (A and AAAA) must be public; loopback, private, link-local, carrier-grade NAT, multicast, documentation, IPv4-mapped and reserved ranges are refused. The checked address is pinned for the connection (`CURLOPT_RESOLVE`), so a DNS answer cannot change between the check and the request (DNS rebinding).
* Timeouts (3 s connect, 8 s total), a 1 MiB size limit enforced while downloading, at most 3 new downloads per request and a cache (24 h; failures 10 min) bound the work an API client can cause.
* Only PNG, JPEG and GIF are delivered, detected from the bytes (the remote Content-Type is ignored); SVG and anything else is never delivered.
* Local images are read only from the image folder (`realpath` check against `img/`, no `..`, no encoded NUL, image extensions only); `GET /images/{sha256}` serves only images that passed these checks and were referenced by a signature.
* The `X-SubSignature-Device` header is validated (same rule as `device_id`) and only written to the API log.

**Unified messages**

* `alertBox()` escapes the message text (`e()` + `nl2br`); the only variant that accepts markup (`alertBoxHtml()`) is called with fixed, translated text and escaped values only. Browser-side messages (`js/alerts.js`) are inserted with `textContent`, never as HTML.

**No external requests**

* All scripts, styles and fonts are served from the application itself; the CSP (`script-src`/`style-src`/`font-src 'self'`, `connect-src 'self'`) enforces it. The template editor's optional CDN features (Ace from cdnjs, js-beautify, Google Fonts) are now configured off or to the bundled copy instead of relying on the CSP to block them. The only third-party requests a browser can make are images that a template deliberately references by URL.

## Residual risks and recommendations

* **Run behind HTTPS.** Without it, session cookies lose the `Secure` flag and the API refuses to work by design.
* **Administrators and technicians are trusted with templates.** Both can edit template HTML and configure the LDAP filter. Sanitizing is defence in depth, not a substitute for trust. Restrict access to the tooling by network if possible and give the technician role sparingly.
* **`secret.key` protects stored secrets.** Anyone who can read both the database and `secret.key` can decrypt the SMTP/LDAP passwords. Keep `private_data/` outside the web root with mode 0750 and back both up together.
* **Directory users do not get accounts.** Users who should log in to SubSignature must be created locally (or register); the LDAP import only fills their signatures.
* **Bundled JavaScript libraries** (Jodit, Ace, Font Awesome) are third-party code and need to be updated by the project maintainers; they were not audited here.
* **`install.php` is reachable until the first administrator exists.** Create the admin right after deployment, or remove the file.
* **No two-factor authentication** is implemented. Consider SSO/VPN in front of the application for sensitive environments.
* **SQLite** is file based: protect the data directory with correct file system permissions.
