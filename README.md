<h1>
  <img src="https://raw.githubusercontent.com/husisusi/SubSignature/main/public_html/img/subsig_logo.png"
       alt="SubSignature Logo"
       height="100"
       style="vertical-align: middle;">
  SubSignature
</h1>

![PHP](https://img.shields.io/badge/PHP-7.4%2B%20%7C%208.3-777BB4?style=flat-square&logo=php&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=flat-square&logo=sqlite&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

SubSignature is a lightweight, self-hosted email signature generator built with PHP and SQLite. It helps organizations manage and standardize email signatures without complex database setups or paid cloud services.

The focus is privacy and security. The application runs entirely on your server: no CDNs, no external fonts, no telemetry. All assets are hosted locally.

## Screenshots

**Generator Interface**
![Generator Interface](https://raw.githubusercontent.com/husisusi/SubSignature/main/public_html/img/screenshots/SubSignature_screenshot_generator.png)

**User Management**
![User Management](https://raw.githubusercontent.com/husisusi/SubSignature/main/public_html/img/screenshots/SubSignature_screenshot_user.png)

**Template Editor**
![Template Editor](https://raw.githubusercontent.com/husisusi/SubSignature/main/public_html/img/screenshots/SubSignature_screenshot_editor.png)

**Import CSV**
![Import Function](https://raw.githubusercontent.com/husisusi/SubSignature/main/public_html/img/screenshots/SubSignature_screenshot_import.png)

## Features

* **Signature generator** with live preview and multiple, editable HTML templates (placeholders: `{{NAME}}`, `{{ROLE}}`, `{{EMAIL}}`, `{{PHONE}}`, `{{PHONE_CLEAN}}`).
* **Template editor** (WYSIWYG + code editor), image manager, template backup (ZIP).
* **Signature rollout:** administrators can send signatures to users by email (SMTP).
* **User management** with roles (admin / user), activation, optional self-registration.
* **CSV import / export** of signatures (delimiter `,` or `;`, formula-injection safe export).
* **LDAP / Active Directory import** of users and their attributes (import only, no LDAP login). See [LDAP import](#ldap--active-directory-import).
* **Read-only API with bearer tokens** to prepare a desktop agent for Outlook and Thunderbird. See [API](#api-for-the-desktop-agent).
* **Light, dark and system theme:** switch in the sidebar (or top right on the login page); the choice is remembered per browser, "system" follows the operating system. Signature previews always stay on white. Static files are versioned automatically (`?v=<mtime>`), so a new release shows up without clearing the browser cache.
* **Security by default:** CSRF protection, strict CSP, hardened sessions, brute-force protection, encrypted secrets, audit log. See [Security](#security).
* **Self-hosted, SQLite:** no MySQL/PostgreSQL required.

## Requirements

* PHP 7.4 or newer (tested with 8.x), with the extensions `sqlite3`, `mbstring`, `fileinfo`, `zip`, and `openssl` or `sodium`.
* Optional: the `ldap` extension for the LDAP import (`apt install php-ldap`).
* Apache 2.4 with `mod_rewrite` and `mod_headers` (the shipped `.htaccess` is written for it). Nginx works with equivalent rules, see [Hardening](#hardening-checklist).
* HTTPS (strongly recommended; required for the API).

## Installation

1. Upload the project. The recommended layout keeps `private_data/` **outside** the web root:

   ```
   /var/www/subsignature/
   ├── private_data/     <- database, secret key, logs, sessions (writable by the web server)
   └── public_html/      <- document root
   ```

   If you cannot place it outside the web root, `private_data/.htaccess` denies all access (Apache). Alternatively set the environment variable `SUBSIG_DATA_DIR` to any directory outside the web root.
2. Make `private_data/` writable by the web server user (for example `chown -R www-data: private_data && chmod 750 private_data`).
3. Open `install.php` in your browser to create the database and the first administrator. The installer locks itself as soon as an administrator exists; deleting `install.php` afterwards is still a good idea.
4. Log in and configure SMTP and options under **Configuration**.

### Optional local configuration

Copy `private_data/config.local.php.example` to `private_data/config.local.php`:

| Constant | Purpose |
|----------|---------|
| `TRUSTED_PROXIES` | IPs of reverse proxies whose `X-Forwarded-*` headers are trusted. Leave empty if there is no proxy. |
| `FORCE_HTTPS` | Redirect HTTP to HTTPS. |
| `API_ALLOW_HTTP` | Allow the API over HTTP (testing only). |
| `LOG_RETENTION_DAYS` | Retention of audit and login logs (default 180). |

### Backup

Back up the whole `private_data/` directory **including `secret.key`**. The key encrypts the SMTP and LDAP passwords stored in the database; without it these values cannot be recovered (you would have to enter them again). Keep the key and the database backups in the same secure place, never in the web root.

## LDAP / Active Directory import

**Admin → LDAP Import** reads users from a directory and creates or updates accounts in SubSignature. It is an **import only**: directory users cannot log in with their directory password.

Workflow: configure → *Test connection* → *Preview import* → *Apply import*. Nothing is written before you have reviewed the preview, and the import runs in a single database transaction.

| Setting | Notes |
|---------|-------|
| Directory type | Presets for Active Directory (`sAMAccountName`, `mail`, `displayName`, `objectGUID`, `title`, `telephoneNumber`) and OpenLDAP/generic (`uid`, `mail`, `cn`, `entryUUID`). Every attribute can be changed, so any other attribute (`mobile`, `department`, `co`, ...) can be mapped. |
| Encryption | LDAPS (default, port 636) or STARTTLS. Certificates are verified by default; a private CA file can be configured. Plain LDAP is possible but not recommended. |
| Bind account | Use a **read-only** service account. Its password is stored encrypted. |
| Base DN / filter | The AD default filter excludes disabled accounts. |
| Create signatures | Optionally creates one signature per user from name, role, email and phone. |
| Deactivate missing | Optionally deactivates previously imported accounts that disappeared from the directory. |

Safety rules built into the importer:

* Imported accounts always get the role `user` and an unusable random password. Directory data can never create administrators.
* Existing **local** accounts are never modified: an entry with the same username or email is skipped and reported in the preview.
* Users are matched by the directory's unique ID first (so renames are followed), then by username.
* Usernames, emails and phone numbers are validated; invalid values are dropped or the entry is skipped with a reason.
* Paged search, referrals disabled, binary attributes are never interpreted as text.

If the PHP `ldap` extension is missing, the page shows a notice; the settings can still be edited.

## API for the desktop agent

A planned C++ agent for Windows and Linux will fetch signatures from the server and install them in Outlook and Thunderbird. The server side is ready:

* Create a token under **Admin → API Tokens** (scope `signatures:read`, optional expiry, revocable, only the hash is stored).
* `GET /api/v1/signatures` returns rendered, sanitized HTML plus the raw fields, a plain-text variant and a hash for change detection; filters `username`, `email`, `updated_since`, paging.
* HTTPS only, rate limited, no session or cookie involved.

Full documentation with implementation notes for the agent: [docs/API.md](docs/API.md).

## Roles

* **Admins:** manage users, templates, images, configuration, LDAP import, API tokens, logs; import/export all data; send signatures.
* **Users:** generate and manage their own signatures from the available templates, import/export their own data.

## Security

An overview of the protections and the results of the security review is in [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md). Highlights:

* All state-changing actions use POST with a CSRF token; no destructive GET requests.
* Strict Content-Security-Policy, `X-Frame-Options: DENY`, `nosniff`, HSTS on HTTPS; the template preview is sandboxed.
* Sessions: private session directory, `HttpOnly`, `SameSite=Strict`, `Secure` on HTTPS, ID regeneration on login, idle timeout (15 min) and absolute lifetime (8 h); role and active flag are re-checked in the database on every request; a password change signs out all other sessions.
* Login throttling per IP and per username (database backed), equalized timing for unknown users.
* Passwords hashed with bcrypt, a password policy is enforced everywhere.
* All output is escaped; template HTML is sanitized on the server and in the browser.
* SMTP and LDAP passwords are encrypted at rest (libsodium or AES-GCM).
* CSV export neutralizes spreadsheet formulas; CSV import is size- and row-limited.
* Audit log of security-relevant events with retention.

### Hardening checklist

* Serve the application over HTTPS only and set `FORCE_HTTPS` if you terminate TLS yourself.
* Keep `private_data/` outside the document root.
* Run PHP with `expose_php=Off`, `display_errors=Off`, `session.use_strict_mode=1`.
* Restrict access to the admin pages by network (VPN / IP allow list) if possible.
* Use a dedicated read-only LDAP service account and LDAPS with certificate verification.
* Nginx: deny `/includes/`, `/templates/`, dotfiles and `*.db|*.log|*.key`; forward the `Authorization` header (`fastcgi_param HTTP_AUTHORIZATION $http_authorization;`); route `/api/v1/*` to `api/v1/index.php`; send `Cache-Control: no-cache` for `*.css` and `*.js` (the Apache `.htaccess` does this already).
* Report vulnerabilities privately (GitHub security advisories) instead of opening a public issue.

## Credits & Third-Party Assets

* **Jodit Editor** (MIT): WYSIWYG editor for template creation.
* **Ace Editor** (BSD-3-Clause): standalone code editor written in JavaScript.
* **Font Awesome Free** (Icons CC BY 4.0, Fonts SIL OFL 1.1, Code MIT): UI icons, hosted locally.

## Roadmap

* SubSignature desktop agent (Python, Windows/Linux) that installs signatures in Outlook and Thunderbird using the API above.
* Optional LDAP import scheduling (cron/CLI).

## Contributing

Contributions are welcome! If you find a bug, please open an issue. If you find this project useful, please give it a **star** ⭐.

## License

MIT, see [LICENSE](LICENSE).
