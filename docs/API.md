# SubSignature API v1 (read-only)

The API lets a client program - in particular the planned **SubSignature desktop agent**
for Windows and Linux - fetch signatures from the server and install them in Outlook
and Thunderbird. It is read-only, stateless (no cookies, no CSRF) and authenticated with
bearer tokens.

## Quick start

1. Sign in as administrator and open **API Tokens** in the sidebar.
2. Create a token (label, expiry). Copy it immediately - only its SHA-256 hash is stored.
3. Call the API:

```bash
curl -H "Authorization: Bearer ssg_xxxxxxxx..." \
     "https://signatures.example.com/api/v1/signatures?limit=50"
```

## Security rules

| Rule | Details |
|------|---------|
| Transport | HTTPS only. Plain HTTP answers `403 https_required` unless `API_ALLOW_HTTP` is set in `private_data/config.local.php` (testing only). |
| Authentication | `Authorization: Bearer <token>`. Tokens are 256-bit random values with the prefix `ssg_`. |
| Storage | The server stores only `SHA-256(token)`; a leaked database does not leak usable tokens. |
| Lifetime | Optional expiry; tokens can be revoked at any time (effective immediately). |
| Scope | `signatures:read`. No endpoint can change data. |
| Brute force | 20 invalid tokens per client IP and 5 minutes, then `429`. |
| Rate limit | 600 requests per minute per token. |
| Visibility | Only signatures of **active** users are returned. |

Use one token per deployment/agent group, so a single token can be revoked without
affecting the others.

## Endpoints

All endpoints use `GET` and return `application/json; charset=utf-8`.

### `GET /api/v1/`

Service information. Useful as a health and credentials check.

```json
{ "service": "SubSignature", "version": "1.4.0", "api": "v1", "token": "Windows rollout", "server_time": "2026-11-07T20:51:07+00:00" }
```

### `GET /api/v1/signatures`

| Query parameter | Meaning |
|-----------------|---------|
| `username` | Only signatures of this account (case-insensitive). |
| `email` | Only signatures with this email address (case-insensitive). |
| `updated_since` | ISO 8601 date/time; returns signatures created or changed at or after it. Tracks changes to the signature data only - edits to the template file itself are not visible here, see the note below. |
| `limit` | 1-500, default 100. |
| `offset` | Default 0. Page until `count < limit`. |

```json
{
  "count": 1, "limit": 100, "offset": 0,
  "items": [
    {
      "id": 2,
      "username": "anna",
      "name": "Anna Example",
      "role": "CTO",
      "email": "anna@example.com",
      "phone": "+49 111 222",
      "template": "signature_pro.html",
      "source": "manual",
      "created_at": "2026-11-07 20:42:11",
      "updated_at": "2026-11-07 20:42:11",
      "html": "<table ...>...</table>",
      "html_sha256": "9f2c...",
      "text": "Anna Example\nCTO\nanna@example.com\n+49 111 222"
    }
  ]
}
```

* `source` is `manual`, `csv` or `ldap`.
* `html` is the final, **server-sanitised** fragment with all values already HTML-escaped.
  Images are absolute URLs defined in the template.
* `html_sha256` changes whenever the rendered signature changes: store it in the agent
  and skip installation when it is unchanged.
* `text` is a plain-text fallback.
* Timestamps are UTC.

### `GET /api/v1/signatures/{id}`

One signature in the same format. `404` if it does not exist or its owner is inactive.

## Errors

```json
{ "error": { "code": "unauthorized", "message": "Missing, invalid, expired or revoked token." } }
```

| HTTP | `code` | Meaning |
|------|--------|---------|
| 400 | `bad_request` | Invalid parameter. |
| 401 | `unauthorized` | Token missing, wrong, expired or revoked. |
| 403 | `https_required` / `forbidden` | Plain HTTP, or the token lacks the scope. |
| 404 | `not_found` | Unknown endpoint or signature. |
| 405 | `method_not_allowed` | Anything but `GET`. |
| 429 | `too_many_attempts` / `rate_limited` | Honour the `Retry-After` header. |

## Notes for the agent (C++)

Suggested design for the Windows/Linux agent:

1. **Configuration**: server URL, token, and the mapping "which signature belongs to this
   machine/user". Store the token in the OS secret store (Windows Credential Manager,
   libsecret/Keychain on Linux), never in plain text.
2. **Selecting the signature**: query `GET /signatures?email=<primary address>` (or
   `?username=`). The email address is taken from the Outlook profile or the Thunderbird
   account configuration.
3. **HTTP client**: libcurl with TLS verification enabled (`CURLOPT_SSL_VERIFYPEER=1`,
   `CURLOPT_SSL_VERIFYHOST=2`). Do not disable certificate checks; use `CURLOPT_CAINFO`
   for a private CA.
   ```cpp
   curl_easy_setopt(h, CURLOPT_URL, url.c_str());
   curl_slist* hdr = curl_slist_append(nullptr, ("Authorization: Bearer " + token).c_str());
   curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdr);
   curl_easy_setopt(h, CURLOPT_PROTOCOLS_STR, "https");
   ```
4. **JSON**: any parser (nlohmann/json, simdjson).
5. **Outlook (Windows)**: write the HTML to
   `%APPDATA%\Microsoft\Signatures\<name>.htm` (plus `.txt` from the `text` field) and set
   the default signature values under
   `HKCU\Software\Microsoft\Office\16.0\Common\MailSettings`
   (`NewSignature`, `ReplySignature`). Classic Outlook only; new Outlook uses roaming
   signatures and needs a different mechanism.
6. **Thunderbird (Windows/Linux)**: signatures are stored per identity in `prefs.js`
   (`mail.identity.idN.htmlSigText`, `mail.identity.idN.htmlSigFormat=true`) or in a file
   referenced by `mail.identity.idN.sig_file` (with `attach_signature=true`). Edit the
   profile only while Thunderbird is closed, or ship the values through a `user.js`.
7. **Polling**: poll `updated_since=<last successful sync>` every few hours with jitter
   (responses are never cached, `Cache-Control: no-store`). Because an edited *template*
   changes the HTML of many signatures without touching their rows, also do a full sync
   (no `updated_since`) about once a day and compare `html_sha256`.
8. **Images**: signature images are absolute URLs inside the template; the agent does not
   need to download them. (Hosting images on your own HTTPS server keeps recipients'
   mail clients happy.)
