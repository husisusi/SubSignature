# SubSignature API v1

The API lets a client program - in particular the **SubSignature desktop agent**
(`subsignature-agent/`, already built and in use for Windows and Linux) - fetch signatures
from the server and install them in Outlook and Thunderbird, and report back whether that
install succeeded. It is stateless (no cookies, no CSRF) and authenticated with bearer
tokens throughout. The `GET` endpoints are read-only; `POST /api/v1/status` is the one
narrow write the API allows (see below) and needs its own token scope.

## Quick start

1. Sign in as administrator or technician and open **API Tokens** in the sidebar.
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
| Scope | `signatures:read` for the `GET` endpoints; `status:write` for `POST /api/v1/status`. A token can hold either, both, or neither - requests against a scope the token lacks get `403 forbidden`. |
| Brute force | 20 invalid tokens per client IP and 5 minutes, then `429`. |
| Rate limit | 600 requests per minute per token for `signatures:read`; 120 requests per minute per token for `status:write` (its own bucket, so a busy read rollout cannot starve status reporting or vice versa). |
| Visibility | Only signatures of **active** users are returned. |

Use one token per deployment/agent group, so a single token can be revoked without
affecting the others. Grant `status:write` only to tokens the agent rollout actually uses to
report status - a token scoped to `signatures:read` alone can never write anything, by design:
a leaked read-only token cannot be used to fake a status report, and a leaked status token
cannot be used to read signature content.

## Endpoints

All endpoints return `application/json; charset=utf-8`. The `GET` endpoints below need
`signatures:read`; `POST /api/v1/status` (its own scope) is documented in its own section further down.

Optional request header for every endpoint: **`X-SubSignature-Device: <device name>`** (1-80
characters: letters, digits, space `. _ - @`). It is only shown in **System Logs -> API Requests**
so the administrator can tell which machine sent a request; it is never used for authentication
or any decision. The desktop agent sends it since 1.0.0-rc2.

### `GET /api/v1/`

Service information. Useful as a health and credentials check.

```json
{ "service": "SubSignature", "version": "1.6.0", "api": "v1", "token": "Windows rollout", "server_time": "2026-11-07T20:51:07+00:00" }
```

### `GET /api/v1/signatures`

| Query parameter | Meaning |
|-----------------|---------|
| `username` | Only signatures of this account (case-insensitive). |
| `email` | Only signatures with this email address (case-insensitive). |
| `updated_since` | ISO 8601 date/time; returns signatures created or changed at or after it. Tracks changes to the signature data only - edits to the template file itself are not visible here, see the note below. |
| `limit` | 1-500, default 100. |
| `offset` | Default 0. Page until `count < limit`. |
| `images` | Optional: `meta` adds the list of the signature's images to every item, `inline` additionally returns the image data (Base64) - see [Embedded images](#embedded-images). |

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

One signature in the same format. `404` if it does not exist or its owner is inactive. Accepts
the same `images` parameter.

### Embedded images

Some clients cannot download the images of a signature themselves - for example an HCL
Notes/Domino agent written in LotusScript, which cannot fetch binary data. For them the server
delivers the images Base64-encoded.

`images=meta` adds `images` to every signature: one entry per `<img>` of the HTML, in order and
without duplicates (at most 20):

```json
"images": [
  { "src": "img/logo.png", "url": "img/logo.png", "status": "ok",
    "sha256": "4b1d...", "content_type": "image/png", "size": 4351 },
  { "src": "https://www.example.com/banner.png?v=2&amp;x=1", "url": "https://www.example.com/banner.png?v=2&x=1",
    "status": "not_allowed" }
]
```

* `src` is the attribute value exactly as it appears in `html` (replace it there, e.g. with
  `cid:` references); `url` is the decoded address.
* `status`: `ok`, or why the image is not delivered: `not_allowed` (host not listed, or a path
  outside the image folder), `https_required`, `invalid_url`, `not_found`, `too_large` (over 1 MiB),
  `unsupported_type` (only PNG, JPEG and GIF), `blocked_address` (the host resolves to a private or
  reserved address), `fetch_failed`, `fetch_unavailable` (PHP `curl` missing), `fetch_deferred`
  (fetch limit of this request reached - ask again).
* `sha256`, `content_type` (detected from the file content) and `size` only for `ok`.

`images=inline` returns the same list plus the data, once per image and response, in a top-level
object (for `GET /signatures/{id}` inside the signature object):

```json
"image_data": { "4b1d...": "iVBORw0KGgoAAAANSUhEUgAA..." }
```

`GET /api/v1/images/{sha256}` returns one image that a signature request has listed before:

```json
{ "sha256": "4b1d...", "content_type": "image/png", "size": 4351, "data": "iVBORw0KGgo..." }
```

`404` if no signature referenced this image (request the signature with `images=meta` first).
Clients with small response limits (LotusScript: 64 KB per byte array) should use `images=meta`
plus one `GET /images/{sha256}` per image instead of `images=inline`.

Where images may come from:

| Source in the template | Delivered |
|---|---|
| The image folder of SubSignature (**Manage Images**): `img/logo.png`, `/img/logo.png` or an absolute URL of this server | Always |
| `data:image/...;base64,...` | Always |
| `https://` URL on another server | Only if the host is listed under **Admin -> Configuration -> Image hosts for embedding** (empty by default). Fetched by the server over https without redirects or proxy (timeouts 3 s / 8 s), only if every address of the host is public, cached for 24 hours (failures for 10 minutes); at most 3 new fetches per request. |
| `http://` URL, other ports, user names in the URL | Never |

### `POST /api/v1/status`

Needs the `status:write` scope. Lets the agent report, per signature it fetched, whether
applying it on the client succeeded **and which version it applied** - so **All Signatures**
can show per signature whether every device has the current version (grey/green/yellow/red,
"2/3 up to date"). Each `device_id` gets its own row per signature; a later report from the
same device replaces that row. The endpoint never touches signature content, and an unknown
or deleted `signature_id` is silently skipped, not an error - the agent has no way to know
server-side IDs changed since its last fetch.

Request body (JSON object, max 64 KiB):

```json
{
  "device_id": "DESKTOP-ANNA-3f9a2b1c",
  "agent_version": "0.5.0-alpha",
  "items": [
    { "signature_id": 2, "status": "ok", "html_sha256": "9f2c…(64 hex characters)" },
    { "signature_id": 5, "status": "warn", "message": "Outlook default signature not set (no account found)." }
  ]
}
```

| Field | Rules |
|-------|-------|
| `device_id` | Required, 1-80 chars, `^[A-Za-z0-9][A-Za-z0-9 ._\-@]{0,79}$`. Identifies the reporting install for the admin's tooltip only - never trusted for anything security-relevant. |
| `agent_version` | Optional, at most 40 chars, `^[A-Za-z0-9][A-Za-z0-9 ._+\-]{0,39}$`. |
| `items` | Required, 1-200 entries per request (batch larger sets into several requests). |
| `items[].signature_id` | Required, positive integer. |
| `items[].status` | Required, one of `ok`, `warn`, `error`. |
| `items[].message` | Optional, at most 300 chars. Free text shown in the admin's sync-status tooltip; use it for `warn`/`error` detail. |
| `items[].html_sha256` | Optional (since 1.7.0), exactly 64 hex characters: the `html_sha256` of the version the device applied, as received from `GET /signatures`. Equal to the current value = **up to date**, different = **out of date**. Without it the server falls back to comparing the signature's `updated_at` with the report time (template or company-detail changes are then not detected). |

If the same `signature_id` appears more than once in `items`, the last entry wins. The
server timestamps the report itself (`synced_at = datetime('now')`, UTC) - it never trusts a
client-supplied time.

Limits on stored data: at most 25 devices are kept per signature (the most recently
reporting ones), and devices that have not reported for the admin-configurable retention
period (default 30 days) are deleted - so a token holder cannot grow the table without bound.

Response:

```json
{ "received": 2, "updated": 2 }
```

`received` is how many distinct signature IDs were in the request after de-duplication;
`updated` is how many of those actually matched an existing signature row.

## Errors

```json
{ "error": { "code": "unauthorized", "message": "Missing, invalid, expired or revoked token." } }
```

| HTTP | `code` | Meaning |
|------|--------|---------|
| 400 | `bad_request` | Invalid parameter. |
| 401 | `unauthorized` | Token missing, wrong, expired or revoked. |
| 403 | `https_required` / `forbidden` | Plain HTTP, or the token lacks the scope required for this request. |
| 404 | `not_found` | Unknown endpoint, signature or image. |
| 405 | `method_not_allowed` | Anything but `GET` on the reading endpoints, or anything but `POST` on `/status` (see the `Allow` response header). |
| 413 | `payload_too_large` | `POST /status` body over 64 KiB. |
| 429 | `too_many_attempts` / `rate_limited` | Honour the `Retry-After` header. |

## Request log

Since 1.8.0 the server logs API requests under **System Logs -> API Requests** (administrators
only), so you can see which clients use the API, with which token and with what result:

* Logged per request: time, HTTP status and result, method and path (plus the known query
  parameters `username`, `email`, `updated_since`, `limit`, `offset`, shortened), token ID and
  label, the device name (`device_id` of a status report, otherwise the `X-SubSignature-Device`
  header), the client's `User-Agent`, IP address, number of
  signatures returned or status rows stored, and the duration. **The token itself is never
  stored.**
* For refused requests the log shows the exact reason - no token, unknown token, revoked token,
  expired token - while the client still only receives the generic `unauthorized` shown above.
* A client that keeps getting `429` is recorded at most once per minute and reason.
* **Admin -> Configuration -> API request log:** all requests (default), only errors, or off;
  retention 1-365 days (default 30), and never more than 200,000 rows.

Tip for client authors: send a meaningful `User-Agent` (for example `my-sync-script/1.2`) and
the header `X-SubSignature-Device` - that is how your client is recognised in the log.

## The desktop agent

The agent that talks to this API is already built and in use: a single Go binary (standard
library only, cross-compiled, no runtime to install) that runs on both Windows and Linux. Its
own documentation lives next to its source in [`subsignature-agent/`](../subsignature-agent/)
([`subsignature-agent/README.md`](../subsignature-agent/README.md) for setup and the CLI,
[`subsignature-agent/docs/WINDOWS.md`](../subsignature-agent/docs/WINDOWS.md) for Outlook and
new-Outlook caveats); this section only covers how it uses this API, for anyone reading the
API on its own.

1. **Reading signatures**: on every `sync`, the agent calls `GET /signatures?email=<address>`
   for each configured identity, compares `html_sha256` against its local state file, and only
   rewrites the signature file / registry value when it changed - so a quiet mailbox produces
   no disk or registry writes. The HTTP client uses Go's default TLS verification; a private
   CA is loaded from the `ca-file` setting in `config.xml`, never disabled.
2. **Applying it**: Outlook gets the HTML (and text) written under
   `%APPDATA%\Microsoft\Signatures\` with the registry default-signature values updated
   (classic Outlook only - the agent detects the new Outlook, which stores signatures
   server-side, and reports that case rather than guessing). Thunderbird gets its identity
   prefs updated directly. Both are config-file driven, not auto-discovered guesses.
3. **Reporting back**: after a sync that completed without being rate-limited or aborted, the
   agent calls `POST /api/v1/status` (scope `status:write`, a separate token scope from
   reading) with one entry per signature it actually resolved to a signature ID - `ok` when
   the write succeeded, `warn` for a non-fatal issue (such as "no matching Outlook account"),
   `error` when applying it failed - plus the `html_sha256` of the version it applied (agent
   0.5.0 and later). This is what feeds the sync-status badge in **All
   Signatures**. It can be turned off per install with `<report-status>false</report-status>`
   in `config.xml` (default: on); turning it off only stops the report, it never affects
   whether the signature itself gets applied.
4. **Device identity**: `device_id` is the host name plus a random suffix (generated once
   with `crypto/rand`, kept in the agent's local state file, shown by
   `subsignature-agent status`). Every installation - and every user profile on a shared
   PC - is its own device, which is what All Signatures counts in "2/3 up to date". It only
   labels *which install* reported; it is never trusted for authentication or authorization.
5. **Polling**: the agent runs on a timer (every 2 hours by default, configurable) and
   fetches every address in full on each run (no `updated_since`), comparing the prepared HTML
   with the installed file - so an edited *template*, which changes the HTML of many
   signatures without touching their rows, is picked up on the next run as well.
6. **Intranet without HTTPS**: the API insists on HTTPS; for an internal CA, point the agent's
   `ca-file` setting at that CA's certificate rather than disabling verification.
