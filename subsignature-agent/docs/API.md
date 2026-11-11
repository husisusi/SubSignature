# How the agent uses the SubSignature API v1

The basis is the server documentation
[`docs/API.md` in the SubSignature repository](https://github.com/husisusi/SubSignature/blob/main/docs/API.md)
(API v1, since SubSignature 1.4.0; the status report since 1.6.0, the applied version in it since 1.7.0). This document records **what the agent uses from it** and
**which decisions** it makes where the server documentation leaves things open.

> **Status:** the Linux agent runs against the project owner's real server. The automated tests run against a
> **mock server** (`cmd/mocksubsig`) that mimics the server documentation. That documentation was read for this
> document but not copied character by character; in case of doubt the documentation in the repository applies.
> Open points are listed below.

## Calls used

| Call | Purpose in the agent |
|---|---|
| `GET /api/v1/` | `subsignature-agent ping`: check reachability, TLS and token; shows service, version, token label and the clock difference to the server |
| `GET /api/v1/signatures?email=<address>&limit=50&offset=<n>` | Fetch the signatures of an address, page by page until a page is not full |
| `POST /api/v1/status` | After a complete sync: report per signature `ok`/`warn`/`error`, the applied version (`html_sha256`) and this installation's device id (see "Status report") |

Not used, with reasons:

* **`updated_since`** – according to the documentation the filter does not see changes to the **template file** (many
  signatures change then without their rows changing). The agent therefore always queries each address **in full**.
  That is a few KB per address and run (600 requests/minute/token are allowed), and there is no "daily full sync"
  that could be forgotten.
* **`username` as a query parameter** – whether it can be combined with `email` is not documented. The agent only
  queries by `email` and filters the account **itself** (`<username>` in the configuration).
* **`GET /api/v1/signatures/{id}`** – not needed.

## Request

```
GET {server/url}{api-path}/signatures?email=<address>&limit=50&offset=0     (api-path: /api/v1)
Authorization: Bearer ssg_…
Accept: application/json
```

* Token: `ssg_…`, 256 bit; created by an admin/technician under **API Tokens**, shown only once (the server stores
  only the hash), scope `signatures:read` (plus `status:write` for the status report), revocable at any time. **One token per rollout group** is also what the
  documentation recommends.
* The address is sent URL-encoded (`+` as `%2B`). The server compares case-insensitively.
* There are no redirects (3xx are not followed; the token never goes to another host).
* Without a token the agent does not send a request at all (the API always requires one).

## Response

```json
{ "count": 1, "limit": 50, "offset": 0,
  "items": [ { "id": 2, "username": "anna", "name": "Anna Example", "role": "CTO",
               "email": "anna@example.com", "phone": "+49 111 222",
               "template": "signature_pro.html", "source": "manual",
               "created_at": "2026-11-07 20:42:11", "updated_at": "2026-11-07 20:42:11",
               "html": "<table …>…</table>", "html_sha256": "9f2c…", "text": "Anna Example\nCTO\n…" } ] }
```

| Field | Use in the agent |
|---|---|
| `items` | If the field is missing, the response is **not** a SubSignature response (wrong URL?) → error. An empty list = **no signature for this address**. That is not an error. |
| `id` (number) | Uniqueness, tie-break, log |
| `email` | **Every entry is checked once more against the requested address by the agent itself.** Foreign addresses are never used. |
| `username` | Account. For several accounts with the same address see "Several signatures" |
| `template` | The **template name** (e.g. `signature_pro.html`); this is what the configuration calls `<template>` |
| `name` | Name of the **person**, not of the signature – never used for selection |
| `source` | `manual`, `csv` or `ldap`; optionally as a ranking (`<prefer-source>`) |
| `updated_at`, `created_at` | `YYYY-MM-DD HH:MM:SS`, **UTC**; "most recently changed" |
| `html` | Fragment sanitized by the server, with absolute image URLs. The agent checks it **additionally** (tripwire) and turns it into a complete HTML document |
| `html_sha256` | SHA-256 (hex) of `html`. The agent does not verify it; it records the value in its state and **sends it back** in the status report, so the server can tell whether this device has the current version |
| `text` | Plain-text version; used for the `.txt`/`.rtf` files of classic Outlook |
| `role`, `phone`, `count` | read but not used |

Order of the entries: **not defined**. The selection is independent of it (tested with randomly shuffled input).
Only signatures of **active** users are returned.

## Errors and behaviour

Error format: `{"error":{"code":"…","message":"…"}}`. The server's text is stripped of control characters and
shortened for the log.

| HTTP / `code` | Meaning | Agent |
|---|---|---|
| 401 `unauthorized` | Token missing, wrong, expired, revoked | **Aborts the run after the first request**; next attempt only after the full interval |
| 403 `forbidden` | Token without permission | like 401 |
| 403 `https_required` | Plain HTTP, server without `API_ALLOW_HTTP` | Abort; hint to use `https://` |
| 429 `rate_limited` / `too_many_attempts` | Limit per token / 20 invalid tokens per address in 5 minutes | **Abort**; wait time = `Retry-After` (at least `retry-interval`, at most `interval`; the server's value is capped at 1 h) |
| 5xx | Server error | this address is skipped, the others continue; retry after `retry-interval` |
| 404 `not_found` | Unknown **endpoint** | Error with a hint at `server/url`/`api-path`. **Not** "no signature" – that is what the empty list says |
| 400, 405, 3xx, others | | Error, nothing is changed |
| Network error, timeout | | Aborts the run (every further request would fail the same way); `retry-interval` |
| TLS error | | Abort; no token is sent |

Why abort instead of "trying every address individually": with a wrong token every address would count as an invalid
attempt, and the server blocks a **source address** after 20 in 5 minutes – in an intranet often all machines behind
the same NAT address. A single attempt per run and the full interval afterwards avoid that.

## Several signatures for one address

The API defines neither a default signature nor an order. The agent decides in this order:

1. **Only entries with exactly this address** and non-empty HTML. (An empty signature would delete the one in the mail client.)
2. IDs delivered more than once and entries with **identical content** are merged.
3. `<username>` (global or per address): only this account. No match ⇒ change nothing.
4. `<template>` (global or per address; `.html` and case do not matter): only this template. No match ⇒ change nothing.
5. **If the address then still belongs to several accounts**, the agent changes nothing and reports it (the result
   would otherwise be another person's name, role and phone number). Solution: `<username>`.
6. Several entries **of the same account** (for example the same template created twice, import plus manual):
   `duplicate-policy` – `newest` (default: ranking `<prefer-source>`, then most recently changed, then higher `id`) or `skip`.
7. If the selection spans **several templates**, the log suggests setting `<template>`.

## Change detection

There is no ETag. Every run fetches the complete response per address and compares the **fully prepared HTML** with the
file in the profile: only on a difference is anything written. A deleted or hand-modified file therefore heals itself.
The server's `html_sha256` value is not used for this decision; it is only reported back (see below).

## Status report

After every **real** sync (`sync`/`run`, never `check`) that was not aborted (no 401/403/429/network abort), the agent
sends one `POST /api/v1/status` with all addresses that resolved to a signature id:

```json
{ "device_id": "PC-ANNA-3f9a2b1c", "agent_version": "0.5.0-alpha",
  "items": [ { "signature_id": 2, "status": "ok", "html_sha256": "9f2c…" },
             { "signature_id": 7, "status": "warn", "message": "…", "html_sha256": "1b0e…" } ] }
```

* `status`: `error` if writing/applying failed (the error text goes into `message`), `warn` for a non-fatal note
  (e.g. an ambiguous selection), otherwise `ok`.
* `html_sha256`: the server's value for the version that was applied. The server compares it with the current version:
  equal = **up to date**, different = **out of date** (the signature, its template or the company details changed since).
  A value that is not 64 hex characters is left out rather than failing the report.
* `device_id`: generated once (host name + random suffix from `crypto/rand`) and kept in the state file; shown by
  `subsignature-agent status`. Every installation (and every user profile on a shared PC) is its own device, so All
  Signatures can show "2/3 up to date". It is a label only, never authentication.
* Needs a token with the **`status:write`** scope (separate from `signatures:read`). A 403 or any other failure only
  logs a warning – the signatures themselves are applied regardless.
* At most 200 items per request; more are split into several requests.
* Off per installation with `<report-status>false</report-status>`.

## Open points (to verify against a real server)

1. The agent does not use `updated_since` (template changes are invisible to it) and does not verify `html_sha256`; it only reports the value back.
2. Whether `username` and `email` may be queried together (AND) – the agent filters itself instead.
3. Does `count` always equal the number of `items`? The agent relies on `items` only.
4. Does a server ever answer with `"items": null` instead of `[]`? The agent would treat that as an error.
5. If the address in the mail client differs from the account's address (alias, shared mailbox), the query by `email`
   finds nothing. Mapping by `username` alone is planned but not built yet.
6. If the server removes the signature of a **deactivated** account, the local file remains (the agent deletes nothing by itself).

## History

The first alpha (0.1.0) ran against a **self-designed** contract. Dropped since then: ETag/`If-None-Match`, the
`default` flag, `sha256` verification, `404` as "no signature", configurable header and scheme (always
`Authorization: Bearer`), running without a token. Added: paging, error format, `Retry-After`, `ping`,
account/template/source selection. In the configuration `<name>` is now `<template>` (the old name is still read, with
a warning), `duplicate-policy` only knows `newest` and `skip`, `api-path` is the API root `/api/v1`. 0.5.0 added the
status report (`POST /status`) including the applied `html_sha256`.
