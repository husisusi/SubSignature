<?php
/**
 * api/v1/index.php - JSON API for the SubSignature desktop agent.
 *
 * Stateless: no session, no cookies, no CSRF (authentication is a Bearer
 * token that is created in the admin area, see admin_api.php).
 *
 * Endpoints:
 *   GET  /api/v1/                   service info (needs a valid token)
 *   GET  /api/v1/signatures         list, filters: username, email, updated_since, limit, offset
 *   GET  /api/v1/signatures/{id}    one signature
 *   POST /api/v1/status             agent reports sync status for signatures it applied
 *
 * The GET endpoints are read-only and need the "signatures:read" scope.
 * POST /status is a narrow write: it can only store per-device sync-status
 * rows (status/message/version/applied hash/time) for signatures that
 * already exist, never their content. It needs the separate "status:write" scope, so a leaked
 * read-only token cannot be used to report fake status, and a status token
 * cannot be used to read signature content.
 *
 * Details: docs/API.md
 */
require_once __DIR__ . '/../../includes/bootstrap.php';

// ---------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------
header_remove('X-Powered-By');
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');
header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");
if (isHttpsRequest()) {
    header('Strict-Transport-Security: max-age=31536000');
}

function apiRespond(int $status, array $payload, array $headers = []): void
{
    http_response_code($status);
    foreach ($headers as $h) {
        header($h);
    }
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

function apiError(int $status, string $code, string $message, array $headers = []): void
{
    apiRespond($status, ['error' => ['code' => $code, 'message' => $message]], $headers);
}

// ---------------------------------------------------------------------
// Transport checks (apply to every method)
// ---------------------------------------------------------------------
// Tokens must never travel over plain HTTP.
if (!isHttpsRequest() && !API_ALLOW_HTTP) {
    apiError(403, 'https_required', 'The API is only available over HTTPS.');
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

// ---------------------------------------------------------------------
// Routing (works with /api/v1/signatures and /api/v1/index.php/signatures)
// ---------------------------------------------------------------------
$path = (string)parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$base = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '')), '/');
if ($base !== '' && strpos($path, $base) === 0) {
    $path = substr($path, strlen($base));
}
$path = trim((string)preg_replace('#^/?index\.php#', '', $path), '/');

if ($method === 'GET') {
    $isKnownGet = ($path === '' || $path === 'signatures' || preg_match('#^signatures/\d{1,10}$#', $path) === 1);
    if (!$isKnownGet) {
        apiError(404, 'not_found', 'Unknown endpoint.');
    }
} elseif ($method === 'POST') {
    if ($path !== 'status') {
        apiError(405, 'method_not_allowed', 'Only GET is supported here.', ['Allow: GET']);
    }
} else {
    apiError(405, 'method_not_allowed', 'Only GET and POST (for /status) are supported.', ['Allow: GET, POST']);
}

$requiredScope = ($method === 'POST' && $path === 'status') ? 'status:write' : 'signatures:read';

// ---------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------
// Brute force protection per client IP: only failed attempts are counted.
if (rateLimitIsBlocked('api_auth_fail', 20, 300)) {
    apiError(429, 'too_many_attempts', 'Too many invalid tokens. Try again later.', ['Retry-After: 300']);
}

$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? ($_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
$token = '';
if (preg_match('/^Bearer\s+([A-Za-z0-9_\-]{20,200})$/', trim($authHeader), $m)) {
    $token = $m[1];
}

$tokenRow = null;
if ($token !== '') {
    $stmt = $db->prepare('SELECT id, label, scope, expires_at, revoked_at FROM api_tokens WHERE token_hash = ?');
    $stmt->bindValue(1, hash('sha256', $token), SQLITE3_TEXT);
    $tokenRow = $stmt->execute()->fetchArray(SQLITE3_ASSOC) ?: null;
}

$valid = $tokenRow !== null
    && empty($tokenRow['revoked_at'])
    && (empty($tokenRow['expires_at']) || strtotime($tokenRow['expires_at'] . ' UTC') > time());

if (!$valid) {
    rateLimitHit('api_auth_fail', 300);
    apiError(401, 'unauthorized', 'Missing, invalid, expired or revoked token.', ['WWW-Authenticate: Bearer realm="SubSignature"']);
}
if (strpos(',' . $tokenRow['scope'] . ',', ',' . $requiredScope . ',') === false) {
    apiError(403, 'forbidden', 'The token has no permission for this resource (needs scope "' . $requiredScope . '").');
}

// Generous per-token request limit (a rollout may poll often, a loop must not hammer).
// Status reports get their own, smaller bucket so a busy rollout of read requests
// cannot starve it, and vice versa.
$rlAction = ($requiredScope === 'status:write') ? 'api_status' : 'api_req';
$rlLimit  = ($requiredScope === 'status:write') ? 120 : 600;
if (!checkRateLimit($rlAction, $rlLimit, 60, 'token:' . $tokenRow['id'])) {
    apiError(429, 'rate_limited', 'Rate limit exceeded (' . $rlLimit . ' requests per minute).', ['Retry-After: 60']);
}

// Bookkeeping (best effort, never fails the request).
try {
    $upd = $db->prepare('UPDATE api_tokens SET last_used_at = CURRENT_TIMESTAMP, last_used_ip = ? WHERE id = ?');
    $upd->bindValue(1, getClientIp(), SQLITE3_TEXT);
    $upd->bindValue(2, (int)$tokenRow['id'], SQLITE3_INTEGER);
    $upd->execute();
} catch (Exception $e) {
    error_log('API token bookkeeping failed: ' . $e->getMessage());
}

/**
 * Converts one database row to the public API representation.
 */
function apiSignature(array $row): array
{
    $html = renderStoredSignature($row);
    $textLines = array_filter([$row['name'], $row['role'], $row['email'], $row['phone']], function ($v) {
        return $v !== null && $v !== '';
    });
    return [
        'id'         => (int)$row['id'],
        'username'   => $row['username'],
        'name'       => $row['name'],
        'role'       => $row['role'],
        'email'      => $row['email'],
        'phone'      => $row['phone'],
        'template'   => resolveTemplateName($row['template'] ?? ''),
        'source'     => $row['source'] ?: 'manual',
        'created_at' => $row['created_at'],
        'updated_at' => $row['updated_at'] ?: $row['created_at'],
        // Rendered, sanitised HTML fragment ready to be installed in a mail client.
        'html'       => $html,
        // SHA-256 of the HTML: lets the agent detect changes without diffing.
        'html_sha256' => hash('sha256', $html),
        // Plain-text variant for clients/identities that only support text.
        'text'       => implode("\n", $textLines),
    ];
}

const API_SELECT = 'SELECT s.id, s.name, s.role, s.email, s.phone, s.template, s.source, s.created_at, s.updated_at, u.username
                    FROM user_signatures s JOIN users u ON u.id = s.user_id
                    WHERE u.is_active = 1';

if ($method === 'GET' && $path === '') {
    apiRespond(200, [
        'service'    => 'SubSignature',
        'version'    => APP_VERSION,
        'api'        => 'v1',
        'token'      => $tokenRow['label'],
        'server_time' => gmdate('c'),
    ]);
}

if ($method === 'GET' && $path === 'signatures') {
    $sql = API_SELECT;
    $binds = [];

    $username = cleanText($_GET['username'] ?? '', 64);
    if ($username !== '') {
        $sql .= ' AND LOWER(u.username) = LOWER(?)';
        $binds[] = $username;
    }
    $email = cleanText($_GET['email'] ?? '', 254);
    if ($email !== '') {
        $sql .= ' AND LOWER(s.email) = LOWER(?)';
        $binds[] = $email;
    }
    if (!empty($_GET['updated_since'])) {
        $ts = strtotime((string)$_GET['updated_since']);
        if ($ts === false) {
            apiError(400, 'bad_request', 'updated_since must be a valid date/time (e.g. 2026-01-31T12:00:00Z).');
        }
        $sql .= ' AND COALESCE(s.updated_at, s.created_at) >= ?';
        $binds[] = gmdate('Y-m-d H:i:s', $ts);
    }

    $limit = min(500, max(1, (int)($_GET['limit'] ?? 100)));
    $offset = max(0, (int)($_GET['offset'] ?? 0));
    $sql .= ' ORDER BY s.id LIMIT ' . $limit . ' OFFSET ' . $offset;

    $stmt = $db->prepare($sql);
    foreach ($binds as $i => $value) {
        $stmt->bindValue($i + 1, $value, SQLITE3_TEXT);
    }
    $res = $stmt->execute();
    $items = [];
    while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
        $items[] = apiSignature($row);
    }
    apiRespond(200, ['count' => count($items), 'limit' => $limit, 'offset' => $offset, 'items' => $items]);
}

if ($method === 'GET' && preg_match('#^signatures/(\d{1,10})$#', $path, $m)) {
    $stmt = $db->prepare(API_SELECT . ' AND s.id = ?');
    $stmt->bindValue(1, (int)$m[1], SQLITE3_INTEGER);
    $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if (!$row) {
        apiError(404, 'not_found', 'Signature not found.');
    }
    apiRespond(200, apiSignature($row));
}

// ---------------------------------------------------------------------
// POST /status - the agent reports what it did with the signatures it fetched.
// ---------------------------------------------------------------------
if ($method === 'POST' && $path === 'status') {
    $raw = file_get_contents('php://input', false, null, 0, 65536 + 1);
    if ($raw === false || strlen($raw) > 65536) {
        apiError(413, 'payload_too_large', 'Request body must be at most 64 KiB.');
    }
    $body = json_decode((string)$raw, true);
    if (!is_array($body)) {
        apiError(400, 'bad_request', 'Request body must be a JSON object.');
    }

    // device_id/agent_version identify the reporting install for the admin's
    // tooltip only; they are never trusted for anything security-relevant.
    $deviceId = cleanText($body['device_id'] ?? '', 80);
    if ($deviceId === '' || !preg_match('/^[A-Za-z0-9][A-Za-z0-9 ._\-@]{0,79}$/', $deviceId)) {
        apiError(400, 'bad_request', 'device_id is required (1-80 characters, letters/digits/space . _ - @).');
    }
    $agentVersion = cleanText($body['agent_version'] ?? '', 40);
    if ($agentVersion !== '' && !preg_match('/^[A-Za-z0-9][A-Za-z0-9 ._+\-]{0,39}$/', $agentVersion)) {
        apiError(400, 'bad_request', 'agent_version must be at most 40 characters (letters/digits/space . _ + -).');
    }

    $items = $body['items'] ?? null;
    if (!is_array($items) || count($items) === 0) {
        apiError(400, 'bad_request', 'items must be a non-empty array.');
    }
    if (count($items) > 200) {
        apiError(400, 'bad_request', 'items must not contain more than 200 entries per request.');
    }

    $allowedStatus = ['ok', 'warn', 'error'];
    $clean = [];
    foreach ($items as $it) {
        if (!is_array($it)) {
            apiError(400, 'bad_request', 'Every entry in items must be an object.');
        }
        $id = filter_var($it['signature_id'] ?? null, FILTER_VALIDATE_INT);
        if ($id === false || $id === null || $id <= 0) {
            apiError(400, 'bad_request', 'signature_id must be a positive integer.');
        }
        $status = (string)($it['status'] ?? '');
        if (!in_array($status, $allowedStatus, true)) {
            apiError(400, 'bad_request', 'status must be one of: ' . implode(', ', $allowedStatus) . '.');
        }
        $message = cleanText($it['message'] ?? '', 300);
        // Optional: SHA-256 (hex) of the signature HTML the device applied, as
        // received from GET /signatures. Lets the server tell "up to date" from
        // "has an older version". Older agents do not send it.
        $sha = strtolower((string)($it['html_sha256'] ?? ''));
        if ($sha !== '' && !preg_match('/^[a-f0-9]{64}$/', $sha)) {
            apiError(400, 'bad_request', 'html_sha256 must be 64 hexadecimal characters.');
        }
        $clean[(int)$id] = ['status' => $status, 'message' => $message, 'sha' => $sha]; // last entry per id wins within the request
    }

    $updated = 0;
    $db->exec('BEGIN IMMEDIATE');
    try {
        // One row per (signature, device). A report from a new device adds a row,
        // a report from a known device replaces that device's row.
        $upsert = $db->prepare('INSERT INTO signature_device_status (signature_id, device_id, status, message, agent_version, html_sha256, synced_at)
                                 SELECT id, :device, :status, :message, :version, :sha, datetime(\'now\') FROM user_signatures WHERE id = :id
                                 ON CONFLICT(signature_id, device_id) DO UPDATE SET
                                     status = excluded.status, message = excluded.message,
                                     agent_version = excluded.agent_version, html_sha256 = excluded.html_sha256,
                                     synced_at = excluded.synced_at');
        // Bound the table: a token holder could invent any number of device ids.
        // Only the most recently reporting devices per signature are kept.
        $cap = $db->prepare('DELETE FROM signature_device_status
                              WHERE signature_id = :id AND device_id NOT IN (
                                  SELECT device_id FROM signature_device_status WHERE signature_id = :id
                                   ORDER BY synced_at DESC, device_id LIMIT ' . (int)STATUS_MAX_DEVICES_PER_SIGNATURE . ')');
        foreach ($clean as $id => $it) {
            $upsert->bindValue(':device', $deviceId, SQLITE3_TEXT);
            $upsert->bindValue(':status', $it['status'], SQLITE3_TEXT);
            $upsert->bindValue(':message', $it['message'], SQLITE3_TEXT);
            $upsert->bindValue(':version', $agentVersion, SQLITE3_TEXT);
            $upsert->bindValue(':sha', $it['sha'] !== '' ? $it['sha'] : null, $it['sha'] !== '' ? SQLITE3_TEXT : SQLITE3_NULL);
            $upsert->bindValue(':id', $id, SQLITE3_INTEGER);
            $upsert->execute();
            // Only signature ids that really exist produce a row (the SELECT ... WHERE id = :id
            // yields no source row otherwise); ids for signatures that were deleted or never
            // existed are silently skipped - not an error, the agent cannot know server-side IDs
            // changed meanwhile.
            $changed = $db->changes();
            $updated += $changed;
            if ($changed > 0) {
                $cap->bindValue(':id', $id, SQLITE3_INTEGER);
                $cap->execute();
            }
        }
        // Forget devices that stopped reporting long ago (replaced laptops ...).
        pruneDeviceStatus($db);
        $db->exec('COMMIT');
    } catch (Exception $e) {
        $db->exec('ROLLBACK');
        error_log('Status report failed: ' . $e->getMessage());
        apiError(500, 'internal_error', 'Could not store the status report.');
    }

    apiRespond(200, ['received' => count($clean), 'updated' => $updated]);
}

apiError(404, 'not_found', 'Unknown endpoint.');
