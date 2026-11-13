<?php
/**
 * api/v1/index.php - JSON API for the SubSignature desktop agent.
 *
 * Stateless: no session, no cookies, no CSRF (authentication is a Bearer
 * token that is created in the admin area, see admin_api.php).
 *
 * Endpoints:
 *   GET  /api/v1/                   service info (needs a valid token)
 *   GET  /api/v1/signatures         list, filters: username, email, updated_since, limit, offset;
 *                                   images=meta|inline adds the signature's images (Base64 for inline)
 *   GET  /api/v1/signatures/{id}    one signature (same images option)
 *   GET  /api/v1/images/{sha256}    one image of a signature, Base64-encoded
 *   POST /api/v1/status             agent reports sync status for signatures it applied
 *
 * Optional request header X-SubSignature-Device: the client's device name,
 * shown in System Logs -> API Requests (informational only).
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

// Request context for the API log (System Logs -> API Requests). Filled in
// step by step below and written once, by apiRespond(), for every response.
$apiStart = microtime(true);
$apiLog = [
    'token_id'    => null,
    'token_label' => '',
    'result'      => null,   // internal outcome; defaults to the error code / "ok"
    'items'       => null,   // signatures returned or status rows stored
    'device_id'   => '',
];

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
    apiWriteLog($status, (string)($payload['error']['code'] ?? 'ok'));
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

/**
 * Endpoint for the log: path plus the known query parameters (values
 * shortened), never anything else from the URL.
 */
function apiLogEndpoint(): string
{
    global $path;
    $p = isset($path) ? (string)$path : trim((string)parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH), '/');
    $p = '/' . substr((string)preg_replace('#[^A-Za-z0-9/_.\-]#', '', $p), 0, 100);
    $query = [];
    foreach (['username', 'email', 'updated_since', 'limit', 'offset', 'images'] as $key) {
        if (isset($_GET[$key]) && is_string($_GET[$key]) && $_GET[$key] !== '') {
            $query[] = $key . '=' . cleanText($_GET[$key], 64);
        }
    }
    return $query ? $p . '?' . implode('&', $query) : $p;
}

/**
 * Writes the API log row for the response that is about to be sent.
 */
function apiWriteLog(int $status, string $code): void
{
    global $db, $apiLog, $apiStart;
    if (!($db instanceof SQLite3)) {
        return;
    }
    $method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
    if (!preg_match('/^[A-Z]{1,10}$/', $method)) {
        $method = 'OTHER';
    }
    logApiRequest($db, [
        'token_id'    => $apiLog['token_id'],
        'token_label' => $apiLog['token_label'],
        'method'      => $method,
        'endpoint'    => apiLogEndpoint(),
        'http_status' => $status,
        'result'      => $apiLog['result'] ?? $code,
        'items'       => $apiLog['items'],
        'device_id'   => $apiLog['device_id'],
        'client'      => (string)($_SERVER['HTTP_USER_AGENT'] ?? ''),
        'duration_ms' => (int)round((microtime(true) - $apiStart) * 1000),
    ]);
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
    $isKnownGet = ($path === '' || $path === 'signatures' || preg_match('#^signatures/\d{1,10}$#', $path) === 1
                   || preg_match('#^images/[a-f0-9]{64}$#', $path) === 1);
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

if ($tokenRow !== null) {
    $apiLog['token_id'] = (int)$tokenRow['id'];
    $apiLog['token_label'] = (string)$tokenRow['label'];
}
if (!$valid) {
    // The client only learns "unauthorized"; the log keeps the exact reason.
    if ($token === '') {
        $apiLog['result'] = 'token_missing';
    } elseif ($tokenRow === null) {
        $apiLog['result'] = 'token_unknown';
    } elseif (!empty($tokenRow['revoked_at'])) {
        $apiLog['result'] = 'token_revoked';
    } else {
        $apiLog['result'] = 'token_expired';
    }
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

// Optional device name of the client (e.g. "PC-042-1a2b3c4d" from the desktop
// agent). Informational only - never used for any decision; status reports
// carry their own device_id, which takes precedence in the log.
$deviceHeader = cleanText($_SERVER['HTTP_X_SUBSIGNATURE_DEVICE'] ?? '', 80);
if ($deviceHeader !== '' && preg_match('/^[A-Za-z0-9][A-Za-z0-9 ._\-@]{0,79}$/', $deviceHeader)) {
    $apiLog['device_id'] = $deviceHeader;
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

/**
 * Reads the images option (?images=meta|inline); '' when not requested.
 */
function apiImagesMode(): string
{
    $mode = $_GET['images'] ?? '';
    if (!is_string($mode) || !in_array($mode, ['', 'meta', 'inline'], true)) {
        apiError(400, 'bad_request', 'images must be "meta" or "inline".');
    }
    return $mode;
}

/**
 * Host name of this server as the client addressed it (without port), and
 * the URL path of the installation, for recognising its own image URLs.
 */
function apiSelfHost(): string
{
    return (string)preg_replace('/:\d+$/', '', strtolower((string)($_SERVER['HTTP_HOST'] ?? '')));
}

function apiBasePath(): string
{
    $script = str_replace('\\', '/', (string)($_SERVER['SCRIPT_NAME'] ?? '/api/v1/index.php'));
    $base = rtrim(dirname(dirname(dirname($script))), '/');
    return $base === '' ? '/' : $base;
}

/**
 * Adds "images" to an API signature and collects the image data (keyed by
 * SHA-256) for the response's "image_data" object when $inline is set.
 */
function apiAttachImages(SQLite3 $db, array &$item, bool $inline, array &$imageData, int &$budget): void
{
    static $hosts = null;
    if ($hosts === null) {
        $hosts = imageEmbedHosts($db);
    }
    $list = [];
    foreach (signatureImages($db, $item['html'], apiSelfHost(), apiBasePath(), $hosts, $budget) as $img) {
        if ($inline && $img['status'] === 'ok' && !isset($imageData[$img['sha256']])) {
            $imageData[$img['sha256']] = base64_encode($img['bytes']);
        }
        unset($img['bytes']);
        $list[] = $img;
    }
    $item['images'] = $list;
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

    $imagesMode = apiImagesMode();
    $limit = min(500, max(1, (int)($_GET['limit'] ?? 100)));
    $offset = max(0, (int)($_GET['offset'] ?? 0));
    $sql .= ' ORDER BY s.id LIMIT ' . $limit . ' OFFSET ' . $offset;

    $stmt = $db->prepare($sql);
    foreach ($binds as $i => $value) {
        $stmt->bindValue($i + 1, $value, SQLITE3_TEXT);
    }
    $res = $stmt->execute();
    $items = [];
    $imageData = [];
    $budget = IMAGE_FETCH_BUDGET;
    while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
        $item = apiSignature($row);
        if ($imagesMode !== '') {
            apiAttachImages($db, $item, $imagesMode === 'inline', $imageData, $budget);
        }
        $items[] = $item;
    }
    $apiLog['items'] = count($items);
    $response = ['count' => count($items), 'limit' => $limit, 'offset' => $offset, 'items' => $items];
    if ($imagesMode === 'inline') {
        // Each image once per response, even if many signatures use it.
        $response['image_data'] = (object)$imageData;
    }
    apiRespond(200, $response);
}

if ($method === 'GET' && preg_match('#^signatures/(\d{1,10})$#', $path, $m)) {
    $imagesMode = apiImagesMode();
    $stmt = $db->prepare(API_SELECT . ' AND s.id = ?');
    $stmt->bindValue(1, (int)$m[1], SQLITE3_INTEGER);
    $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if (!$row) {
        apiError(404, 'not_found', 'Signature not found.');
    }
    $apiLog['items'] = 1;
    $item = apiSignature($row);
    if ($imagesMode !== '') {
        $imageData = [];
        $budget = IMAGE_FETCH_BUDGET;
        apiAttachImages($db, $item, $imagesMode === 'inline', $imageData, $budget);
        if ($imagesMode === 'inline') {
            $item['image_data'] = (object)$imageData;
        }
    }
    apiRespond(200, $item);
}

// ---------------------------------------------------------------------
// GET /images/{sha256} - one image, Base64-encoded. Only images that a
// signature referenced (and that passed the checks) are in the cache.
// ---------------------------------------------------------------------
if ($method === 'GET' && preg_match('#^images/([a-f0-9]{64})$#', $path, $m)) {
    $stmt = $db->prepare("SELECT sha256, content_type, size, data FROM image_cache WHERE sha256 = ? AND status = 'ok' LIMIT 1");
    $stmt->bindValue(1, $m[1], SQLITE3_TEXT);
    $img = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if (!$img) {
        apiError(404, 'not_found', 'Image not found. Request the signature with images=meta first.');
    }
    $apiLog['items'] = 1;
    apiRespond(200, [
        'sha256'       => $img['sha256'],
        'content_type' => $img['content_type'],
        'size'         => (int)$img['size'],
        'data'         => base64_encode((string)$img['data']),
    ]);
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
    $apiLog['device_id'] = $deviceId;
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

    $apiLog['items'] = $updated;
    apiRespond(200, ['received' => count($clean), 'updated' => $updated]);
}

apiError(404, 'not_found', 'Unknown endpoint.');
