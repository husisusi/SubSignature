<?php
/**
 * api/v1/index.php - read-only JSON API for the SubSignature desktop agent.
 *
 * Stateless: no session, no cookies, no CSRF (authentication is a Bearer
 * token that is created in the admin area, see admin_api.php).
 *
 * Endpoints (all GET):
 *   /api/v1/                   service info (needs a valid token)
 *   /api/v1/signatures         list, filters: username, email, updated_since, limit, offset
 *   /api/v1/signatures/{id}    one signature
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
// Transport and method checks
// ---------------------------------------------------------------------
// Tokens must never travel over plain HTTP.
if (!isHttpsRequest() && !API_ALLOW_HTTP) {
    apiError(403, 'https_required', 'The API is only available over HTTPS.');
}
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    apiError(405, 'method_not_allowed', 'Only GET is supported.', ['Allow: GET']);
}

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
if (strpos(',' . $tokenRow['scope'] . ',', ',signatures:read,') === false) {
    apiError(403, 'forbidden', 'The token has no permission for this resource.');
}

// Generous per-token request limit (a rollout may poll often, a loop must not hammer).
if (!checkRateLimit('api_req', 600, 60, 'token:' . $tokenRow['id'])) {
    apiError(429, 'rate_limited', 'Rate limit exceeded (600 requests per minute).', ['Retry-After: 60']);
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

// ---------------------------------------------------------------------
// Routing (works with /api/v1/signatures and /api/v1/index.php/signatures)
// ---------------------------------------------------------------------
$path = (string)parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$base = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '')), '/');
if ($base !== '' && strpos($path, $base) === 0) {
    $path = substr($path, strlen($base));
}
$path = trim((string)preg_replace('#^/?index\.php#', '', $path), '/');

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

if ($path === '') {
    apiRespond(200, [
        'service'    => 'SubSignature',
        'version'    => APP_VERSION,
        'api'        => 'v1',
        'token'      => $tokenRow['label'],
        'server_time' => gmdate('c'),
    ]);
}

if ($path === 'signatures') {
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

if (preg_match('#^signatures/(\d{1,10})$#', $path, $m)) {
    $stmt = $db->prepare(API_SELECT . ' AND s.id = ?');
    $stmt->bindValue(1, (int)$m[1], SQLITE3_INTEGER);
    $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if (!$row) {
        apiError(404, 'not_found', 'Signature not found.');
    }
    apiRespond(200, apiSignature($row));
}

apiError(404, 'not_found', 'Unknown endpoint.');
