<?php
/**
 * includes/helpers.php
 *
 * Shared helper functions used by the web UI and the API: output escaping,
 * request info, settings, validation, template handling, rate limiting and
 * audit logging.
 *
 * Functions here must not depend on a session; session-aware helpers live in
 * config.php. Functions that need the database use the global $db at call
 * time (it is created in bootstrap.php after this file is loaded).
 */

// ---------------------------------------------------------------------
// 1. OUTPUT & REQUEST HELPERS
// ---------------------------------------------------------------------

/**
 * HTML-escapes a value for safe output (HTML body and quoted attributes).
 */
function e($value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Legacy helper kept for compatibility: trims and HTML-escapes input.
 */
function sanitizeInput($input)
{
    if (is_array($input)) {
        return array_map('sanitizeInput', $input);
    }
    return htmlspecialchars(trim((string)$input), ENT_QUOTES, 'UTF-8');
}

/**
 * True if the current request was made over HTTPS (also behind a trusted
 * reverse proxy that sets X-Forwarded-Proto).
 */
function isHttpsRequest(): bool
{
    if (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') {
        return true;
    }
    if ((int)($_SERVER['SERVER_PORT'] ?? 0) === 443) {
        return true;
    }
    if (isTrustedProxy($_SERVER['REMOTE_ADDR'] ?? '')
        && strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https') {
        return true;
    }
    return false;
}

function isTrustedProxy(string $ip): bool
{
    return $ip !== '' && in_array($ip, TRUSTED_PROXIES, true);
}

/**
 * Returns the client IP. X-Forwarded-For is only honoured when the direct peer
 * is a configured trusted proxy (TRUSTED_PROXIES in config.local.php).
 */
function getClientIp(): string
{
    $remote = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    if (!isTrustedProxy($remote) || empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return $remote;
    }
    // Walk the chain from the right and return the first address that is not
    // one of our own proxies (the left-most entries are client controlled).
    $chain = array_reverse(array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])));
    foreach ($chain as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP) && !isTrustedProxy($ip)) {
            return $ip;
        }
    }
    return $remote;
}

// ---------------------------------------------------------------------
// 2. SETTINGS
// ---------------------------------------------------------------------

function getSetting($db, string $key, string $default = ''): string
{
    $stmt = $db->prepare('SELECT setting_value FROM system_settings WHERE setting_key = ?');
    $stmt->bindValue(1, $key, SQLITE3_TEXT);
    $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    return ($row && $row['setting_value'] !== null) ? (string)$row['setting_value'] : $default;
}

function setSetting($db, string $key, string $value): void
{
    $stmt = $db->prepare('INSERT OR REPLACE INTO system_settings (setting_key, setting_value) VALUES (?, ?)');
    $stmt->bindValue(1, $key, SQLITE3_TEXT);
    $stmt->bindValue(2, $value, SQLITE3_TEXT);
    $stmt->execute();
}

// ---------------------------------------------------------------------
// 3. VALIDATION
// ---------------------------------------------------------------------

/**
 * Removes control characters, trims whitespace and limits the length.
 */
function cleanText($value, int $maxLength = 255): string
{
    $value = (string)$value;
    // Strip C0/C1 control characters (keeps normal Unicode text).
    $value = preg_replace('/[\x00-\x1F\x7F]/u', ' ', $value) ?? '';
    $value = trim(preg_replace('/\s+/u', ' ', $value) ?? '');
    if (mb_strlen($value, 'UTF-8') > $maxLength) {
        $value = mb_substr($value, 0, $maxLength, 'UTF-8');
    }
    return $value;
}

/**
 * Validates and normalises the four signature fields.
 *
 * @param array $input             Raw input with keys name, role, email, phone
 * @param bool  $requireRoleAndPhone Whether role and phone are mandatory
 * @return array [cleanFields, errors]
 */
function validateSignatureFields(array $input, bool $requireRoleAndPhone = true): array
{
    $clean = [
        'name'  => cleanText($input['name'] ?? '', 100),
        'role'  => cleanText($input['role'] ?? '', 100),
        'email' => cleanText($input['email'] ?? '', 254),
        'phone' => cleanText($input['phone'] ?? '', 30),
    ];
    $errors = [];

    if ($clean['name'] === '') {
        $errors[] = 'Name is required.';
    }
    if ($requireRoleAndPhone && $clean['role'] === '') {
        $errors[] = 'Role is required.';
    }
    if ($clean['email'] === '' || !filter_var($clean['email'], FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'A valid email address is required.';
    }
    if ($requireRoleAndPhone && $clean['phone'] === '') {
        $errors[] = 'Phone number is required.';
    }
    if ($clean['phone'] !== '') {
        $digits = preg_replace('/\D/', '', $clean['phone']);
        if (!preg_match('/^[\+\d\s\-\(\)\/\.]{5,30}$/', $clean['phone']) || strlen($digits) < 3) {
            $errors[] = 'Invalid phone number format.';
        }
    }
    return [$clean, $errors];
}

/**
 * Password policy shared by registration, installer, password change and
 * admin password reset. Returns a list of error messages (empty = OK).
 */
function validatePasswordPolicy($password): array
{
    $password = (string)$password;
    $errors = [];
    if (strlen($password) < 8) $errors[] = 'Password must be at least 8 characters';
    if (strlen($password) > 200) $errors[] = 'Password must not be longer than 200 characters';
    if (!preg_match('/[A-Z]/', $password)) $errors[] = 'At least one uppercase letter';
    if (!preg_match('/[a-z]/', $password)) $errors[] = 'At least one lowercase letter';
    if (!preg_match('/[0-9]/', $password)) $errors[] = 'At least one number';
    return $errors;
}

/**
 * Local usernames: letters, digits, underscore, dot, hyphen and @ (so that
 * directory account names such as "john.doe" are possible).
 */
function isValidUsername($username): bool
{
    return is_string($username) && preg_match('/^[A-Za-z0-9_.@\-]{3,64}$/', $username) === 1;
}

/**
 * Neutralises spreadsheet formula injection for CSV exports. Values that
 * start with = + - @ (or tab / CR) get a leading apostrophe, except values
 * that are plain phone numbers.
 */
function csvSafeCell($value): string
{
    $value = (string)$value;
    if ($value === '') {
        return $value;
    }
    if (preg_match('/^[=+\-@\t\r]/', $value) && !preg_match('/^\+?[\d\s()\-\/.]+$/', $value)) {
        return "'" . $value;
    }
    return $value;
}

// ---------------------------------------------------------------------
// 4. FILE SYSTEM & TEMPLATES
// ---------------------------------------------------------------------

/**
 * True if $path lies inside $dir (both are resolved with realpath first).
 * Uses a separator-aware comparison so "/var/www/tpl_evil" is not "inside"
 * "/var/www/tpl".
 */
function isPathInside(string $path, string $dir): bool
{
    $realPath = realpath($path);
    $realDir  = realpath($dir);
    if ($realPath === false || $realDir === false) {
        return false;
    }
    $realDir = rtrim($realDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    return strpos($realPath, $realDir) === 0;
}

/**
 * Valid signature template file name (no path, signature_ prefix, .html).
 */
function isValidTemplateName($name): bool
{
    return is_string($name) && preg_match('/^signature_[A-Za-z0-9_\-]{1,80}\.html$/', $name) === 1;
}

/**
 * Templates the admin may edit in the editor: signature templates plus the
 * notification mail wrapper.
 */
function isEditableTemplateName($name): bool
{
    return isValidTemplateName($name) || $name === 'email_notification.html';
}

/**
 * Lists all signature templates (file names), sorted.
 */
function listSignatureTemplates(): array
{
    $result = [];
    foreach (glob(TEMPLATES_DIR . '/signature_*.html') ?: [] as $file) {
        $name = basename($file);
        if (isValidTemplateName($name) && is_file($file)) {
            $result[] = $name;
        }
    }
    sort($result);
    return $result;
}

/**
 * Human readable template title, e.g. "signature_modern_blue.html" -> "Modern blue".
 */
function templateDisplayName(string $filename): string
{
    return ucfirst(str_replace(['signature_', '.html', '_'], ['', '', ' '], $filename));
}

/**
 * The system-wide default template (set by an admin), validated.
 */
function getDefaultTemplateName(): string
{
    $configFile = TEMPLATES_DIR . '/default_config.txt';
    if (is_file($configFile)) {
        $name = trim((string)file_get_contents($configFile));
        if (isValidTemplateName($name) && is_file(TEMPLATES_DIR . '/' . $name)) {
            return $name;
        }
    }
    if (is_file(TEMPLATES_DIR . '/signature_default.html')) {
        return 'signature_default.html';
    }
    $all = listSignatureTemplates();
    return $all[0] ?? 'signature_default.html';
}

/**
 * Returns an existing, valid template name; falls back to the default.
 */
function resolveTemplateName($name): string
{
    if (isValidTemplateName($name) && is_file(TEMPLATES_DIR . '/' . $name) && isPathInside(TEMPLATES_DIR . '/' . $name, TEMPLATES_DIR)) {
        return $name;
    }
    return getDefaultTemplateName();
}

/**
 * Reads a signature template (with fallback to the default template).
 */
function loadSignatureTemplate($name): string
{
    $resolved = resolveTemplateName($name);
    $path = TEMPLATES_DIR . '/' . $resolved;
    if (is_file($path) && isPathInside($path, TEMPLATES_DIR)) {
        return (string)file_get_contents($path);
    }
    return '';
}

/**
 * Fills a template with signature data. All values are HTML-escaped and the
 * replacement happens in a single pass, so a value like "{{EMAIL}}" inside a
 * name is not expanded a second time.
 *
 * Supported placeholders: {{NAME}} {{ROLE}} {{EMAIL}} {{PHONE}} {{PHONE_CLEAN}}
 */
function renderSignatureHtml(string $template, array $fields): string
{
    $phone = (string)($fields['phone'] ?? '');
    return strtr($template, [
        '{{NAME}}'        => e($fields['name'] ?? ''),
        '{{ROLE}}'        => e($fields['role'] ?? ''),
        '{{EMAIL}}'       => e($fields['email'] ?? ''),
        '{{PHONE}}'       => e($phone),
        '{{PHONE_CLEAN}}' => e(preg_replace('/[^0-9+]/', '', $phone)),
    ]);
}

/**
 * Renders a stored signature row (user_signatures) to a final HTML fragment:
 * template lookup with fallback, server-side sanitising, escaped placeholders.
 */
function renderStoredSignature(array $sig): string
{
    $template = sanitizeTemplateHtml(loadSignatureTemplate($sig['template'] ?? ''));
    return renderSignatureHtml($template, $sig);
}

/**
 * Builds a safe ASCII file name part from free text.
 */
function safeFileNamePart($text, string $fallback = 'signature'): string
{
    $clean = trim((string)preg_replace('/[^a-z0-9]+/i', '_', strtolower((string)$text)), '_');
    return $clean === '' ? $fallback : substr($clean, 0, 60);
}

/**
 * Best-effort server-side removal of active content from template HTML.
 *
 * Templates are authored by administrators (trusted), but they are rendered
 * in every user's browser, so this is defence in depth. The browser side
 * additionally sanitises through js/safe-html.js, and standalone previews are
 * sandboxed by a Content-Security-Policy.
 */
function sanitizeTemplateHtml(string $html): string
{
    // Whole elements that must never be part of a signature.
    $html = preg_replace('#<\s*(script|iframe|frameset|frame|object|embed|applet|form|textarea|select|button)\b[^>]*>.*?<\s*/\s*\1\s*>#is', '', $html) ?? $html;
    // Remaining (unclosed / void) dangerous tags.
    $html = preg_replace('#<\s*/?\s*(script|iframe|frameset|frame|object|embed|applet|form|input|textarea|select|button|base)\b[^>]*>#is', '', $html) ?? $html;
    // <meta http-equiv="refresh"> redirects.
    $html = preg_replace('#<\s*meta\b[^>]*http-equiv\s*=\s*["\']?\s*refresh[^>]*>#is', '', $html) ?? $html;
    // Inline event handlers (onclick=, onerror=, ...), run until nothing changes.
    do {
        $before = $html;
        $html = preg_replace('#(<[^>]*?)\son[a-z]+\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)#is', '$1', $html) ?? $html;
    } while ($html !== $before);
    // javascript: / vbscript: / data:text/html URLs in URL-bearing attributes.
    $html = preg_replace(
        '#\b(href|src|action|formaction|background|xlink:href)\s*=\s*(["\']?)\s*(?:javascript|vbscript|data\s*:\s*text/html)[^"\'>\s]*\2#is',
        '$1=$2#$2',
        $html
    ) ?? $html;

    return $html;
}

// ---------------------------------------------------------------------
// 5. RATE LIMITING (database backed, cannot be bypassed by dropping cookies)
// ---------------------------------------------------------------------

function rateLimitKey(string $action, ?string $subject): string
{
    return hash('sha256', $action . '|' . ($subject ?? getClientIp()));
}

/**
 * True if the action is currently blocked (does not count a hit).
 */
function rateLimitIsBlocked(string $action, int $limit, int $window, ?string $subject = null): bool
{
    global $db;
    $stmt = $db->prepare('SELECT hits, window_start FROM rate_limits WHERE rl_key = ?');
    $stmt->bindValue(1, rateLimitKey($action, $subject), SQLITE3_TEXT);
    $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if (!$row) {
        return false;
    }
    if (time() - (int)$row['window_start'] > $window) {
        return false;
    }
    return (int)$row['hits'] >= $limit;
}

/**
 * Registers one hit (e.g. a failed login) for the action.
 */
function rateLimitHit(string $action, int $window, ?string $subject = null): void
{
    global $db;
    $key = rateLimitKey($action, $subject);
    $now = time();
    $db->exec('BEGIN IMMEDIATE');
    try {
        $stmt = $db->prepare('SELECT hits, window_start FROM rate_limits WHERE rl_key = ?');
        $stmt->bindValue(1, $key, SQLITE3_TEXT);
        $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

        if (!$row || $now - (int)$row['window_start'] > $window) {
            $up = $db->prepare('INSERT OR REPLACE INTO rate_limits (rl_key, hits, window_start) VALUES (?, 1, ?)');
            $up->bindValue(1, $key, SQLITE3_TEXT);
            $up->bindValue(2, $now, SQLITE3_INTEGER);
        } else {
            $up = $db->prepare('UPDATE rate_limits SET hits = hits + 1 WHERE rl_key = ?');
            $up->bindValue(1, $key, SQLITE3_TEXT);
        }
        $up->execute();
        $db->exec('COMMIT');
    } catch (Exception $e) {
        $db->exec('ROLLBACK');
        error_log('rateLimitHit failed: ' . $e->getMessage());
    }
}

function rateLimitReset(string $action, ?string $subject = null): void
{
    global $db;
    $stmt = $db->prepare('DELETE FROM rate_limits WHERE rl_key = ?');
    $stmt->bindValue(1, rateLimitKey($action, $subject), SQLITE3_TEXT);
    $stmt->execute();
}

/**
 * Check-and-count in one call: returns false when the limit is exceeded,
 * otherwise registers the hit and returns true.
 */
function checkRateLimit(string $action, int $limit = 5, int $timeframe = 300, ?string $subject = null): bool
{
    global $db;
    if (rateLimitIsBlocked($action, $limit, $timeframe, $subject)) {
        logSecurityEventToDB($db, 'RATE_LIMIT_EXCEEDED', null, 'Action: ' . $action . ', IP: ' . getClientIp());
        return false;
    }
    rateLimitHit($action, $timeframe, $subject);
    return true;
}

// ---------------------------------------------------------------------
// 6. AUDIT LOGGING & HOUSEKEEPING
// ---------------------------------------------------------------------

function logSecurityEventToDB($db, string $event_type, $user_id = null, string $details = ''): void
{
    $ua = cleanText($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown', 255);
    try {
        $stmt = $db->prepare('INSERT INTO security_events (event_type, user_id, ip_address, user_agent, details) VALUES (?, ?, ?, ?, ?)');
        $stmt->bindValue(1, $event_type, SQLITE3_TEXT);
        $stmt->bindValue(2, $user_id, $user_id === null ? SQLITE3_NULL : SQLITE3_INTEGER);
        $stmt->bindValue(3, getClientIp(), SQLITE3_TEXT);
        $stmt->bindValue(4, $ua, SQLITE3_TEXT);
        $stmt->bindValue(5, cleanText($details, 1000), SQLITE3_TEXT);
        $stmt->execute();
    } catch (Exception $e) {
        error_log('Audit log error: ' . $e->getMessage());
    }
}

/**
 * Writes one row to the mail log (used by the signature rollout).
 */
function logMail($db, $signatureId, string $recipient, string $status, string $message): void
{
    try {
        $stmt = $db->prepare('INSERT INTO mail_logs (signature_id, recipient, status, message) VALUES (?, ?, ?, ?)');
        $stmt->bindValue(1, $signatureId, $signatureId === null ? SQLITE3_NULL : SQLITE3_INTEGER);
        $stmt->bindValue(2, cleanText($recipient, 254), SQLITE3_TEXT);
        $stmt->bindValue(3, $status, SQLITE3_TEXT);
        $stmt->bindValue(4, cleanText($message, 1000), SQLITE3_TEXT);
        $stmt->execute();
    } catch (Exception $e) {
        error_log('Mail log error: ' . $e->getMessage());
    }
}

/**
 * Deletes log rows older than LOG_RETENTION_DAYS and stale rate-limit rows.
 * Cheap; runs on roughly 1 % of logins.
 */
function pruneOldLogs($db): void
{
    $days = max(7, (int)LOG_RETENTION_DAYS);
    foreach ([
        ['login_attempts', 'attempted_at'],
        ['security_events', 'created_at'],
        ['mail_logs', 'created_at'],
    ] as [$table, $column]) {
        $stmt = $db->prepare("DELETE FROM $table WHERE $column < datetime('now', ?)");
        $stmt->bindValue(1, '-' . $days . ' days', SQLITE3_TEXT);
        $stmt->execute();
    }
    $stmt = $db->prepare('DELETE FROM rate_limits WHERE window_start < ?');
    $stmt->bindValue(1, time() - 86400, SQLITE3_INTEGER);
    $stmt->execute();

    // Remove abandoned temporary files (LDAP previews etc.) older than 2 hours.
    foreach (glob(TMP_DIR . '/*.json') ?: [] as $file) {
        if (is_file($file) && filemtime($file) < time() - 7200) {
            @unlink($file);
        }
    }
}
