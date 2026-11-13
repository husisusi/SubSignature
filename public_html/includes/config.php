<?php
/**
 * includes/config.php
 *
 * Entry point included by every web page. It loads the session-less core
 * (bootstrap.php) and then adds everything that needs a browser session:
 * secure session handling, security headers, CSRF protection and the
 * authentication / authorisation helpers.
 */

require_once __DIR__ . '/bootstrap.php';

// Absolute session lifetime (hours) and idle timeout (seconds).
const SESSION_ABSOLUTE_TIMEOUT = 8 * 3600;
const SESSION_IDLE_TIMEOUT     = 900;

// Fixed bcrypt hash of a random value. Verifying against it for unknown
// usernames keeps the response time equal to a real password check.
const DUMMY_PASSWORD_HASH = '$2y$10$vAYvzqa.wVaWw4kqHyZhCesfkeZM4ckGyj8F6WU7dBtD57HJcFyl.';

// ---------------------------------------------------------------------
// 1. HTTPS ENFORCEMENT (optional, see FORCE_HTTPS in config.local.php)
// ---------------------------------------------------------------------
if (FORCE_HTTPS && !isHttpsRequest() && PHP_SAPI !== 'cli') {
    $host = $_SERVER['HTTP_HOST'] ?? '';
    // Only redirect to a syntactically valid host to avoid host-header abuse.
    if (preg_match('/^[A-Za-z0-9.\-]+(:\d+)?$/', $host)) {
        header('Location: https://' . $host . ($_SERVER['REQUEST_URI'] ?? '/'), true, 301);
        exit;
    }
}

// ---------------------------------------------------------------------
// 2. SECURE SESSION
// ---------------------------------------------------------------------
if (session_status() === PHP_SESSION_NONE) {
    // Keep sessions in our own private directory instead of the shared system
    // temp directory (other sites on the same host could read those files).
    $sessionDir = BASE_DIR . '/sessions';
    if (!is_dir($sessionDir)) {
        @mkdir($sessionDir, 0700, true);
    }
    if (is_dir($sessionDir) && is_writable($sessionDir)) {
        session_save_path($sessionDir);
    }
    ini_set('session.gc_maxlifetime', (string)SESSION_ABSOLUTE_TIMEOUT);
    session_name('SUBSIGSID');
    session_start([
        'cookie_httponly'  => true,
        'cookie_secure'    => isHttpsRequest(),
        'cookie_samesite'  => 'Strict',
        'use_strict_mode'  => true,
        'use_only_cookies' => true,
        'use_trans_sid'    => false,
    ]);
}

/**
 * Fully terminates the current session (data, server file and cookie).
 */
function destroySession(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_destroy();
    }
}

// Idle timeout applies to logged-in sessions only.
if (isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true) {
    if (isset($_SESSION['last_activity']) && (time() - (int)$_SESSION['last_activity']) > SESSION_IDLE_TIMEOUT) {
        destroySession();
        header('Location: index.php?timeout=1');
        exit;
    }
}
$_SESSION['last_activity'] = time();

// A CSRF token always exists after this point.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ---------------------------------------------------------------------
// 3. SECURITY HEADERS
// ---------------------------------------------------------------------

/**
 * Sends the standard security headers including a Content-Security-Policy.
 *
 * The policy still allows inline scripts/styles (the UI uses them), but it
 * blocks foreign script sources, plugins, framing and form targets. Image
 * sources include https:/http: because signature templates reference remote
 * images by design. A page can define CSP_ALLOW_EVAL before including this
 * file when a bundled editor needs it (template editor).
 */
function sendSecurityHeaders(): void
{
    if (headers_sent()) {
        return;
    }
    header_remove('X-Powered-By');
    $scriptExtra = (defined('CSP_ALLOW_EVAL') && CSP_ALLOW_EVAL) ? " 'unsafe-eval'" : '';
    $csp = "default-src 'self'; "
         . "script-src 'self' 'unsafe-inline'" . $scriptExtra . "; "
         . "style-src 'self' 'unsafe-inline'; "
         . "img-src 'self' data: blob: https: http:; "
         . "font-src 'self' data:; "
         . "connect-src 'self'; "
         . "worker-src 'self' blob:; "
         . "frame-src 'self'; "
         . "object-src 'none'; "
         . "base-uri 'self'; "
         . "form-action 'self'; "
         . "frame-ancestors 'none'";

    header('Content-Security-Policy: ' . $csp);
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('X-XSS-Protection: 0'); // legacy XSS auditors are harmful; CSP is the control
    header('Referrer-Policy: same-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), browsing-topics=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cache-Control: no-store, max-age=0');
    if (isHttpsRequest()) {
        header('Strict-Transport-Security: max-age=31536000');
    }
}
sendSecurityHeaders();

// ---------------------------------------------------------------------
// 4. INSTALLATION CHECK
// ---------------------------------------------------------------------
$currentScript = basename($_SERVER['PHP_SELF'] ?? '');
if ($currentScript !== 'install.php') {
    $tablesExist = $db->querySingle("SELECT name FROM sqlite_master WHERE type='table' AND name='users'");
    $adminCount  = $tablesExist ? (int)$db->querySingle("SELECT COUNT(*) FROM users WHERE role = 'admin'") : 0;
    if (!$tablesExist || $adminCount === 0) {
        header('Location: install.php');
        exit;
    }
}

// ---------------------------------------------------------------------
// 5. AUTHENTICATION & ACCESS CONTROL
// ---------------------------------------------------------------------

/**
 * Roles
 *
 *   admin       - everything, including user management, system configuration and logs
 *   technician  - everything except those three areas (templates, images, backup, LDAP import,
 *                 API tokens, all signatures, tags, imports/exports, sending signatures)
 *   user        - own signatures only
 *
 * isAdmin() is deliberately strict: it is true for administrators ONLY. Every area a
 * technician must not reach (users, system configuration, system logs) is guarded by
 * requireAdmin(). Areas a technician may use are guarded by requireStaff().
 * An unknown or damaged role value is treated as "user" (fail closed).
 */
const ROLE_ADMIN      = 'admin';
const ROLE_TECHNICIAN = 'technician';
const ROLE_USER       = 'user';

/** Roles that may be stored in users.role (whitelist for every write). */
function validRoles(): array
{
    return [ROLE_USER, ROLE_TECHNICIAN, ROLE_ADMIN];
}

function isValidRole($role): bool
{
    return is_string($role) && in_array($role, validRoles(), true);
}

/** Role of the current session; anything unknown counts as "user". */
function currentRole(): string
{
    $role = $_SESSION['role'] ?? ROLE_USER;
    return isValidRole($role) ? $role : ROLE_USER;
}

function isAdmin(): bool
{
    return currentRole() === ROLE_ADMIN;
}

function isTechnician(): bool
{
    return currentRole() === ROLE_TECHNICIAN;
}

/** Administrator or technician: may work with the signatures of all users and use the tooling. */
function isStaff(): bool
{
    return isAdmin() || isTechnician();
}

/** Translated name of a role (default: the role of the current session). */
function roleLabel(?string $role = null): string
{
    switch ($role ?? currentRole()) {
        case ROLE_ADMIN:
            return t('Administrator');
        case ROLE_TECHNICIAN:
            return t('Technician');
        default:
            return t('User');
    }
}

/** HTML-escaped role label for templates. */
function eRoleLabel(?string $role = null): string
{
    return e(roleLabel($role));
}

function isLoggedIn(): bool
{
    return isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true;
}

/**
 * Short fingerprint of the stored password hash. It is kept in the session so
 * that a password change or reset invalidates all other sessions of the user.
 */
function passwordFingerprint(string $passwordHash): string
{
    return hash_hmac('sha256', $passwordHash, appSecretKey());
}

/**
 * Establishes a fresh authenticated session for a user row.
 */
function startUserSession(array $user): void
{
    session_regenerate_id(true); // prevents session fixation
    $_SESSION['loggedin']      = true;
    $_SESSION['user_id']       = (int)$user['id'];
    $_SESSION['username']      = $user['username'];
    $_SESSION['role']          = $user['role'];
    $_SESSION['full_name']     = $user['full_name'];
    $_SESSION['email']         = $user['email'];
    $_SESSION['last_activity'] = time();
    $_SESSION['login_time']    = time();
    $_SESSION['pw_fp']         = passwordFingerprint($user['password_hash']);
    $_SESSION['csrf_token']    = bin2hex(random_bytes(32));

    // Restore the user's saved interface language (follows the account across devices).
    global $db;
    if ($db instanceof SQLite3) {
        $saved = $db->querySingle('SELECT language FROM users WHERE id = ' . (int)$user['id']);
        if (is_string($saved) && isSupportedLanguage($saved)) {
            setLanguageCookie($saved);
        }
    }
}

/**
 * Requires a valid login. On every request the account is re-read from the
 * database, so deactivated, deleted or demoted users lose access immediately
 * and the role is never trusted from a stale session.
 */
function requireLogin(): void
{
    global $db;

    if (!isLoggedIn() || empty($_SESSION['user_id'])) {
        header('Location: index.php');
        exit;
    }

    if (isset($_SESSION['login_time']) && (time() - (int)$_SESSION['login_time']) > SESSION_ABSOLUTE_TIMEOUT) {
        destroySession();
        header('Location: index.php?timeout=1');
        exit;
    }

    $stmt = $db->prepare('SELECT username, password_hash, role, is_active, full_name, email FROM users WHERE id = ?');
    $stmt->bindValue(1, (int)$_SESSION['user_id'], SQLITE3_INTEGER);
    $user = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if (!$user) {
        destroySession();
        header('Location: index.php');
        exit;
    }
    if ((int)$user['is_active'] === 0) {
        destroySession();
        header('Location: index.php?error=deactivated');
        exit;
    }

    $fingerprint = passwordFingerprint($user['password_hash']);
    if (empty($_SESSION['pw_fp'])) {
        $_SESSION['pw_fp'] = $fingerprint;              // session created before this check existed
    } elseif (!hash_equals($_SESSION['pw_fp'], $fingerprint)) {
        destroySession();                               // password was changed elsewhere
        header('Location: index.php?timeout=1');
        exit;
    }

    // Keep session copies in sync with the database.
    $_SESSION['username']  = $user['username'];
    $_SESSION['role']      = $user['role'];
    $_SESSION['full_name'] = $user['full_name'];
    $_SESSION['email']     = $user['email'];
}

/** Administrators only (users, system configuration, system logs). */
function requireAdmin(): void
{
    global $db;

    requireLogin();
    if (!isAdmin()) {
        if (isTechnician()) {
            logSecurityEventToDB($db, 'UNAUTHORIZED_ACCESS', (int)$_SESSION['user_id'], 'Technician requested admin-only page: ' . basename($_SERVER['PHP_SELF'] ?? ''));
        }
        header('Location: generator.php');
        exit;
    }
}

/** Administrators and technicians. */
function requireStaff(): void
{
    requireLogin();
    if (!isStaff()) {
        header('Location: generator.php');
        exit;
    }
}

// ---------------------------------------------------------------------
// 6. CSRF PROTECTION
// ---------------------------------------------------------------------

function generateCSRFToken(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCSRFToken($token): bool
{
    return is_string($token)
        && isset($_SESSION['csrf_token'])
        && hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Aborts with HTTP 403 unless the request carries a valid CSRF token
 * (POST field "csrf_token" or the X-CSRF-Token header).
 */
function requireCsrf(): void
{
    $token = $_POST['csrf_token'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
    if (!verifyCSRFToken($token)) {
        http_response_code(403);
        die('Security error: invalid CSRF token. Please reload the page and try again.');
    }
}

/**
 * Hidden form field with the CSRF token.
 */
function csrfField(): string
{
    return '<input type="hidden" name="csrf_token" value="' . e(generateCSRFToken()) . '">';
}

/**
 * <meta> tag read by js/post-action.js for button-driven POST requests.
 */
function csrfMeta(): string
{
    return '<meta name="csrf-token" content="' . e(generateCSRFToken()) . '">';
}

// ---------------------------------------------------------------------
// 7. FLASH MESSAGES (survive one redirect, never put in URLs)
// ---------------------------------------------------------------------

function setFlash(string $type, string $message): void
{
    $_SESSION['flash'][$type] = $message;
}

function popFlash(string $type): string
{
    $msg = $_SESSION['flash'][$type] ?? '';
    unset($_SESSION['flash'][$type]);
    return (string)$msg;
}

// ---------------------------------------------------------------------
// 8. LOGIN BOOKKEEPING
// ---------------------------------------------------------------------

/**
 * Records a login attempt and updates the per-account counters.
 */
function logLoginAttempt($db, $username, $successful, $ip = null, $user_agent = null): void
{
    $ip = $ip ?? getClientIp();
    $ua = cleanText($user_agent ?? ($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'), 255);
    $username = cleanText($username, 64);

    $stmt = $db->prepare('INSERT INTO login_attempts (ip_address, username, successful, user_agent) VALUES (?, ?, ?, ?)');
    $stmt->bindValue(1, $ip, SQLITE3_TEXT);
    $stmt->bindValue(2, $username, SQLITE3_TEXT);
    $stmt->bindValue(3, $successful ? 1 : 0, SQLITE3_INTEGER);
    $stmt->bindValue(4, $ua, SQLITE3_TEXT);
    $stmt->execute();

    if ($username === '') {
        return;
    }

    if (!$successful) {
        $stmt = $db->prepare("UPDATE users SET failed_login_attempts = failed_login_attempts + 1, last_failed_login = datetime('now') WHERE username = ?");
        $stmt->bindValue(1, $username, SQLITE3_TEXT);
        $stmt->execute();
        logSecurityEventToDB($db, 'LOGIN_FAILED', null, 'User: ' . $username);
        return;
    }

    $stmt = $db->prepare("UPDATE users SET failed_login_attempts = 0, last_login = datetime('now'), account_locked_until = NULL WHERE username = ?");
    $stmt->bindValue(1, $username, SQLITE3_TEXT);
    $stmt->execute();

    $stmt = $db->prepare('SELECT id FROM users WHERE username = ?');
    $stmt->bindValue(1, $username, SQLITE3_TEXT);
    $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if ($row) {
        logSecurityEventToDB($db, 'LOGIN_SUCCESS', (int)$row['id'], 'User: ' . $username);
    }
}

/**
 * True while a username is throttled after too many failed logins. The check
 * does not depend on the account existing, so it does not reveal valid names.
 */
function isAccountLocked($db, $username): bool
{
    return rateLimitIsBlocked('login_user', 5, 900, mb_strtolower((string)$username, 'UTF-8'));
}
