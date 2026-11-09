<?php
/**
 * includes/bootstrap.php
 *
 * Session-less core initialisation shared by the web UI (via config.php) and
 * the JSON API (api/v1/index.php):
 *   - constants and paths
 *   - optional local configuration (private_data/config.local.php)
 *   - error handling
 *   - SQLite connection and schema migrations
 *   - shared helper libraries
 *
 * This file MUST NOT start a session or send headers.
 */

if (defined('SUBSIG_BOOTSTRAPPED')) {
    return;
}
define('SUBSIG_BOOTSTRAPPED', true);

// ---------------------------------------------------------------------
// 1. CONSTANTS & PATHS
// ---------------------------------------------------------------------
define('APP_VERSION', '1.5.0');
define('APP_ROOT', dirname(__DIR__));                      // public_html/
define('TEMPLATES_DIR', APP_ROOT . '/templates');
define('IMAGES_DIR', APP_ROOT . '/img');

// The data directory lives OUTSIDE the web root. It can be relocated with the
// SUBSIG_DATA_DIR environment variable (e.g. for Docker setups).
$envDataDir = getenv('SUBSIG_DATA_DIR');
define('BASE_DIR', ($envDataDir !== false && $envDataDir !== '') ? rtrim($envDataDir, '/\\') : (APP_ROOT . '/../private_data'));
define('DB_PATH', BASE_DIR . '/signatures.db');
define('LOG_DIR', BASE_DIR . '/logs');
define('TMP_DIR', BASE_DIR . '/tmp');
define('SECRET_KEY_FILE', BASE_DIR . '/secret.key');

// Current database schema version (see runMigrations()).
define('SCHEMA_VERSION', 3);

// ---------------------------------------------------------------------
// 2. DIRECTORY CHECKS
// ---------------------------------------------------------------------
foreach ([BASE_DIR, LOG_DIR, TMP_DIR] as $dir) {
    if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) {
        error_log('CRITICAL: Failed to create directory: ' . $dir);
    }
}

// ---------------------------------------------------------------------
// 3. OPTIONAL LOCAL CONFIGURATION
// ---------------------------------------------------------------------
// private_data/config.local.php may define (all optional):
//   TRUSTED_PROXIES      array of reverse-proxy IPs whose X-Forwarded-* headers are trusted
//   FORCE_HTTPS          bool, redirect HTTP to HTTPS and send HSTS
//   API_ALLOW_HTTP       bool, allow the API over plain HTTP (testing only!)
//   LOG_RETENTION_DAYS   int, how long audit/login logs are kept (default 180)
if (is_file(BASE_DIR . '/config.local.php')) {
    require_once BASE_DIR . '/config.local.php';
}
if (!defined('TRUSTED_PROXIES')) define('TRUSTED_PROXIES', []);
if (!defined('FORCE_HTTPS')) define('FORCE_HTTPS', false);
if (!defined('API_ALLOW_HTTP')) define('API_ALLOW_HTTP', false);
if (!defined('LOG_RETENTION_DAYS')) define('LOG_RETENTION_DAYS', 180);

// ---------------------------------------------------------------------
// 4. ERROR HANDLING (production defaults)
// ---------------------------------------------------------------------
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', LOG_DIR . '/php_errors.log');

set_exception_handler(function ($e) {
    error_log('Uncaught ' . get_class($e) . ': ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
    if (!headers_sent()) {
        http_response_code(500);
    }
    echo 'An internal error occurred. Please check the server logs.';
    exit(1);
});

// ---------------------------------------------------------------------
// 5. HELPER LIBRARIES
// ---------------------------------------------------------------------
require_once __DIR__ . '/crypto.php';
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/i18n.php';

// ---------------------------------------------------------------------
// 6. DATABASE CONNECTION
// ---------------------------------------------------------------------
if (!is_writable(BASE_DIR)) {
    error_log('CRITICAL: Web server needs write access to: ' . BASE_DIR);
    http_response_code(500);
    die('Setup error: the private data directory is not writable. See the server log for details.');
}

try {
    $db = new SQLite3(DB_PATH);
    $db->enableExceptions(true);
    $db->busyTimeout(5000);
    $db->exec('PRAGMA foreign_keys = ON');
    $db->exec('PRAGMA journal_mode = WAL');
    @chmod(DB_PATH, 0640);
} catch (Exception $e) {
    error_log('Database connection error: ' . $e->getMessage());
    http_response_code(500);
    die('System error. Please check the server logs.');
}

// ---------------------------------------------------------------------
// 7. SCHEMA & MIGRATIONS
// ---------------------------------------------------------------------

/**
 * Adds a column to a table if it does not exist yet.
 */
function addColumnIfMissing(SQLite3 $db, string $table, string $column, string $definition): void
{
    // $table / $column are internal constants, never user input.
    $res = $db->query('PRAGMA table_info(' . $table . ')');
    while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
        if (strcasecmp($row['name'], $column) === 0) {
            return;
        }
    }
    $db->exec('ALTER TABLE ' . $table . ' ADD COLUMN ' . $column . ' ' . $definition);
}

/**
 * Creates / upgrades the database schema. Cheap no-op once up to date.
 */
function runMigrations(SQLite3 $db): void
{
    if ((int)$db->querySingle('PRAGMA user_version') >= SCHEMA_VERSION) {
        return;
    }

    $db->exec('BEGIN IMMEDIATE');
    try {
        // Re-check inside the lock: another request may have migrated meanwhile.
        $version = (int)$db->querySingle('PRAGMA user_version');
        if ($version >= SCHEMA_VERSION) {
            $db->exec('COMMIT');
            return;
        }

        // ---- Version 1: baseline schema ---------------------------------
        $db->exec("CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            full_name TEXT,
            role TEXT DEFAULT 'user',
            is_active BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME,
            failed_login_attempts INTEGER DEFAULT 0,
            last_failed_login DATETIME,
            account_locked_until DATETIME
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS user_signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            role TEXT,
            email TEXT,
            phone TEXT,
            template TEXT DEFAULT 'signature_default.html',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS user_settings (
            user_id INTEGER PRIMARY KEY,
            default_template TEXT DEFAULT 'signature_default.html',
            theme TEXT DEFAULT 'light',
            items_per_page INTEGER DEFAULT 10,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS system_settings (
            setting_key TEXT PRIMARY KEY,
            setting_value TEXT
        )");
        // New self-registered users are inactive until an admin approves them.
        $db->exec("INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('default_user_active', '0')");

        $db->exec("CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            username TEXT,
            attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            successful BOOLEAN DEFAULT 0,
            user_agent TEXT
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            user_id INTEGER,
            ip_address TEXT NOT NULL,
            user_agent TEXT,
            details TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS mail_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            signature_id INTEGER,
            recipient TEXT,
            status TEXT,
            message TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");

        // ---- Version 2: LDAP import, API tokens, DB-backed rate limits ---
        // Accounts created by the LDAP import cannot log in with LDAP (login is
        // not implemented); auth_source/external_id/ldap_dn prepare for that.
        addColumnIfMissing($db, 'users', 'auth_source', "TEXT DEFAULT 'local'");
        addColumnIfMissing($db, 'users', 'external_id', 'TEXT');
        addColumnIfMissing($db, 'users', 'ldap_dn', 'TEXT');
        addColumnIfMissing($db, 'users', 'ldap_synced_at', 'DATETIME');
        addColumnIfMissing($db, 'user_signatures', 'source', "TEXT DEFAULT 'manual'");
        addColumnIfMissing($db, 'user_signatures', 'updated_at', 'DATETIME');

        $db->exec("CREATE TABLE IF NOT EXISTS rate_limits (
            rl_key TEXT PRIMARY KEY,
            hits INTEGER NOT NULL DEFAULT 0,
            window_start INTEGER NOT NULL
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT NOT NULL,
            token_hash TEXT UNIQUE NOT NULL,
            token_prefix TEXT NOT NULL,
            scope TEXT NOT NULL DEFAULT 'signatures:read',
            created_by INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            last_used_at DATETIME,
            last_used_ip TEXT,
            revoked_at DATETIME,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
        )");

        // ---- Version 3: per-user interface language ----------------------
        addColumnIfMissing($db, 'users', 'language', 'TEXT');

        $db->exec('CREATE INDEX IF NOT EXISTS idx_sig_user ON user_signatures(user_id)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_sig_email ON user_signatures(email COLLATE NOCASE)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email COLLATE NOCASE)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_users_external ON users(external_id)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_login_attempted ON login_attempts(attempted_at)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_sec_created ON security_events(created_at)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_mail_created ON mail_logs(created_at)');

        // Encrypt a legacy plaintext SMTP password at rest.
        $smtp = $db->querySingle("SELECT setting_value FROM system_settings WHERE setting_key = 'smtp_pass'");
        if ($smtp !== null && $smtp !== false && $smtp !== '' && !isEncryptedSecret($smtp)) {
            $stmt = $db->prepare("UPDATE system_settings SET setting_value = ? WHERE setting_key = 'smtp_pass'");
            $stmt->bindValue(1, encryptSecret($smtp), SQLITE3_TEXT);
            $stmt->execute();
        }

        $db->exec('PRAGMA user_version = ' . (int)SCHEMA_VERSION);
        $db->exec('COMMIT');
    } catch (Exception $e) {
        $db->exec('ROLLBACK');
        error_log('Migration failed: ' . $e->getMessage());
        http_response_code(500);
        die('System error: database migration failed. Please check the server logs.');
    }
}

runMigrations($db);
