<?php

define('TEMPLATES_DIR', dirname(__DIR__) . '/public_html/templates');
require_once dirname(__DIR__) . '/public_html/includes/helpers.php';
require_once dirname(__DIR__) . '/public_html/includes/crypto.php';
require_once dirname(__DIR__) . '/public_html/includes/i18n.php';
require_once dirname(__DIR__) . '/public_html/includes/LdapService.php';
require_once dirname(__DIR__) . '/public_html/includes/LdapJit.php';

function assertSameValue($expected, $actual, string $message): void
{
    if ($expected !== $actual) {
        throw new RuntimeException($message . ': expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
    }
}

function ldapEntry(string $username, string $email, string $name, string $dn, string $id = 'guid-1'): array
{
    return [
        'dn' => $dn,
        'attributes' => [
            'samaccountname' => [$username],
            'mail' => [$email],
            'displayname' => [$name],
            'title' => ['Engineer'],
            'telephonenumber' => ['+1 555 123 4567'],
            'objectguid' => [$id],
        ],
    ];
}

$db = new SQLite3(':memory:');
$db->enableExceptions(true);
$db->exec("CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
    email TEXT, full_name TEXT, role TEXT DEFAULT 'user', is_active BOOLEAN DEFAULT 1,
    auth_source TEXT DEFAULT 'local', external_id TEXT, ldap_dn TEXT, ldap_synced_at DATETIME
)");
$db->exec("CREATE TABLE user_settings (
    user_id INTEGER PRIMARY KEY, default_template TEXT DEFAULT 'signature_default.html'
)");
$db->exec("CREATE TABLE user_signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, name TEXT NOT NULL,
    role TEXT, email TEXT, phone TEXT, template TEXT, source TEXT DEFAULT 'manual',
    ldap_key TEXT, updated_at DATETIME
)");
$db->exec('CREATE TABLE system_settings (setting_key TEXT PRIMARY KEY, setting_value TEXT)');

assertSameValue(false, LdapConfig::defaults()['auth_enabled'], 'LDAP JIT should be disabled by default');
$savedConfig = LdapConfig::defaults();
$savedConfig['auth_enabled'] = true;
LdapConfig::save($db, $savedConfig);
assertSameValue(true, LdapConfig::load($db)['auth_enabled'], 'LDAP JIT setting should persist');
$savedConfig['auth_enabled'] = false;
LdapConfig::save($db, $savedConfig);
assertSameValue(false, LdapConfig::load($db)['auth_enabled'], 'LDAP JIT setting should be disableable');

$unsafeInput = array_merge(LdapConfig::defaults(), [
    'host' => 'dc.example.com',
    'port' => '389',
    'encryption' => 'none',
    'verify_cert' => '1',
    'bind_dn' => 'svc-subsig@example.com',
    'bind_pass' => 'not-a-real-password',
    'base_dn' => 'dc=example,dc=com',
    'auth_enabled' => '1',
]);
[, $unsafeErrors] = LdapConfig::fromInput($unsafeInput, '');
assertSameValue(true, in_array('LDAP login requires LDAPS or STARTTLS with certificate verification enabled.', $unsafeErrors, true), 'LDAP login must reject unencrypted configuration');

$safeInput = $unsafeInput;
$safeInput['encryption'] = 'ldaps';
[, $safeErrors] = LdapConfig::fromInput($safeInput, '');
assertSameValue([], $safeErrors, 'Verified LDAPS with a service bind should be accepted');

if (function_exists('ldap_connect')) {
    $unsafeConnectionRejected = false;
    try {
        new LdapService(array_merge(LdapConfig::defaults(), [
            'auth_enabled' => true,
            'encryption' => 'none',
            'verify_cert' => true,
            'bind_dn' => 'svc-subsig@example.com',
            'bind_pass' => 'not-a-real-password',
        ]));
    } catch (RuntimeException $e) {
        $unsafeConnectionRejected = true;
    }
    assertSameValue(true, $unsafeConnectionRejected, 'Unsafe LDAP configuration must be rejected before connecting');
}

$config = [
    'user_filter' => '(&(objectCategory=person)(objectClass=user))',
    'attr_username' => 'sAMAccountName',
    'attr_email' => 'mail',
    'attr_name' => 'displayName',
    'attr_role' => 'title',
    'attr_phone' => 'telephoneNumber',
    'attr_id' => 'objectGUID',
];

if (function_exists('ldap_escape')) {
    $filter = LdapService::buildUserFilter($config, 'alice*)(objectClass=*)');
    assertSameValue(
        '(&(&(objectCategory=person)(objectClass=user))(|(sAMAccountName=alice\\2a\\29\\28objectClass=\\2a\\29)(mail=alice\\2a\\29\\28objectClass=\\2a\\29)))',
        $filter,
        'LDAP filter should escape user-controlled metacharacters'
    );
}

$user = LdapJitProvisioner::provision(
    $db,
    ldapEntry('alice', 'alice@example.com', 'Alice Example', 'CN=Alice,OU=Staff,DC=example,DC=com'),
    $config
);
assertSameValue('ldap', $user['auth_source'], 'New user should be LDAP-backed');
assertSameValue('user', $user['role'], 'New user should have the least-privileged role');
assertSameValue(1, (int)$user['is_active'], 'New LDAP user should be active');
assertSameValue(1, (int)$db->querySingle('SELECT COUNT(*) FROM user_settings'), 'New user should get settings');
assertSameValue(1, (int)$db->querySingle('SELECT COUNT(*) FROM user_signatures'), 'New user should get one signature');

$userId = (int)$user['id'];
$db->exec("UPDATE users SET role = 'technician' WHERE id = $userId");
$manual = $db->prepare("INSERT INTO user_signatures (user_id, name, email, source) VALUES (?, 'Manual version', 'alice@example.com', 'manual')");
$manual->bindValue(1, $userId, SQLITE3_INTEGER);
$manual->execute();

$updated = LdapJitProvisioner::provision(
    $db,
    ldapEntry('alice', 'alice@example.com', 'Alice Updated', 'CN=Alice,OU=Staff,DC=example,DC=com'),
    $config
);
assertSameValue($userId, (int)$updated['id'], 'Repeat login should update the existing LDAP account');
assertSameValue('technician', $updated['role'], 'Existing LDAP role should be preserved');
assertSameValue('Alice Updated', $updated['full_name'], 'Directory profile should refresh');
assertSameValue(2, (int)$db->querySingle('SELECT COUNT(*) FROM user_signatures'), 'Repeat login should not duplicate the LDAP signature');
assertSameValue('Alice Updated', $db->querySingle("SELECT name FROM user_signatures WHERE user_id = $userId AND source = 'ldap'"), 'LDAP signature should refresh');
assertSameValue('Manual version', $db->querySingle("SELECT name FROM user_signatures WHERE user_id = $userId AND source = 'manual'"), 'Manual signature must remain untouched');

$db->exec("UPDATE users SET is_active = 0 WHERE id = $userId");
$inactiveRejected = false;
try {
    LdapJitProvisioner::provision(
        $db,
        ldapEntry('alice', 'alice@example.com', 'Alice Updated', 'CN=Alice,OU=Staff,DC=example,DC=com'),
        $config
    );
} catch (RuntimeException $e) {
    $inactiveRejected = true;
}
assertSameValue(true, $inactiveRejected, 'Deactivated SubSignature account should not be reactivated by JIT');

$local = $db->prepare("INSERT INTO users (username, password_hash, email, full_name, role, is_active, auth_source)
                       VALUES ('bob', 'local-hash', 'bob@example.com', 'Bob Local', 'admin', 1, 'local')");
$local->execute();
$collisionRejected = false;
try {
    LdapJitProvisioner::provision(
        $db,
        ldapEntry('bob', 'bob@example.com', 'Bob Directory', 'CN=Bob,OU=Staff,DC=example,DC=com', 'guid-2'),
        $config
    );
} catch (RuntimeException $e) {
    $collisionRejected = true;
}
assertSameValue(true, $collisionRejected, 'Existing local account must not be linked implicitly');
assertSameValue('local', $db->querySingle("SELECT auth_source FROM users WHERE username = 'bob'"), 'Local account auth source must remain unchanged');

$longIdUser = LdapJitProvisioner::provision(
    $db,
    ldapEntry('carol', 'carol@example.com', 'Carol Example', 'CN=Carol,OU=Staff,DC=example,DC=com', str_repeat('x', 200)),
    $config
);
assertSameValue('sha256:' . hash('sha256', str_repeat('x', 200)), $longIdUser['external_id'], 'Long directory IDs should not be truncated into collisions');

echo "LDAP JIT provisioning tests passed.\n";
