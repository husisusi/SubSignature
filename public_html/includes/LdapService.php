<?php
/**
 * includes/LdapService.php
 *
 * LDAP / Active Directory access for the user IMPORT (read-only).
 *
 * Passwords of directory users are never read or checked: SubSignature does
 * not use LDAP for logging in. The only credentials used are those of a
 * read-only service account that is configured by an administrator; its
 * password is stored encrypted (see crypto.php).
 *
 * Contents:
 *   - LdapClientInterface   what the importer needs from a directory
 *   - LdapService           implementation on top of PHP's ldap extension
 *   - LdapConfig            settings storage, presets and validation
 */

interface LdapClientInterface
{
    /**
     * Runs a (paged) subtree search and returns normalised entries:
     * [ ['dn' => '...', 'attributes' => ['mail' => ['a@b.c'], ...]], ... ]
     * Attribute names are lower-case; values are always lists of strings.
     *
     * @throws RuntimeException on connection or search errors
     */
    public function search(string $baseDn, string $filter, array $attributes, int $limit = 0): array;
}

class LdapService implements LdapClientInterface
{
    private $link = null;
    private $config;

    /** Page size for the paged-results control (AD allows at most 1000 per request). */
    private const PAGE_SIZE = 500;

    /**
     * @param array $config Normalised configuration (see LdapConfig::load())
     * @throws RuntimeException
     */
    public function __construct(array $config)
    {
        if (!function_exists('ldap_connect')) {
            throw new RuntimeException(t('The PHP "ldap" extension is not installed.'));
        }
        $this->config = $config;
        $this->connect();
    }

    public function __destruct()
    {
        if ($this->link) {
            @ldap_unbind($this->link);
            $this->link = null;
        }
    }

    private function connect(): void
    {
        $c = $this->config;

        // TLS options are process-wide and must be set BEFORE the connection is created.
        // Certificate verification is on by default and can only be disabled explicitly.
        if ($c['encryption'] !== 'none') {
            $mode = $c['verify_cert'] ? LDAP_OPT_X_TLS_DEMAND : LDAP_OPT_X_TLS_NEVER;
            ldap_set_option(null, LDAP_OPT_X_TLS_REQUIRE_CERT, $mode);
            if ($c['ca_file'] !== '' && is_file($c['ca_file'])) {
                ldap_set_option(null, LDAP_OPT_X_TLS_CACERTFILE, $c['ca_file']);
            }
        }

        $scheme = $c['encryption'] === 'ldaps' ? 'ldaps' : 'ldap';
        $uri = $scheme . '://' . $c['host'] . ':' . (int)$c['port'];

        $link = @ldap_connect($uri);
        if (!$link) {
            throw new RuntimeException(t('Could not create the LDAP connection (check host and port).'));
        }
        ldap_set_option($link, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($link, LDAP_OPT_REFERRALS, 0);          // do not chase referrals (AD returns many)
        ldap_set_option($link, LDAP_OPT_NETWORK_TIMEOUT, 10);
        ldap_set_option($link, LDAP_OPT_TIMELIMIT, 60);

        if ($c['encryption'] === 'starttls' && !@ldap_start_tls($link)) {
            throw new RuntimeException(t('STARTTLS failed: {error}', ['error' => ldap_error($link)]));
        }

        // A DN with an empty password would be an "unauthenticated bind" which
        // many servers accept silently, so it is refused here.
        if ($c['bind_dn'] !== '') {
            if ($c['bind_pass'] === '') {
                throw new RuntimeException(t('A bind DN is configured but no bind password is set.'));
            }
            if (!@ldap_bind($link, $c['bind_dn'], $c['bind_pass'])) {
                throw new RuntimeException(t('Bind failed: {error}', ['error' => ldap_error($link)]));
            }
        } elseif (!@ldap_bind($link)) {
            throw new RuntimeException(t('Anonymous bind failed: {error}', ['error' => ldap_error($link)]));
        }

        $this->link = $link;
    }

    public function search(string $baseDn, string $filter, array $attributes, int $limit = 0): array
    {
        $entries = [];
        $cookie = '';
        $attributes = array_values(array_unique(array_map('strtolower', $attributes)));

        do {
            $controls = [[
                'oid'   => LDAP_CONTROL_PAGEDRESULTS,
                'value' => ['size' => self::PAGE_SIZE, 'cookie' => $cookie],
            ]];
            $result = @ldap_search($this->link, $baseDn, $filter, $attributes, 0, 0, 0, LDAP_DEREF_NEVER, $controls);
            if ($result === false) {
                throw new RuntimeException(t('Search failed: {error}', ['error' => ldap_error($this->link)]));
            }

            $errCode = 0;
            $matchedDn = '';
            $errMsg = '';
            $referrals = [];
            $responseControls = [];
            @ldap_parse_result($this->link, $result, $errCode, $matchedDn, $errMsg, $referrals, $responseControls);

            for ($entry = ldap_first_entry($this->link, $result); $entry; $entry = ldap_next_entry($this->link, $entry)) {
                $entries[] = $this->readEntry($entry);
                if ($limit > 0 && count($entries) >= $limit) {
                    return $entries;
                }
            }

            $cookie = $responseControls[LDAP_CONTROL_PAGEDRESULTS]['value']['cookie'] ?? '';
        } while ($cookie !== '' && $cookie !== null);

        return $entries;
    }

    /**
     * Converts one LDAP entry into a plain array.
     */
    private function readEntry($entry): array
    {
        $attributes = [];
        $raw = ldap_get_attributes($this->link, $entry);
        for ($i = 0; $i < ($raw['count'] ?? 0); $i++) {
            $name = strtolower($raw[$i]);
            $values = [];
            // Binary values (objectGUID, objectSid) are returned as hex strings.
            $bin = @ldap_get_values_len($this->link, $entry, $raw[$i]);
            if (is_array($bin)) {
                for ($v = 0; $v < ($bin['count'] ?? 0); $v++) {
                    $values[] = LdapService::normaliseValue($bin[$v]);
                }
            }
            $attributes[$name] = $values;
        }
        return ['dn' => (string)ldap_get_dn($this->link, $entry), 'attributes' => $attributes];
    }

    /**
     * Text values stay text; anything that is not valid, printable UTF-8 becomes hex.
     */
    public static function normaliseValue($value): string
    {
        $value = (string)$value;
        if ($value !== '' && (!mb_check_encoding($value, 'UTF-8') || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', $value))) {
            return bin2hex($value);
        }
        return $value;
    }
}

class LdapConfig
{
    public const PRESETS = [
        'ad' => [
            'label'         => 'Microsoft Active Directory',
            'user_filter'   => '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
            'attr_username' => 'sAMAccountName',
            'attr_email'    => 'mail',
            'attr_name'     => 'displayName',
            'attr_role'     => 'title',
            'attr_phone'    => 'telephoneNumber',
            'attr_id'       => 'objectGUID',
        ],
        'openldap' => [
            'label'         => 'OpenLDAP / inetOrgPerson',
            'user_filter'   => '(objectClass=inetOrgPerson)',
            'attr_username' => 'uid',
            'attr_email'    => 'mail',
            'attr_name'     => 'cn',
            'attr_role'     => 'title',
            'attr_phone'    => 'telephoneNumber',
            'attr_id'       => 'entryUUID',
        ],
    ];

    /** Keys stored in system_settings (prefixed with "ldap_"). */
    private const KEYS = [
        'host', 'port', 'encryption', 'verify_cert', 'ca_file', 'bind_dn', 'bind_pass', 'base_dn',
        'preset', 'user_filter', 'attr_username', 'attr_email', 'attr_name', 'attr_role', 'attr_phone', 'attr_id',
        'create_signatures', 'template', 'default_active', 'deactivate_missing',
    ];

    public static function defaults(): array
    {
        return array_merge([
            'host' => '', 'port' => 636, 'encryption' => 'ldaps', 'verify_cert' => true, 'ca_file' => '',
            'bind_dn' => '', 'bind_pass' => '', 'base_dn' => '', 'preset' => 'ad',
            'create_signatures' => true, 'template' => '', 'default_active' => true, 'deactivate_missing' => false,
        ], array_diff_key(self::PRESETS['ad'], ['label' => 1]));
    }

    /**
     * Loads the configuration; the bind password is decrypted.
     */
    public static function load($db): array
    {
        $cfg = self::defaults();
        foreach (self::KEYS as $key) {
            $stmt = $db->prepare('SELECT setting_value FROM system_settings WHERE setting_key = ?');
            $stmt->bindValue(1, 'ldap_' . $key, SQLITE3_TEXT);
            $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
            if (!$row) {
                continue;
            }
            $value = $row['setting_value'];
            switch ($key) {
                case 'port':
                    $cfg[$key] = (int)$value;
                    break;
                case 'verify_cert':
                case 'create_signatures':
                case 'default_active':
                case 'deactivate_missing':
                    $cfg[$key] = $value === '1';
                    break;
                case 'bind_pass':
                    $cfg[$key] = decryptSecret($value);
                    break;
                default:
                    $cfg[$key] = $value;
            }
        }
        return $cfg;
    }

    /**
     * Validates posted form data. Returns [config, errors]. An empty password
     * field keeps the stored one ($currentPassword).
     */
    public static function fromInput(array $in, string $currentPassword): array
    {
        $errors = [];
        $cfg = self::defaults();

        $cfg['preset'] = isset(self::PRESETS[$in['preset'] ?? '']) ? $in['preset'] : 'custom';

        $cfg['host'] = cleanText($in['host'] ?? '', 255);
        if ($cfg['host'] === '' || !preg_match('/^[A-Za-z0-9.\-]+$|^\[[0-9A-Fa-f:.]+\]$/', $cfg['host'])) {
            $errors[] = 'Host must be a plain host name or IP address (no "ldaps://" prefix, no port).';
        }

        $cfg['encryption'] = in_array($in['encryption'] ?? '', ['ldaps', 'starttls', 'none'], true) ? $in['encryption'] : 'ldaps';
        $cfg['port'] = (int)($in['port'] ?? 0);
        if ($cfg['port'] < 1 || $cfg['port'] > 65535) {
            $errors[] = 'Port must be between 1 and 65535.';
            $cfg['port'] = $cfg['encryption'] === 'ldaps' ? 636 : 389;
        }
        $cfg['verify_cert'] = ($in['verify_cert'] ?? '1') === '1';

        $cfg['ca_file'] = cleanText($in['ca_file'] ?? '', 255);
        if ($cfg['ca_file'] !== '' && (!preg_match('#^[A-Za-z0-9_./\\\\:\-]+$#', $cfg['ca_file']) || strpos($cfg['ca_file'], '..') !== false)) {
            $errors[] = 'Invalid CA file path.';
            $cfg['ca_file'] = '';
        }

        $cfg['bind_dn'] = cleanText($in['bind_dn'] ?? '', 512);
        $newPass = is_string($in['bind_pass'] ?? null) ? $in['bind_pass'] : '';
        $cfg['bind_pass'] = $newPass !== '' ? $newPass : $currentPassword;

        $cfg['base_dn'] = cleanText($in['base_dn'] ?? '', 512);
        if ($cfg['base_dn'] === '') {
            $errors[] = 'Base DN is required (e.g. dc=example,dc=com).';
        }

        if ($cfg['preset'] !== 'custom') {
            // A preset fills filter and attribute names.
            foreach (self::PRESETS[$cfg['preset']] as $k => $v) {
                if ($k !== 'label') {
                    $cfg[$k] = $v;
                }
            }
        }
        // Individual fields can still be overridden ("custom" or fine-tuning).
        $cfg['user_filter'] = trim((string)($in['user_filter'] ?? $cfg['user_filter']));
        if (!self::isValidFilter($cfg['user_filter'])) {
            $errors[] = 'The user filter must be a valid LDAP filter, e.g. (objectClass=person).';
            $cfg['user_filter'] = self::PRESETS['ad']['user_filter'];
        }
        foreach (['attr_username' => 'Username', 'attr_email' => 'Email', 'attr_name' => 'Full name', 'attr_role' => 'Role', 'attr_phone' => 'Phone', 'attr_id' => 'Unique ID'] as $key => $label) {
            $v = trim((string)($in[$key] ?? $cfg[$key]));
            if ($v === '' && in_array($key, ['attr_role', 'attr_phone'], true)) {
                $cfg[$key] = '';
            } elseif (!self::isValidAttributeName($v)) {
                $errors[] = $label . ' attribute name is invalid.';
            } else {
                $cfg[$key] = $v;
            }
        }

        $cfg['create_signatures'] = ($in['create_signatures'] ?? '0') === '1';
        $cfg['template'] = isValidTemplateName($in['template'] ?? '') ? $in['template'] : '';
        $cfg['default_active'] = ($in['default_active'] ?? '1') === '1';
        $cfg['deactivate_missing'] = ($in['deactivate_missing'] ?? '0') === '1';

        return [$cfg, $errors];
    }

    public static function save($db, array $cfg): void
    {
        foreach (self::KEYS as $key) {
            $value = $cfg[$key] ?? '';
            if (is_bool($value)) {
                $value = $value ? '1' : '0';
            } elseif ($key === 'bind_pass') {
                $value = $value === '' ? '' : encryptSecret((string)$value);
            }
            setSetting($db, 'ldap_' . $key, (string)$value);
        }
    }

    public static function isValidAttributeName(string $name): bool
    {
        return preg_match('/^[A-Za-z][A-Za-z0-9\-]{0,63}(;[A-Za-z0-9\-]{1,32})?$/', $name) === 1;
    }

    /**
     * Light syntax check: starts with "(", ends with ")", parentheses are balanced.
     * (The filter is entered by an administrator; no end-user data is ever put into it.)
     */
    public static function isValidFilter(string $filter): bool
    {
        if ($filter === '' || strlen($filter) > 2000 || $filter[0] !== '(' || substr($filter, -1) !== ')') {
            return false;
        }
        if (preg_match('/[\x00-\x1F]/', $filter)) {
            return false;
        }
        $depth = 0;
        $len = strlen($filter);
        for ($i = 0; $i < $len; $i++) {
            if ($filter[$i] === '\\') {
                $i++;               // skip escaped character
            } elseif ($filter[$i] === '(') {
                $depth++;
            } elseif ($filter[$i] === ')') {
                $depth--;
                if ($depth < 0) {
                    return false;
                }
            }
        }
        return $depth === 0;
    }
}
