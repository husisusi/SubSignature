<?php
/**
 * includes/LdapService.php
 *
 * LDAP / Active Directory access for import and optional JIT login.
 *
 * Directory passwords are only passed to ldap_bind() for JIT authentication;
 * they are never read or stored. The service-account password is encrypted
 * at rest (see crypto.php).
 *
 * Contents:
 *   - LdapClientInterface   what the importer needs from a directory
 *   - LdapAuthenticatorInterface optional direct user authentication
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

interface LdapAuthenticatorInterface
{
    /**
     * Finds exactly one active directory user and authenticates its DN.
     * Returns the normalised entry on success, otherwise null.
     */
    public function authenticateUser(string $identifier, string $password): ?array;
}

class LdapService implements LdapClientInterface, LdapAuthenticatorInterface
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
        if (!empty($config['auth_enabled'])
            && (($config['encryption'] ?? 'none') === 'none'
                || empty($config['verify_cert'])
                || ($config['bind_dn'] ?? '') === ''
                || ($config['bind_pass'] ?? '') === '')) {
            throw new RuntimeException(t('LDAP login requires verified TLS and a service bind account.'));
        }
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

    public function authenticateUser(string $identifier, string $password): ?array
    {
        $c = $this->config;
        if ($c['encryption'] === 'none' || !$c['verify_cert'] || $c['bind_dn'] === '' || $c['bind_pass'] === '') {
            throw new RuntimeException(t('LDAP login requires verified TLS and a service bind account.'));
        }
        if (trim($identifier) === '' || strlen($identifier) > 254 || $password === '' || strlen($password) > 1024) {
            return null;
        }
        $attributes = array_values(array_unique(array_filter([
            $c['attr_username'], $c['attr_email'], $c['attr_name'], $c['attr_role'], $c['attr_phone'], $c['attr_id'],
        ])));
        $filter = self::buildUserFilter($c, $identifier);
        $entries = $this->search($c['base_dn'], $filter, $attributes, 2);

        if (count($entries) !== 1 || $entries[0]['dn'] === '') {
            return null;
        }
        if (!@ldap_bind($this->link, $entries[0]['dn'], $password)) {
            return null;
        }
        return $entries[0];
    }

    public static function buildUserFilter(array $config, string $identifier): string
    {
        if (!LdapConfig::isValidFilter($config['user_filter'] ?? '')) {
            throw new RuntimeException(t('The LDAP user filter is invalid.'));
        }

        $lookupAttributes = array_values(array_unique(array_filter([
            $config['attr_username'] ?? '',
            $config['attr_email'] ?? '',
        ])));
        foreach ($lookupAttributes as $attribute) {
            if (!LdapConfig::isValidAttributeName((string)$attribute)) {
                throw new RuntimeException(t('The LDAP username or email attribute is invalid.'));
            }
        }
        if (!$lookupAttributes) {
            throw new RuntimeException(t('An LDAP username or email attribute is required.'));
        }

        $escaped = ldap_escape($identifier, '', LDAP_ESCAPE_FILTER);
        $matches = array_map(
            static function (string $attribute) use ($escaped): string {
                return '(' . $attribute . '=' . $escaped . ')';
            },
            $lookupAttributes
        );
        return '(&' . $config['user_filter'] . '(|' . implode('', $matches) . '))';
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
        'template', 'target', 'auth_enabled',
    ];

    public static function defaults(): array
    {
        return array_merge([
            'host' => '', 'port' => 636, 'encryption' => 'ldaps', 'verify_cert' => true, 'ca_file' => '',
            'bind_dn' => '', 'bind_pass' => '', 'base_dn' => '', 'preset' => 'ad',
            'template' => '', 'target' => '', 'auth_enabled' => false,
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
                case 'auth_enabled':
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

    /** Settings that decide WHERE the bind password is sent and how the server is verified. */
    private const CONNECTION_KEYS = ['host', 'port', 'encryption', 'verify_cert', 'ca_file', 'bind_dn'];

    /**
     * True when $new points the stored bind password at a different server / account
     * or weakens how the server is verified.
     */
    public static function connectionChanged(array $old, array $new): bool
    {
        foreach (self::CONNECTION_KEYS as $key) {
            if (($old[$key] ?? null) !== ($new[$key] ?? null)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Validates posted form data. Returns [config, errors]. An empty password
     * field keeps the stored one ($currentPassword) - but only while the connection
     * settings (host, port, encryption, certificate check, CA file, bind account) stay
     * the same. Anyone who may edit these settings could otherwise redirect the stored
     * service-account password to a server of their own; so a changed connection
     * requires the password to be typed again ($current = the stored configuration).
     */
    public static function fromInput(array $in, string $currentPassword, ?array $current = null): array
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
        if ($newPass === '' && $current !== null && $currentPassword !== '' && self::connectionChanged($current, $cfg)) {
            $cfg['bind_pass'] = '';   // never carry the stored password over to a changed connection
            $errors[] = t('Please enter the bind password again when you change the server, port, encryption, certificate settings or bind account.');
        }

        $cfg['base_dn'] = cleanText($in['base_dn'] ?? '', 512);
        if ($cfg['base_dn'] === '') {
            $errors[] = 'Base DN is required (e.g. dc=example,dc=com).';
        }
        $cfg['auth_enabled'] = ($in['auth_enabled'] ?? '0') === '1';
        if ($cfg['auth_enabled']) {
            if ($cfg['encryption'] === 'none' || !$cfg['verify_cert']) {
                $errors[] = 'LDAP login requires LDAPS or STARTTLS with certificate verification enabled.';
            }
            if ($cfg['bind_dn'] === '' || $cfg['bind_pass'] === '') {
                $errors[] = 'LDAP login requires a service bind account and password.';
            }
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

        $cfg['template'] = isValidTemplateName($in['template'] ?? '') ? $in['template'] : '';
        // Default assignment of imported signatures: "auto" (by email) or a user id.
        // Whether the user still exists is checked when the preview is built.
        $target = (string)($in['target'] ?? '');
        $cfg['target'] = ($target === 'auto' || preg_match('/^[1-9]\d{0,9}$/', $target)) ? $target : '';

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
