<?php
/**
 * includes/LdapImporter.php
 *
 * Turns directory entries into SIGNATURES that are assigned to an existing
 * SubSignature user. No user accounts are created or changed.
 *
 * Two steps, so that nothing changes before an administrator has seen the result:
 *   1. fetchRows() reads the directory and validates every entry (read-only)
 *   2. evaluate()  compares the rows with the database for a chosen target user
 *      and template; applyPlan() then writes the selected rows in one transaction
 *
 * Rules:
 *   - Directory data is untrusted and validated like manual input.
 *   - Only signatures with source = 'ldap' are ever updated. Signatures that
 *     were created manually or by CSV import are never touched.
 *   - An imported signature is recognised again by its directory key (unique ID,
 *     or the DN if there is no unique ID), so repeated imports update instead of
 *     duplicating.
 *   - The target is either one chosen user, or "auto": every entry goes to the
 *     active user that has the same email address.
 */
class LdapImporter
{
    public const ACTION_CREATE    = 'create';
    public const ACTION_UPDATE    = 'update';
    public const ACTION_UNCHANGED = 'unchanged';
    public const ACTION_SKIP      = 'skip';

    public const TARGET_AUTO = 'auto';

    /** Upper limit of directory entries shown / processed in one run. */
    public const MAX_ENTRIES = 5000;

    private $db;
    private $config;

    public function __construct($db, array $config)
    {
        $this->db = $db;
        $this->config = $config;
    }

    /**
     * Attributes requested from the directory.
     */
    public function requestedAttributes(): array
    {
        $c = $this->config;
        return array_values(array_filter(array_unique([
            $c['attr_username'], $c['attr_email'], $c['attr_name'], $c['attr_role'], $c['attr_phone'], $c['attr_id'],
        ])));
    }

    /**
     * Reads and validates the directory entries.
     *
     * @return array ['rows' => [...], 'truncated' => bool]; every row has an 'idx'
     */
    public function fetchRows(LdapClientInterface $client): array
    {
        $entries = $client->search(
            $this->config['base_dn'],
            $this->config['user_filter'],
            $this->requestedAttributes(),
            self::MAX_ENTRIES
        );

        $rows = [];
        $seenKeys = [];
        $seenEmails = [];

        foreach ($entries as $entry) {
            $row = $this->mapEntry($entry);

            if ($row['action'] !== self::ACTION_SKIP) {
                $eKey = mb_strtolower($row['email'], 'UTF-8');
                if (isset($seenKeys[$row['key']])) {
                    $row = $this->skip($row, t('Duplicate entry in directory result'));
                } elseif (isset($seenEmails[$eKey])) {
                    $row = $this->skip($row, t('Email address used by another directory entry'));
                } else {
                    $seenKeys[$row['key']] = true;
                    $seenEmails[$eKey] = true;
                }
            }
            $row['idx'] = count($rows);
            $rows[] = $row;
        }

        return ['rows' => $rows, 'truncated' => count($entries) >= self::MAX_ENTRIES];
    }

    /**
     * Maps and validates one directory entry.
     */
    private function mapEntry(array $entry): array
    {
        $c = $this->config;
        $get = function (string $attr) use ($entry): string {
            if ($attr === '') return '';
            $vals = $entry['attributes'][strtolower($attr)] ?? [];
            return (string)($vals[0] ?? '');
        };

        $row = [
            'idx'      => 0,
            'action'   => 'pending',
            'reason'   => '',
            'dn'       => cleanText($entry['dn'] ?? '', 512),
            'username' => cleanText($get($c['attr_username']), 64),
            'email'    => cleanText($get($c['attr_email']), 254),
            'name'     => cleanText($get($c['attr_name']), 100),
            'role'     => cleanText($get($c['attr_role']), 100),
            'phone'    => cleanText($get($c['attr_phone']), 30),
            'key'      => cleanText($get($c['attr_id']), 128),
            'user_id'  => 0,
            'user'     => '',
            'sig_id'   => 0,
        ];

        // Stable identity of the entry: the unique ID, otherwise the DN.
        if ($row['key'] === '') {
            $row['key'] = $row['dn'];
        }
        if ($row['key'] === '') {
            return $this->skip($row, t('Entry has neither a unique ID nor a DN'));
        }
        if ($row['email'] === '' || !filter_var($row['email'], FILTER_VALIDATE_EMAIL)) {
            return $this->skip($row, t('Missing or invalid email address'));
        }
        if ($row['name'] === '') {
            $row['name'] = $row['username'] !== '' ? $row['username'] : strstr($row['email'], '@', true);
        }
        // A phone number the signature validation would reject is dropped.
        if ($row['phone'] !== '' && !preg_match('/^[\+\d\s\-\(\)\/\.]{5,30}$/', $row['phone'])) {
            $row['phone'] = '';
        }
        return $row;
    }

    private function skip(array $row, string $reason): array
    {
        $row['action'] = self::ACTION_SKIP;
        $row['reason'] = $reason;
        return $row;
    }

    /**
     * Normalises a posted target: "auto" or the id of an active user, otherwise null.
     */
    public function normalizeTarget($raw): ?string
    {
        if ($raw === self::TARGET_AUTO) {
            return self::TARGET_AUTO;
        }
        if (is_string($raw) && preg_match('/^[1-9]\d{0,9}$/', $raw) && $this->activeUser((int)$raw) !== null) {
            return $raw;
        }
        return null;
    }

    /** @return array|null id, username, full_name of an active user */
    private function activeUser(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT id, username, full_name FROM users WHERE id = ? AND is_active = 1');
        $stmt->bindValue(1, $id, SQLITE3_INTEGER);
        return $stmt->execute()->fetchArray(SQLITE3_ASSOC) ?: null;
    }

    private static function userLabel(array $u): string
    {
        $name = trim((string)($u['full_name'] ?? ''));
        return $name !== '' && $name !== $u['username'] ? $name . ' (' . $u['username'] . ')' : (string)$u['username'];
    }

    /**
     * Decides create / update / unchanged / skip for every row, for the chosen
     * target and template.
     *
     * @param array  $rows          rows from fetchRows()
     * @param string $target        "auto" or a user id
     * @param string $template      template file name or "" for the system default
     * @param bool   $applyTemplate also change the template of signatures that already exist
     * @return array ['rows' => [...], 'counts' => [...]]
     */
    public function evaluate(array $rows, string $target, string $template, bool $applyTemplate): array
    {
        $effectiveTemplate = $template !== '' ? resolveTemplateName($template) : getDefaultTemplateName();

        // Resolve the target user(s).
        $fixedUser = null;
        $emailMap = [];
        if ($target === self::TARGET_AUTO) {
            $res = $this->db->query("SELECT id, username, full_name, email FROM users WHERE is_active = 1 AND email IS NOT NULL AND email != ''");
            while ($u = $res->fetchArray(SQLITE3_ASSOC)) {
                $emailMap[mb_strtolower($u['email'], 'UTF-8')] = $u;
            }
        } else {
            $fixedUser = $this->activeUser((int)$target);
        }

        $find = $this->db->prepare("SELECT id, name, role, email, phone, template, ldap_key FROM user_signatures
            WHERE user_id = ? AND source = 'ldap' AND (ldap_key = ? OR (ldap_key IS NULL AND LOWER(email) = LOWER(?)))
            ORDER BY (ldap_key = ?) DESC LIMIT 1");

        $counts = [self::ACTION_CREATE => 0, self::ACTION_UPDATE => 0, self::ACTION_UNCHANGED => 0, self::ACTION_SKIP => 0];
        $out = [];

        foreach ($rows as $row) {
            if ($row['action'] !== self::ACTION_SKIP) {
                $user = $fixedUser;
                if ($target === self::TARGET_AUTO) {
                    $user = $emailMap[mb_strtolower($row['email'], 'UTF-8')] ?? null;
                    if ($user === null) {
                        $row = $this->skip($row, t('No active user with this email address'));
                    }
                } elseif ($user === null) {
                    $row = $this->skip($row, t('The selected user does not exist or is not active.'));
                }

                if ($row['action'] !== self::ACTION_SKIP) {
                    $row['user_id'] = (int)$user['id'];
                    $row['user'] = self::userLabel($user);
                    $row['reason'] = '';

                    $find->bindValue(1, $row['user_id'], SQLITE3_INTEGER);
                    $find->bindValue(2, $row['key'], SQLITE3_TEXT);
                    $find->bindValue(3, $row['email'], SQLITE3_TEXT);
                    $find->bindValue(4, $row['key'], SQLITE3_TEXT);
                    $existing = $find->execute()->fetchArray(SQLITE3_ASSOC) ?: null;

                    if (!$existing) {
                        $row['action'] = self::ACTION_CREATE;
                        $row['sig_id'] = 0;
                    } else {
                        $row['sig_id'] = (int)$existing['id'];
                        $changed = (string)$existing['name'] !== $row['name']
                            || (string)$existing['role'] !== $row['role']
                            || (string)$existing['email'] !== $row['email']
                            || (string)$existing['phone'] !== $row['phone']
                            || (string)($existing['ldap_key'] ?? '') !== $row['key']
                            || ($applyTemplate && (string)$existing['template'] !== $effectiveTemplate);
                        $row['action'] = $changed ? self::ACTION_UPDATE : self::ACTION_UNCHANGED;
                    }
                }
            }
            $counts[$row['action']]++;
            $out[] = $row;
        }
        $counts['total'] = count($out);

        return ['rows' => $out, 'counts' => $counts];
    }

    /**
     * Writes the selected rows. Everything happens in one transaction: all or nothing.
     * The rows are evaluated again inside the transaction, because the preview may be
     * a few minutes old.
     *
     * @param array $rows     rows from fetchRows()
     * @param int[] $selected row indices (idx) chosen by the administrator
     * @return array counts: created, updated, unchanged, skipped
     * @throws Exception
     */
    public function applyPlan(array $rows, string $target, string $template, bool $applyTemplate, array $selected): array
    {
        $db = $this->db;
        $effectiveTemplate = $template !== '' ? resolveTemplateName($template) : getDefaultTemplateName();
        $chosen = array_fill_keys(array_map('intval', $selected), true);
        $result = ['created' => 0, 'updated' => 0, 'unchanged' => 0, 'skipped' => 0];

        $db->exec('BEGIN IMMEDIATE');
        try {
            $evaluated = $this->evaluate($rows, $target, $template, $applyTemplate);

            foreach ($evaluated['rows'] as $row) {
                if (!isset($chosen[$row['idx']])) {
                    continue;
                }
                switch ($row['action']) {
                    case self::ACTION_CREATE:
                        $in = $db->prepare("INSERT INTO user_signatures (user_id, name, role, email, phone, template, source, ldap_key, updated_at)
                                            VALUES (?, ?, ?, ?, ?, ?, 'ldap', ?, datetime('now'))");
                        $in->bindValue(1, $row['user_id'], SQLITE3_INTEGER);
                        $in->bindValue(2, $row['name'], SQLITE3_TEXT);
                        $in->bindValue(3, $row['role'], SQLITE3_TEXT);
                        $in->bindValue(4, $row['email'], SQLITE3_TEXT);
                        $in->bindValue(5, $row['phone'], SQLITE3_TEXT);
                        $in->bindValue(6, $effectiveTemplate, SQLITE3_TEXT);
                        $in->bindValue(7, $row['key'], SQLITE3_TEXT);
                        $in->execute();
                        $result['created']++;
                        break;

                    case self::ACTION_UPDATE:
                        $sql = "UPDATE user_signatures SET name = ?, role = ?, email = ?, phone = ?, ldap_key = ?"
                             . ($applyTemplate ? ', template = ?' : '')
                             . ", updated_at = datetime('now') WHERE id = ? AND user_id = ? AND source = 'ldap'";
                        $up = $db->prepare($sql);
                        $n = 1;
                        $up->bindValue($n++, $row['name'], SQLITE3_TEXT);
                        $up->bindValue($n++, $row['role'], SQLITE3_TEXT);
                        $up->bindValue($n++, $row['email'], SQLITE3_TEXT);
                        $up->bindValue($n++, $row['phone'], SQLITE3_TEXT);
                        $up->bindValue($n++, $row['key'], SQLITE3_TEXT);
                        if ($applyTemplate) {
                            $up->bindValue($n++, $effectiveTemplate, SQLITE3_TEXT);
                        }
                        $up->bindValue($n++, $row['sig_id'], SQLITE3_INTEGER);
                        $up->bindValue($n++, $row['user_id'], SQLITE3_INTEGER);
                        $up->execute();
                        $result['updated']++;
                        break;

                    case self::ACTION_UNCHANGED:
                        $result['unchanged']++;
                        break;

                    default:
                        $result['skipped']++;
                }
            }

            $db->exec('COMMIT');
        } catch (Exception $e) {
            $db->exec('ROLLBACK');
            throw $e;
        }
        return $result;
    }
}
