<?php
/**
 * includes/LdapImporter.php
 *
 * Turns directory entries into SubSignature users (and optionally signatures).
 *
 * Two steps, so that nothing changes before an administrator has seen the result:
 *   1. buildPlan()  reads the directory and compares it with the database (read-only)
 *   2. applyPlan()  writes the plan in one transaction
 *
 * Safety rules:
 *   - Directory users never get a usable password (import, not login).
 *   - Directory data can never create or change administrators: new accounts
 *     are always role "user".
 *   - Existing LOCAL accounts are never modified. A directory entry whose
 *     username or email collides with a local account is skipped and reported.
 *   - All values are validated like manual input; directory data is untrusted.
 */
class LdapImporter
{
    public const ACTION_CREATE    = 'create';
    public const ACTION_UPDATE    = 'update';
    public const ACTION_UNCHANGED = 'unchanged';
    public const ACTION_SKIP      = 'skip';

    /** Upper limit of directory entries processed in one run. */
    public const MAX_ENTRIES = 20000;

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
     * Reads the directory and creates the plan.
     *
     * @return array ['rows' => [...], 'counts' => [...], 'deactivate' => [user ids]]
     */
    public function buildPlan(LdapClientInterface $client): array
    {
        $entries = $client->search(
            $this->config['base_dn'],
            $this->config['user_filter'],
            $this->requestedAttributes(),
            self::MAX_ENTRIES
        );

        $rows = [];
        $seenUsernames = [];
        $seenIds = [];
        $seenEmails = [];

        foreach ($entries as $entry) {
            $row = $this->mapEntry($entry);

            // Two directory entries must not claim the same username / id / email.
            if ($row['action'] !== self::ACTION_SKIP) {
                $uKey = mb_strtolower($row['username'], 'UTF-8');
                $eKey = mb_strtolower($row['email'], 'UTF-8');
                if (isset($seenUsernames[$uKey])) {
                    $row = $this->skip($row, 'Duplicate username in directory result');
                } elseif ($row['external_id'] !== '' && isset($seenIds[$row['external_id']])) {
                    $row = $this->skip($row, 'Duplicate unique ID in directory result');
                } elseif ($eKey !== '' && isset($seenEmails[$eKey])) {
                    $row = $this->skip($row, 'Email address used by another directory entry');
                }
            }
            if ($row['action'] !== self::ACTION_SKIP) {
                $seenUsernames[mb_strtolower($row['username'], 'UTF-8')] = true;
                if ($row['external_id'] !== '') $seenIds[$row['external_id']] = true;
                if ($row['email'] !== '') $seenEmails[mb_strtolower($row['email'], 'UTF-8')] = true;
                $row = $this->compareWithDatabase($row);
            }
            $rows[] = $row;
        }

        // Directory accounts that are in the database but not in the result any more.
        $deactivate = [];
        if ($this->config['deactivate_missing'] && count($entries) > 0) {
            // Accounts that were matched (also after a rename) are still present.
            $matchedIds = [];
            foreach ($rows as $r) {
                if ($r['action'] !== self::ACTION_SKIP && $r['user_id'] > 0) {
                    $matchedIds[$r['user_id']] = true;
                }
            }
            $stmt = $this->db->prepare("SELECT id, username FROM users WHERE auth_source = 'ldap' AND is_active = 1");
            $res = $stmt->execute();
            while ($u = $res->fetchArray(SQLITE3_ASSOC)) {
                if (!isset($matchedIds[(int)$u['id']]) && !isset($seenUsernames[mb_strtolower($u['username'], 'UTF-8')])) {
                    $deactivate[] = (int)$u['id'];
                }
            }
        }

        $counts = [self::ACTION_CREATE => 0, self::ACTION_UPDATE => 0, self::ACTION_UNCHANGED => 0, self::ACTION_SKIP => 0];
        foreach ($rows as $r) {
            $counts[$r['action']]++;
        }
        $counts['deactivate'] = count($deactivate);
        $counts['total'] = count($rows);

        return ['rows' => $rows, 'counts' => $counts, 'deactivate' => $deactivate];
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
            'action'      => self::ACTION_CREATE,
            'reason'      => '',
            'dn'          => cleanText($entry['dn'] ?? '', 512),
            'username'    => cleanText($get($c['attr_username']), 64),
            'email'       => cleanText($get($c['attr_email']), 254),
            'name'        => cleanText($get($c['attr_name']), 100),
            'role'        => cleanText($get($c['attr_role']), 100),
            'phone'       => cleanText($get($c['attr_phone']), 30),
            'external_id' => cleanText($get($c['attr_id']), 128),
            'user_id'     => 0,
        ];

        if ($row['username'] === '' || !isValidUsername($row['username'])) {
            return $this->skip($row, 'Missing or invalid username (allowed: letters, digits, . _ - @, 3-64 characters)');
        }
        if ($row['email'] !== '' && !filter_var($row['email'], FILTER_VALIDATE_EMAIL)) {
            // An invalid address is dropped instead of skipping the whole user.
            $row['email'] = '';
        }
        if ($row['name'] === '') {
            $row['name'] = $row['username'];
        }
        // A phone number the signature validation would reject is dropped as well.
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
     * Decides create / update / unchanged for a valid row.
     */
    private function compareWithDatabase(array $row): array
    {
        $existing = null;

        // 1. Match by the directory's stable unique ID (survives renames).
        if ($row['external_id'] !== '') {
            $stmt = $this->db->prepare("SELECT * FROM users WHERE auth_source = 'ldap' AND external_id = ?");
            $stmt->bindValue(1, $row['external_id'], SQLITE3_TEXT);
            $existing = $stmt->execute()->fetchArray(SQLITE3_ASSOC) ?: null;
        }
        // 2. Match by username, but only against directory accounts.
        if (!$existing) {
            $stmt = $this->db->prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)');
            $stmt->bindValue(1, $row['username'], SQLITE3_TEXT);
            $byName = $stmt->execute()->fetchArray(SQLITE3_ASSOC) ?: null;
            if ($byName) {
                if (($byName['auth_source'] ?? 'local') !== 'ldap') {
                    return $this->skip($row, 'Username belongs to a local account (not modified)');
                }
                $existing = $byName;
            }
        }

        // The email must not belong to a different account.
        if ($row['email'] !== '') {
            $stmt = $this->db->prepare('SELECT COUNT(*) FROM users WHERE LOWER(email) = LOWER(?) AND id != ?');
            $stmt->bindValue(1, $row['email'], SQLITE3_TEXT);
            $stmt->bindValue(2, $existing ? (int)$existing['id'] : 0, SQLITE3_INTEGER);
            if ((int)$stmt->execute()->fetchArray(SQLITE3_NUM)[0] > 0) {
                return $this->skip($row, 'Email address is used by another account');
            }
        }

        if (!$existing) {
            $row['action'] = self::ACTION_CREATE;
            return $row;
        }

        // A renamed directory account must not collide with another user.
        if (mb_strtolower($existing['username'], 'UTF-8') !== mb_strtolower($row['username'], 'UTF-8')) {
            $stmt = $this->db->prepare('SELECT COUNT(*) FROM users WHERE LOWER(username) = LOWER(?) AND id != ?');
            $stmt->bindValue(1, $row['username'], SQLITE3_TEXT);
            $stmt->bindValue(2, (int)$existing['id'], SQLITE3_INTEGER);
            if ((int)$stmt->execute()->fetchArray(SQLITE3_NUM)[0] > 0) {
                return $this->skip($row, 'New username collides with another account');
            }
        }

        $row['user_id'] = (int)$existing['id'];
        $changed = $existing['username'] !== $row['username']
            || (string)$existing['email'] !== $row['email']
            || (string)$existing['full_name'] !== $row['name']
            || (string)($existing['external_id'] ?? '') !== $row['external_id']
            || (string)($existing['ldap_dn'] ?? '') !== $row['dn'];
        $row['action'] = $changed ? self::ACTION_UPDATE : self::ACTION_UNCHANGED;
        return $row;
    }

    /**
     * Writes the plan. Everything happens in one transaction: all or nothing.
     *
     * @return array counts: created, updated, signatures, deactivated, skipped
     * @throws Exception
     */
    public function applyPlan(array $plan): array
    {
        $db = $this->db;
        $result = ['created' => 0, 'updated' => 0, 'signatures' => 0, 'deactivated' => 0, 'skipped' => 0];
        $template = $this->config['template'] !== '' ? resolveTemplateName($this->config['template']) : getDefaultTemplateName();

        $db->exec('BEGIN IMMEDIATE');
        try {
            foreach ($plan['rows'] as $row) {
                if ($row['action'] === self::ACTION_SKIP) {
                    $result['skipped']++;
                    continue;
                }

                $userId = (int)$row['user_id'];

                if ($row['action'] === self::ACTION_CREATE) {
                    // Re-check inside the transaction: the plan may be a few minutes old.
                    $chk = $db->prepare('SELECT COUNT(*) FROM users WHERE LOWER(username) = LOWER(?) OR (? != \'\' AND LOWER(email) = LOWER(?))');
                    $chk->bindValue(1, $row['username'], SQLITE3_TEXT);
                    $chk->bindValue(2, $row['email'], SQLITE3_TEXT);
                    $chk->bindValue(3, $row['email'], SQLITE3_TEXT);
                    if ((int)$chk->execute()->fetchArray(SQLITE3_NUM)[0] > 0) {
                        $result['skipped']++;
                        continue;
                    }

                    $stmt = $db->prepare("INSERT INTO users
                        (username, password_hash, email, full_name, role, is_active, created_at, auth_source, external_id, ldap_dn, ldap_synced_at)
                        VALUES (?, ?, ?, ?, 'user', ?, datetime('now'), 'ldap', ?, ?, datetime('now'))");
                    $stmt->bindValue(1, $row['username'], SQLITE3_TEXT);
                    // Random, unknown password: the account cannot be used to log in.
                    $stmt->bindValue(2, password_hash(bin2hex(random_bytes(32)), PASSWORD_DEFAULT), SQLITE3_TEXT);
                    $stmt->bindValue(3, $row['email'], SQLITE3_TEXT);
                    $stmt->bindValue(4, $row['name'], SQLITE3_TEXT);
                    $stmt->bindValue(5, $this->config['default_active'] ? 1 : 0, SQLITE3_INTEGER);
                    $stmt->bindValue(6, $row['external_id'] !== '' ? $row['external_id'] : null, $row['external_id'] !== '' ? SQLITE3_TEXT : SQLITE3_NULL);
                    $stmt->bindValue(7, $row['dn'], SQLITE3_TEXT);
                    $stmt->execute();
                    $userId = (int)$db->lastInsertRowID();

                    $st = $db->prepare('INSERT INTO user_settings (user_id) VALUES (?)');
                    $st->bindValue(1, $userId, SQLITE3_INTEGER);
                    $st->execute();
                    $result['created']++;
                } elseif ($row['action'] === self::ACTION_UPDATE) {
                    // Only accounts that came from the directory are touched.
                    $stmt = $db->prepare("UPDATE users SET username = ?, email = ?, full_name = ?, external_id = ?, ldap_dn = ?, ldap_synced_at = datetime('now')
                                          WHERE id = ? AND auth_source = 'ldap'");
                    $stmt->bindValue(1, $row['username'], SQLITE3_TEXT);
                    $stmt->bindValue(2, $row['email'], SQLITE3_TEXT);
                    $stmt->bindValue(3, $row['name'], SQLITE3_TEXT);
                    $stmt->bindValue(4, $row['external_id'] !== '' ? $row['external_id'] : null, $row['external_id'] !== '' ? SQLITE3_TEXT : SQLITE3_NULL);
                    $stmt->bindValue(5, $row['dn'], SQLITE3_TEXT);
                    $stmt->bindValue(6, $userId, SQLITE3_INTEGER);
                    $stmt->execute();
                    if ($db->changes() === 0) {
                        $result['skipped']++;
                        continue;
                    }
                    $result['updated']++;
                } else { // unchanged
                    $stmt = $db->prepare("UPDATE users SET ldap_synced_at = datetime('now') WHERE id = ? AND auth_source = 'ldap'");
                    $stmt->bindValue(1, $userId, SQLITE3_INTEGER);
                    $stmt->execute();
                }

                if ($this->config['create_signatures'] && $userId > 0) {
                    $result['signatures'] += $this->upsertSignature($userId, $row, $template);
                }
            }

            foreach ($plan['deactivate'] as $id) {
                $stmt = $db->prepare("UPDATE users SET is_active = 0 WHERE id = ? AND auth_source = 'ldap'");
                $stmt->bindValue(1, (int)$id, SQLITE3_INTEGER);
                $stmt->execute();
                $result['deactivated'] += $db->changes();
            }

            $db->exec('COMMIT');
        } catch (Exception $e) {
            $db->exec('ROLLBACK');
            throw $e;
        }
        return $result;
    }

    /**
     * Creates or refreshes the signature that belongs to a directory user.
     * Only the row marked source='ldap' is managed here; signatures the user
     * created manually are never touched.
     *
     * @return int 1 if a row was written
     */
    private function upsertSignature(int $userId, array $row, string $template): int
    {
        // Signatures need name, role, email and phone like a manual entry; incomplete directory
        // entries get a signature only if there is at least an email address.
        if ($row['email'] === '') {
            return 0;
        }
        $db = $this->db;
        $stmt = $db->prepare("SELECT id FROM user_signatures WHERE user_id = ? AND source = 'ldap'");
        $stmt->bindValue(1, $userId, SQLITE3_INTEGER);
        $existing = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

        if ($existing) {
            $up = $db->prepare("UPDATE user_signatures SET name = ?, role = ?, email = ?, phone = ?, updated_at = datetime('now') WHERE id = ?");
            $up->bindValue(1, $row['name'], SQLITE3_TEXT);
            $up->bindValue(2, $row['role'], SQLITE3_TEXT);
            $up->bindValue(3, $row['email'], SQLITE3_TEXT);
            $up->bindValue(4, $row['phone'], SQLITE3_TEXT);
            $up->bindValue(5, (int)$existing['id'], SQLITE3_INTEGER);
            $up->execute();
        } else {
            $in = $db->prepare("INSERT INTO user_signatures (user_id, name, role, email, phone, template, source, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'ldap', datetime('now'))");
            $in->bindValue(1, $userId, SQLITE3_INTEGER);
            $in->bindValue(2, $row['name'], SQLITE3_TEXT);
            $in->bindValue(3, $row['role'], SQLITE3_TEXT);
            $in->bindValue(4, $row['email'], SQLITE3_TEXT);
            $in->bindValue(5, $row['phone'], SQLITE3_TEXT);
            $in->bindValue(6, $template, SQLITE3_TEXT);
            $in->execute();
        }
        return 1;
    }
}
