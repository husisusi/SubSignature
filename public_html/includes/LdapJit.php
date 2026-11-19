<?php
/**
 * Provisions a SubSignature account and signature after successful LDAP login.
 */
class LdapJitProvisioner
{
    /**
     * Creates or refreshes one LDAP-backed account and its signature atomically.
     *
     * Existing local accounts are never linked implicitly. Existing LDAP users
     * keep their role and activation status.
     *
     * @throws RuntimeException when the directory identity conflicts with a local account
     */
    public static function provision(SQLite3 $db, array $entry, array $config): array
    {
        $dn = (string)($entry['dn'] ?? '');
        $attributes = $entry['attributes'] ?? [];
        if ($dn === '' || strlen($dn) > 2048 || preg_match('/[\x00-\x1F\x7F]/', $dn) || !is_array($attributes)) {
            throw new RuntimeException('The LDAP entry is incomplete.');
        }

        $get = static function (string $attribute) use ($attributes): string {
            if ($attribute === '') {
                return '';
            }
            $values = $attributes[strtolower($attribute)] ?? [];
            return is_array($values) ? (string)($values[0] ?? '') : '';
        };

        $username = cleanText($get((string)$config['attr_username']), 64);
        $email = cleanText($get((string)$config['attr_email']), 254);
        $name = cleanText($get((string)$config['attr_name']), 100);
        $role = cleanText($get((string)$config['attr_role']), 100);
        $phone = cleanText($get((string)$config['attr_phone']), 30);
        $externalId = cleanText($get((string)$config['attr_id']), 1024);

        if (!isValidUsername($username) || $email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new RuntimeException('The LDAP account is missing a valid username or email address.');
        }
        if ($name === '') {
            $name = $username;
        }
        if ($phone !== '' && !preg_match('/^[\+\d\s\-\(\)\/\.]{5,30}$/', $phone)) {
            $phone = '';
        }
        [, $fieldErrors] = validateSignatureFields([
            'name' => $name,
            'role' => $role,
            'email' => $email,
            'phone' => $phone,
        ], false);
        if ($fieldErrors) {
            throw new RuntimeException('The LDAP account contains invalid signature data.');
        }

        if ($externalId === '') {
            $externalId = 'dn:' . hash('sha256', $dn);
        } elseif (strlen($externalId) > 128) {
            $externalId = 'sha256:' . hash('sha256', $externalId);
        }
        $template = resolveTemplateName(getDefaultTemplateName());

        $db->exec('BEGIN IMMEDIATE');
        try {
            $find = $db->prepare("SELECT id, username, is_active FROM users
                                  WHERE auth_source = 'ldap' AND (external_id = ? OR ldap_dn = ?)
                                  LIMIT 2");
            $find->bindValue(1, $externalId, SQLITE3_TEXT);
            $find->bindValue(2, $dn, SQLITE3_TEXT);
            $result = $find->execute();
            $existing = $result->fetchArray(SQLITE3_ASSOC) ?: null;
            if ($existing && $result->fetchArray(SQLITE3_ASSOC)) {
                throw new RuntimeException('The LDAP identity matches multiple accounts.');
            }

            if ($existing && (int)$existing['is_active'] !== 1) {
                throw new RuntimeException('The SubSignature account is deactivated.');
            }

            $collision = $db->prepare("SELECT id FROM users
                                       WHERE username = ? COLLATE NOCASE
                                          OR (email IS NOT NULL AND email != '' AND LOWER(email) = LOWER(?))
                                       LIMIT 2");
            $collision->bindValue(1, $username, SQLITE3_TEXT);
            $collision->bindValue(2, $email, SQLITE3_TEXT);
            $collisionResult = $collision->execute();
            $collisionId = $collisionResult->fetchArray(SQLITE3_ASSOC) ?: null;
            while ($collisionId && (int)$collisionId['id'] === (int)($existing['id'] ?? 0)) {
                $collisionId = $collisionResult->fetchArray(SQLITE3_ASSOC) ?: null;
            }
            if ($collisionId) {
                throw new RuntimeException('The LDAP identity conflicts with an existing local account.');
            }

            if ($existing) {
                $userId = (int)$existing['id'];
                $update = $db->prepare("UPDATE users
                                        SET username = ?, email = ?, full_name = ?, external_id = ?, ldap_dn = ?,
                                            ldap_synced_at = datetime('now')
                                        WHERE id = ? AND auth_source = 'ldap'");
                $update->bindValue(1, $username, SQLITE3_TEXT);
                $update->bindValue(2, $email, SQLITE3_TEXT);
                $update->bindValue(3, $name, SQLITE3_TEXT);
                $update->bindValue(4, $externalId, SQLITE3_TEXT);
                $update->bindValue(5, $dn, SQLITE3_TEXT);
                $update->bindValue(6, $userId, SQLITE3_INTEGER);
                $update->execute();
            } else {
                $passwordHash = password_hash(bin2hex(random_bytes(32)), PASSWORD_DEFAULT);
                $insert = $db->prepare("INSERT INTO users
                                        (username, password_hash, email, full_name, role, is_active,
                                         auth_source, external_id, ldap_dn, ldap_synced_at)
                                        VALUES (?, ?, ?, ?, 'user', 1, 'ldap', ?, ?, datetime('now'))");
                $insert->bindValue(1, $username, SQLITE3_TEXT);
                $insert->bindValue(2, $passwordHash, SQLITE3_TEXT);
                $insert->bindValue(3, $email, SQLITE3_TEXT);
                $insert->bindValue(4, $name, SQLITE3_TEXT);
                $insert->bindValue(5, $externalId, SQLITE3_TEXT);
                $insert->bindValue(6, $dn, SQLITE3_TEXT);
                $insert->execute();
                $userId = (int)$db->lastInsertRowID();
            }

            $settings = $db->prepare('INSERT OR IGNORE INTO user_settings (user_id) VALUES (?)');
            $settings->bindValue(1, $userId, SQLITE3_INTEGER);
            $settings->execute();

            $findSignature = $db->prepare("SELECT id FROM user_signatures
                                           WHERE user_id = ? AND source = 'ldap' AND ldap_key = ?
                                           ORDER BY id LIMIT 1");
            $findSignature->bindValue(1, $userId, SQLITE3_INTEGER);
            $findSignature->bindValue(2, $externalId, SQLITE3_TEXT);
            $signature = $findSignature->execute()->fetchArray(SQLITE3_ASSOC) ?: null;

            if ($signature) {
                $saveSignature = $db->prepare("UPDATE user_signatures
                                               SET name = ?, role = ?, email = ?, phone = ?, template = ?,
                                                   updated_at = datetime('now')
                                               WHERE id = ? AND user_id = ? AND source = 'ldap'");
                $saveSignature->bindValue(1, $name, SQLITE3_TEXT);
                $saveSignature->bindValue(2, $role, SQLITE3_TEXT);
                $saveSignature->bindValue(3, $email, SQLITE3_TEXT);
                $saveSignature->bindValue(4, $phone, SQLITE3_TEXT);
                $saveSignature->bindValue(5, $template, SQLITE3_TEXT);
                $saveSignature->bindValue(6, (int)$signature['id'], SQLITE3_INTEGER);
                $saveSignature->bindValue(7, $userId, SQLITE3_INTEGER);
                $saveSignature->execute();
            } else {
                $saveSignature = $db->prepare("INSERT INTO user_signatures
                                               (user_id, name, role, email, phone, template, source, ldap_key, updated_at)
                                               VALUES (?, ?, ?, ?, ?, ?, 'ldap', ?, datetime('now'))");
                $saveSignature->bindValue(1, $userId, SQLITE3_INTEGER);
                $saveSignature->bindValue(2, $name, SQLITE3_TEXT);
                $saveSignature->bindValue(3, $role, SQLITE3_TEXT);
                $saveSignature->bindValue(4, $email, SQLITE3_TEXT);
                $saveSignature->bindValue(5, $phone, SQLITE3_TEXT);
                $saveSignature->bindValue(6, $template, SQLITE3_TEXT);
                $saveSignature->bindValue(7, $externalId, SQLITE3_TEXT);
                $saveSignature->execute();
            }

            $read = $db->prepare('SELECT * FROM users WHERE id = ?');
            $read->bindValue(1, $userId, SQLITE3_INTEGER);
            $user = $read->execute()->fetchArray(SQLITE3_ASSOC);
            if (!$user) {
                throw new RuntimeException('The LDAP account could not be loaded after provisioning.');
            }
            $db->exec('COMMIT');
            return $user;
        } catch (Throwable $e) {
            $db->exec('ROLLBACK');
            throw $e;
        }
    }
}
