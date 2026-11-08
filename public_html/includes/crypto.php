<?php
/**
 * includes/crypto.php
 *
 * Encryption of secrets stored in the database (SMTP password, LDAP bind
 * password). The key is a random 32-byte value stored in
 * private_data/secret.key (outside the web root, mode 0600).
 *
 * IMPORTANT: back up secret.key together with signatures.db. Without the key
 * the encrypted secrets cannot be recovered and must be re-entered.
 */

const SECRET_PREFIX_SODIUM  = 'enc:v1:';
const SECRET_PREFIX_OPENSSL = 'enc:v2:';

/**
 * Returns the application secret key, creating it on first use.
 */
function appSecretKey(): string
{
    static $key = null;
    if ($key !== null) {
        return $key;
    }

    $read = function () {
        $raw = @file_get_contents(SECRET_KEY_FILE);
        if ($raw === false) {
            return null;
        }
        $bin = @hex2bin(trim($raw));
        return ($bin !== false && strlen($bin) === 32) ? $bin : null;
    };

    $existing = is_file(SECRET_KEY_FILE) ? $read() : null;
    if ($existing !== null) {
        return $key = $existing;
    }

    $new = random_bytes(32);
    // Mode "x" creates the file exclusively, so two parallel requests cannot
    // both create (and then disagree on) a key.
    $fh = @fopen(SECRET_KEY_FILE, 'x');
    if ($fh === false) {
        $existing = $read();
        if ($existing !== null) {
            return $key = $existing;
        }
        throw new RuntimeException('Cannot create or read the secret key file.');
    }
    @chmod(SECRET_KEY_FILE, 0600);
    fwrite($fh, bin2hex($new));
    fclose($fh);

    return $key = $new;
}

/**
 * True if the value looks like something produced by encryptSecret().
 */
function isEncryptedSecret($value): bool
{
    return is_string($value)
        && (strpos($value, SECRET_PREFIX_SODIUM) === 0 || strpos($value, SECRET_PREFIX_OPENSSL) === 0);
}

/**
 * Encrypts a secret for storage. Empty strings stay empty.
 */
function encryptSecret(string $plain): string
{
    if ($plain === '') {
        return '';
    }
    $key = appSecretKey();

    if (function_exists('sodium_crypto_secretbox')) {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return SECRET_PREFIX_SODIUM . base64_encode($nonce . sodium_crypto_secretbox($plain, $nonce, $key));
    }

    $iv  = random_bytes(12);
    $tag = '';
    $ct  = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    if ($ct === false) {
        throw new RuntimeException('Encryption failed.');
    }
    return SECRET_PREFIX_OPENSSL . base64_encode($iv . $tag . $ct);
}

/**
 * Decrypts a stored secret.
 *
 * Values without the encryption prefix are legacy plaintext and returned as
 * they are (they get encrypted the next time they are saved). Returns an
 * empty string if decryption fails (tampered data or wrong key).
 */
function decryptSecret($stored): string
{
    if (!is_string($stored) || $stored === '') {
        return '';
    }
    if (!isEncryptedSecret($stored)) {
        return $stored;
    }

    $key = appSecretKey();

    if (strpos($stored, SECRET_PREFIX_SODIUM) === 0) {
        $raw = base64_decode(substr($stored, strlen(SECRET_PREFIX_SODIUM)), true);
        if ($raw === false || !function_exists('sodium_crypto_secretbox_open')
            || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            return '';
        }
        $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $plain = sodium_crypto_secretbox_open(substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), $nonce, $key);
        return $plain === false ? '' : $plain;
    }

    $raw = base64_decode(substr($stored, strlen(SECRET_PREFIX_OPENSSL)), true);
    if ($raw === false || strlen($raw) <= 28) {
        return '';
    }
    $plain = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16));
    return $plain === false ? '' : $plain;
}
