<?php
/**
 * includes/SignatureImages.php - template images delivered through the API.
 *
 * Some mail clients cannot download the images of a signature themselves
 * (HCL Notes/Domino agents written in LotusScript cannot fetch binary data).
 * For them the API can deliver every image of a signature Base64-encoded:
 *
 *   GET /api/v1/signatures?...&images=meta     image list per signature
 *   GET /api/v1/signatures?...&images=inline   ... plus the data (Base64)
 *   GET /api/v1/images/{sha256}                one image (Base64)
 *
 * Where an image may come from (security boundary - this code runs requests
 * on behalf of API clients):
 *   - the image folder of this installation (img/, "Manage Images"), given as
 *     a relative path or as an absolute URL of this server,
 *   - a data:image/... URI inside the template,
 *   - an https URL on a host that the administrator listed under
 *     Configuration -> "Image hosts for embedding" (empty list = none).
 * Remote images are fetched with cURL: https only, no redirects, no proxy,
 * short timeouts, a size limit, and only if every address the host name
 * resolves to is public (no loopback, private, link-local or reserved range);
 * the checked address is pinned for the connection, so DNS cannot change it
 * between check and use. Only PNG, JPEG and GIF are accepted (detected from
 * the file content, never from the server's Content-Type). Results - also
 * failures - are cached in the image_cache table.
 */

/** Largest image that is embedded (bytes). */
const IMAGE_EMBED_MAX_BYTES = 1048576;
/** At most this many different images are reported per signature. */
const IMAGE_EMBED_MAX_PER_SIGNATURE = 20;
/** A successfully fetched remote image is fetched again after this time (seconds). */
const IMAGE_CACHE_TTL = 86400;
/** A failed remote fetch is retried after this time (seconds). */
const IMAGE_CACHE_FAIL_TTL = 600;
/** Remote fetches per API request; further images are reported as "fetch_deferred". */
const IMAGE_FETCH_BUDGET = 3;

/**
 * Host names from the setting image_embed_hosts (lower case, validated).
 *
 * @return string[]
 */
function imageEmbedHosts(SQLite3 $db): array
{
    return parseImageEmbedHosts(getSetting($db, 'image_embed_hosts', ''));
}

/**
 * Parses the host list as entered by the administrator: one host per line
 * (commas and spaces are accepted as separators too). Invalid entries are
 * dropped; at most 50 hosts.
 *
 * @return string[]
 */
function parseImageEmbedHosts(string $raw): array
{
    $hosts = [];
    foreach (preg_split('/[\s,;]+/', strtolower($raw)) ?: [] as $h) {
        $h = trim($h);
        if ($h === '' || strlen($h) > 253) {
            continue;
        }
        // Plain DNS names only: no scheme, path, port, wildcard or IP literal.
        if (!preg_match('/^(?=.*[a-z])[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/', $h)) {
            continue;
        }
        $hosts[$h] = true;
        if (count($hosts) >= 50) {
            break;
        }
    }
    return array_keys($hosts);
}

/**
 * The src values of all <img> tags of a rendered (sanitised) signature, as
 * they appear in the HTML attribute, in order and without duplicates.
 *
 * sanitizeTemplateHtml() rebuilds every tag with double-quoted, escaped
 * attribute values, so a simple pattern is reliable here.
 *
 * @return string[]
 */
function signatureImageSources(string $html): array
{
    $out = [];
    if (preg_match_all('/<img\b[^>]*?\ssrc="([^"]*)"/i', $html, $m)) {
        foreach ($m[1] as $src) {
            if ($src !== '' && !in_array($src, $out, true)) {
                $out[] = $src;
            }
        }
    }
    return $out;
}

/**
 * Detects PNG, JPEG and GIF from the first bytes; '' for anything else.
 */
function sniffImageType(string $bytes): string
{
    if (strncmp($bytes, "\x89PNG\r\n\x1a\n", 8) === 0) {
        return 'image/png';
    }
    if (strncmp($bytes, "\xFF\xD8\xFF", 3) === 0) {
        return 'image/jpeg';
    }
    if (strncmp($bytes, 'GIF87a', 6) === 0 || strncmp($bytes, 'GIF89a', 6) === 0) {
        return 'image/gif';
    }
    return '';
}

/**
 * True when $ip is a public unicast address (not loopback, private,
 * link-local, carrier-grade NAT, multicast, documentation or reserved).
 */
function isPublicIpAddress(string $ip): bool
{
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return false;
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $long = ip2long($ip);
        $blocked = [
            ['100.64.0.0', 10],  // carrier-grade NAT
            ['192.0.0.0', 24],   // IETF protocol assignments
            ['192.0.2.0', 24],   // documentation
            ['198.18.0.0', 15],  // benchmarking
            ['198.51.100.0', 24],
            ['203.0.113.0', 24],
            ['224.0.0.0', 4],    // multicast
        ];
        foreach ($blocked as [$net, $bits]) {
            $mask = -1 << (32 - $bits);
            if (($long & $mask) === (ip2long($net) & $mask)) {
                return false;
            }
        }
        return true;
    }
    // IPv6: FILTER_FLAG_NO_PRIV_RANGE/NO_RES_RANGE cover ::1, fc00::/7, fe80::/10 and
    // more; additionally refuse multicast, documentation and IPv4-mapped addresses.
    $bin = inet_pton($ip);
    if ($bin === false) {
        return false;
    }
    if ($bin[0] === "\xFF") {
        return false; // ff00::/8 multicast
    }
    if (strncmp($bin, "\x20\x01\x0d\xb8", 4) === 0) {
        return false; // 2001:db8::/32 documentation
    }
    if (strncmp($bin, str_repeat("\0", 10) . "\xFF\xFF", 12) === 0) {
        return false; // ::ffff:0:0/96 IPv4-mapped
    }
    return true;
}

/**
 * Resolves a host name; returns its addresses, or [] if it does not resolve.
 *
 * @return string[]
 */
function resolveHostAddresses(string $host): array
{
    $ips = [];
    foreach (@gethostbynamel($host) ?: [] as $ip) {
        $ips[] = $ip;
    }
    foreach (@dns_get_record($host, DNS_AAAA) ?: [] as $rec) {
        if (!empty($rec['ipv6'])) {
            $ips[] = $rec['ipv6'];
        }
    }
    return array_values(array_unique($ips));
}

/**
 * Downloads one remote image (see the file comment for the rules).
 *
 * @return array{status: string, data?: string}
 */
function fetchRemoteImage(string $url, string $host): array
{
    if (!function_exists('curl_init')) {
        return ['status' => 'fetch_unavailable'];
    }
    $ips = resolveHostAddresses($host);
    if (!$ips) {
        return ['status' => 'fetch_failed'];
    }
    foreach ($ips as $ip) {
        if (!isPublicIpAddress($ip)) {
            return ['status' => 'blocked_address'];
        }
    }
    return downloadPinned($url, $host, $ips[0]);
}

/**
 * The transfer itself: https only, no redirects, no proxy, short timeouts,
 * size limit, and the connection goes to $ip (already checked) for $host.
 * $extra lets tests add cURL options (e.g. a test CA); production passes none.
 *
 * @return array{status: string, data?: string}
 */
function downloadPinned(string $url, string $host, string $ip, array $extra = []): array
{
    $resolve = $host . ':443:' . (strpos($ip, ':') !== false ? '[' . $ip . ']' : $ip);

    $body = '';
    $tooLarge = false;
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_PROTOCOLS       => CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_FOLLOWLOCATION  => false,
        CURLOPT_RESOLVE         => [$resolve],
        CURLOPT_PROXY           => '',       // never through a proxy: the pinned address must be used
        CURLOPT_CONNECTTIMEOUT  => 3,
        CURLOPT_TIMEOUT         => 8,
        CURLOPT_SSL_VERIFYPEER  => true,
        CURLOPT_SSL_VERIFYHOST  => 2,
        CURLOPT_USERAGENT       => 'SubSignature/' . APP_VERSION . ' (signature image embedding)',
        CURLOPT_HTTPHEADER      => ['Accept: image/png, image/jpeg, image/gif'],
        CURLOPT_WRITEFUNCTION   => function ($ch, string $chunk) use (&$body, &$tooLarge): int {
            if (strlen($body) + strlen($chunk) > IMAGE_EMBED_MAX_BYTES) {
                $tooLarge = true;
                return 0; // aborts the transfer
            }
            $body .= $chunk;
            return strlen($chunk);
        },
    ] + $extra);
    $ok = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);

    if ($tooLarge) {
        return ['status' => 'too_large'];
    }
    if ($ok === false || $code !== 200) {
        return ['status' => 'fetch_failed'];
    }
    return ['status' => 'ok', 'data' => $body];
}

/**
 * Turns a src value into a source description.
 *
 * @return array{kind: string, url?: string, path?: string, host?: string, data?: string, status?: string}
 *   kind: local | data | remote | invalid
 */
function classifyImageSource(string $src, string $selfHost, string $basePath): array
{
    $url = html_entity_decode($src, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    if (preg_match('/[\x00-\x20\x7f]/', $url)) {
        return ['kind' => 'invalid', 'url' => $url, 'status' => 'invalid_url'];
    }

    // data:image/...;base64,...
    if (preg_match('#^data:image/[a-z+.-]+;base64,([A-Za-z0-9+/=]+)$#i', $url, $m)) {
        $bytes = base64_decode($m[1], true);
        if ($bytes === false) {
            return ['kind' => 'invalid', 'url' => 'data:', 'status' => 'invalid_url'];
        }
        return ['kind' => 'data', 'url' => 'data:', 'data' => $bytes];
    }

    // Relative path into the image folder: "img/logo.png", "./img/logo.png", "/<base>/img/logo.png"
    $parts = parse_url($url);
    if ($parts === false) {
        return ['kind' => 'invalid', 'url' => $url, 'status' => 'invalid_url'];
    }
    $scheme = strtolower($parts['scheme'] ?? '');
    $host = strtolower($parts['host'] ?? '');
    $path = rawurldecode((string)($parts['path'] ?? ''));
    if (preg_match('/[\x00-\x1f\x7f]/', $path)) {
        return ['kind' => 'invalid', 'url' => $url, 'status' => 'invalid_url'];
    }

    $isSelf = ($scheme === '' && $host === '')
        || (in_array($scheme, ['http', 'https'], true) && $host !== '' && $host === $selfHost);
    if ($isSelf) {
        $rel = $path;
        if ($rel !== '' && $rel[0] === '/') {
            // Absolute path: must lie below this installation's base path.
            $prefix = rtrim($basePath, '/') . '/';
            if (strpos($rel, $prefix) !== 0) {
                return ['kind' => 'invalid', 'url' => $url, 'status' => 'not_allowed'];
            }
            $rel = substr($rel, strlen($prefix));
        }
        $rel = preg_replace('#^(\./)+#', '', $rel);
        if (strpos($rel, 'img/') !== 0) {
            return ['kind' => 'invalid', 'url' => $url, 'status' => 'not_allowed'];
        }
        return ['kind' => 'local', 'url' => $url, 'path' => substr($rel, 4)];
    }

    if ($scheme === 'http') {
        return ['kind' => 'invalid', 'url' => $url, 'status' => 'https_required'];
    }
    if ($scheme !== 'https' || $host === '' || isset($parts['user']) || isset($parts['pass'])
        || (isset($parts['port']) && (int)$parts['port'] !== 443)) {
        return ['kind' => 'invalid', 'url' => $url, 'status' => 'not_allowed'];
    }
    return ['kind' => 'remote', 'url' => $url, 'host' => $host];
}

/**
 * Validates image bytes and returns the API description of an image.
 */
function imageFromBytes(string $bytes): array
{
    if (strlen($bytes) > IMAGE_EMBED_MAX_BYTES) {
        return ['status' => 'too_large'];
    }
    $type = sniffImageType($bytes);
    if ($type === '') {
        return ['status' => 'unsupported_type'];
    }
    return ['status' => 'ok', 'sha256' => hash('sha256', $bytes), 'content_type' => $type, 'size' => strlen($bytes), 'bytes' => $bytes];
}

/**
 * Stores an image (or a failure) in the cache unless the stored row is already
 * identical, so repeated requests do not write.
 */
function storeImageCache(SQLite3 $db, string $sourceKey, array $img, bool $touch): void
{
    $hash = hash('sha256', $sourceKey);
    $row = $db->prepare('SELECT status, sha256 FROM image_cache WHERE source_hash = ?');
    $row->bindValue(1, $hash, SQLITE3_TEXT);
    $cur = $row->execute()->fetchArray(SQLITE3_ASSOC);
    if ($cur && !$touch && $cur['status'] === $img['status'] && (string)$cur['sha256'] === (string)($img['sha256'] ?? '')) {
        return;
    }
    $stmt = $db->prepare('INSERT OR REPLACE INTO image_cache (source_hash, source, status, sha256, content_type, size, data, fetched_at)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
    $stmt->bindValue(1, $hash, SQLITE3_TEXT);
    $stmt->bindValue(2, cleanText($sourceKey, 500), SQLITE3_TEXT);
    $stmt->bindValue(3, $img['status'], SQLITE3_TEXT);
    $ok = $img['status'] === 'ok';
    $stmt->bindValue(4, $ok ? $img['sha256'] : null, $ok ? SQLITE3_TEXT : SQLITE3_NULL);
    $stmt->bindValue(5, $ok ? $img['content_type'] : null, $ok ? SQLITE3_TEXT : SQLITE3_NULL);
    $stmt->bindValue(6, $ok ? $img['size'] : null, $ok ? SQLITE3_INTEGER : SQLITE3_NULL);
    $stmt->bindValue(7, $ok ? $img['bytes'] : null, $ok ? SQLITE3_BLOB : SQLITE3_NULL);
    $stmt->bindValue(8, time(), SQLITE3_INTEGER);
    $stmt->execute();
}

/**
 * Resolves one src value of a signature to an API image entry.
 *
 * Returned keys: src, url, status and - when status is "ok" - sha256,
 * content_type, size and (internally) bytes. $budget counts the remote
 * fetches still allowed in this request.
 */
function resolveSignatureImage(SQLite3 $db, string $src, string $selfHost, string $basePath, array $allowedHosts, int &$budget): array
{
    $source = classifyImageSource($src, $selfHost, $basePath);
    $entry = ['src' => $src, 'url' => $source['url'] ?? ''];

    if ($source['kind'] === 'invalid') {
        return $entry + ['status' => $source['status']];
    }

    if ($source['kind'] === 'data') {
        $img = imageFromBytes($source['data']);
        if ($img['status'] === 'ok') {
            storeImageCache($db, 'data:' . $img['sha256'], $img, false);
        }
        return $entry + $img;
    }

    if ($source['kind'] === 'local') {
        $base = realpath(IMAGES_DIR);
        $file = $base !== false ? realpath(IMAGES_DIR . '/' . $source['path']) : false;
        if ($file === false || $base === false || strpos($file, $base . DIRECTORY_SEPARATOR) !== 0 || !is_file($file)) {
            return $entry + ['status' => 'not_found'];
        }
        if (!preg_match('/\.(png|jpe?g|gif)$/i', $file)) {
            return $entry + ['status' => 'unsupported_type'];
        }
        if (filesize($file) > IMAGE_EMBED_MAX_BYTES) {
            return $entry + ['status' => 'too_large'];
        }
        $img = imageFromBytes((string)file_get_contents($file));
        if ($img['status'] === 'ok') {
            storeImageCache($db, 'local:' . $source['path'], $img, false);
        }
        return $entry + $img;
    }

    // Remote image on an allowed host.
    if (!in_array($source['host'], $allowedHosts, true)) {
        return $entry + ['status' => 'not_allowed'];
    }
    $key = $source['url'];
    $stmt = $db->prepare('SELECT status, sha256, content_type, size, data, fetched_at FROM image_cache WHERE source_hash = ?');
    $stmt->bindValue(1, hash('sha256', $key), SQLITE3_TEXT);
    $cached = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    $age = $cached ? time() - (int)$cached['fetched_at'] : PHP_INT_MAX;
    $fresh = $cached && $age < ($cached['status'] === 'ok' ? IMAGE_CACHE_TTL : IMAGE_CACHE_FAIL_TTL);

    if (!$fresh && $budget > 0) {
        $budget--;
        $res = fetchRemoteImage($key, $source['host']);
        $img = $res['status'] === 'ok' ? imageFromBytes($res['data']) : ['status' => $res['status']];
        if ($img['status'] === 'ok' || !$cached || $cached['status'] !== 'ok') {
            storeImageCache($db, $key, $img, true);
            return $entry + $img;
        }
        // The refresh failed but an older copy exists: keep serving it and retry later.
        $retry = $db->prepare('UPDATE image_cache SET fetched_at = ? WHERE source_hash = ?');
        $retry->bindValue(1, time() - IMAGE_CACHE_TTL + IMAGE_CACHE_FAIL_TTL, SQLITE3_INTEGER);
        $retry->bindValue(2, hash('sha256', $key), SQLITE3_TEXT);
        $retry->execute();
    }
    if ($cached && $cached['status'] === 'ok') {
        return $entry + ['status' => 'ok', 'sha256' => $cached['sha256'], 'content_type' => $cached['content_type'],
                         'size' => (int)$cached['size'], 'bytes' => (string)$cached['data']];
    }
    if ($cached && $fresh) {
        return $entry + ['status' => $cached['status']];
    }
    return $entry + ['status' => 'fetch_deferred'];
}

/**
 * All images of a rendered signature.
 *
 * @return array<int, array> entries as returned by resolveSignatureImage()
 */
function signatureImages(SQLite3 $db, string $html, string $selfHost, string $basePath, array $allowedHosts, int &$budget): array
{
    $out = [];
    foreach (array_slice(signatureImageSources($html), 0, IMAGE_EMBED_MAX_PER_SIGNATURE) as $src) {
        $out[] = resolveSignatureImage($db, $src, $selfHost, $basePath, $allowedHosts, $budget);
    }
    return $out;
}

/**
 * Removes cached images that no signature has asked for in a long time.
 */
function pruneImageCache(SQLite3 $db): void
{
    try {
        $stmt = $db->prepare('DELETE FROM image_cache WHERE fetched_at < ?');
        $stmt->bindValue(1, time() - 30 * 86400, SQLITE3_INTEGER);
        $stmt->execute();
    } catch (Exception $e) {
        error_log('Pruning the image cache failed: ' . $e->getMessage());
    }
}
