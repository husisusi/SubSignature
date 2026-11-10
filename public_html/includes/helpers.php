<?php
/**
 * includes/helpers.php
 *
 * Shared helper functions used by the web UI and the API: output escaping,
 * request info, settings, validation, template handling, rate limiting and
 * audit logging.
 *
 * Functions here must not depend on a session; session-aware helpers live in
 * config.php. Functions that need the database use the global $db at call
 * time (it is created in bootstrap.php after this file is loaded).
 */

// ---------------------------------------------------------------------
// 1. OUTPUT & REQUEST HELPERS
// ---------------------------------------------------------------------

/**
 * HTML-escapes a value for safe output (HTML body and quoted attributes).
 */
function e($value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Returns a versioned URL for a static asset (CSS/JS) relative to the web
 * root, e.g. "css/style.css?v=1731150000".
 *
 * The version is the file's modification time, so browsers (Firefox in
 * particular tends to keep stylesheets for a long time) fetch the new file
 * as soon as it changes on the server, e.g. after an update. Falls back to
 * APP_VERSION if the file cannot be stat'ed. The result is already
 * HTML-escaped and safe to use in an attribute.
 */
function assetUrl(string $path): string
{
    $file = APP_ROOT . '/' . $path;
    $mtime = is_file($file) ? @filemtime($file) : false;
    $version = $mtime ? (string)$mtime : (defined('APP_VERSION') ? (string)APP_VERSION : '0');
    return e($path . '?v=' . $version);
}

/**
 * Legacy helper kept for compatibility: trims and HTML-escapes input.
 */
function sanitizeInput($input)
{
    if (is_array($input)) {
        return array_map('sanitizeInput', $input);
    }
    return htmlspecialchars(trim((string)$input), ENT_QUOTES, 'UTF-8');
}

/**
 * True if the current request was made over HTTPS (also behind a trusted
 * reverse proxy that sets X-Forwarded-Proto).
 */
function isHttpsRequest(): bool
{
    if (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') {
        return true;
    }
    if ((int)($_SERVER['SERVER_PORT'] ?? 0) === 443) {
        return true;
    }
    if (isTrustedProxy($_SERVER['REMOTE_ADDR'] ?? '')
        && strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https') {
        return true;
    }
    return false;
}

function isTrustedProxy(string $ip): bool
{
    return $ip !== '' && in_array($ip, TRUSTED_PROXIES, true);
}

/**
 * Returns the client IP. X-Forwarded-For is only honoured when the direct peer
 * is a configured trusted proxy (TRUSTED_PROXIES in config.local.php).
 */
function getClientIp(): string
{
    $remote = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    if (!isTrustedProxy($remote) || empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return $remote;
    }
    // Walk the chain from the right and return the first address that is not
    // one of our own proxies (the left-most entries are client controlled).
    $chain = array_reverse(array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])));
    foreach ($chain as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP) && !isTrustedProxy($ip)) {
            return $ip;
        }
    }
    return $remote;
}

// ---------------------------------------------------------------------
// 2. SETTINGS
// ---------------------------------------------------------------------

function getSetting($db, string $key, string $default = ''): string
{
    $stmt = $db->prepare('SELECT setting_value FROM system_settings WHERE setting_key = ?');
    $stmt->bindValue(1, $key, SQLITE3_TEXT);
    $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    return ($row && $row['setting_value'] !== null) ? (string)$row['setting_value'] : $default;
}

function setSetting($db, string $key, string $value): void
{
    $stmt = $db->prepare('INSERT OR REPLACE INTO system_settings (setting_key, setting_value) VALUES (?, ?)');
    $stmt->bindValue(1, $key, SQLITE3_TEXT);
    $stmt->bindValue(2, $value, SQLITE3_TEXT);
    $stmt->execute();
}

// ---------------------------------------------------------------------
// 3. VALIDATION
// ---------------------------------------------------------------------

/**
 * Removes control characters, trims whitespace and limits the length.
 */
function cleanText($value, int $maxLength = 255): string
{
    $value = (string)$value;
    // Strip C0/C1 control characters (keeps normal Unicode text).
    $value = preg_replace('/[\x00-\x1F\x7F]/u', ' ', $value) ?? '';
    $value = trim(preg_replace('/\s+/u', ' ', $value) ?? '');
    if (mb_strlen($value, 'UTF-8') > $maxLength) {
        $value = mb_substr($value, 0, $maxLength, 'UTF-8');
    }
    return $value;
}

/**
 * Like cleanText() but keeps line breaks (for addresses, disclaimers).
 */
function cleanMultilineText($value, int $maxLength = 1000): string
{
    $value = str_replace(["\r\n", "\r"], "\n", (string)$value);
    // Strip control characters except newline, collapse blank-line runs.
    $value = preg_replace('/[\x00-\x09\x0B-\x1F\x7F]/u', ' ', $value) ?? '';
    $lines = array_map(function ($line) {
        return trim(preg_replace('/[ \t]+/u', ' ', $line) ?? '');
    }, explode("\n", $value));
    $value = trim(preg_replace("/\n{3,}/", "\n\n", implode("\n", $lines)) ?? '');
    if (mb_strlen($value, 'UTF-8') > $maxLength) {
        $value = mb_substr($value, 0, $maxLength, 'UTF-8');
    }
    return $value;
}

/**
 * Company-wide values for the placeholders {{COMPANY}}, {{WEBSITE}},
 * {{ADDRESS}} and {{DISCLAIMER}} (Admin -> System Configuration).
 * Keys are lower case; values are plain text (escape when rendering).
 */
function companyFields(): array
{
    static $fields = null;
    if ($fields === null) {
        global $db;
        $fields = ['company' => '', 'website' => '', 'address' => '', 'disclaimer' => ''];
        if (isset($db) && $db instanceof SQLite3) {
            foreach ($fields as $key => $_) {
                $fields[$key] = getSetting($db, 'company_' . $key, '');
            }
        }
    }
    return $fields;
}

/**
 * Validates and normalises the four signature fields.
 *
 * @param array $input             Raw input with keys name, role, email, phone
 * @param bool  $requireRoleAndPhone Whether role and phone are mandatory
 * @return array [cleanFields, errors]
 */
function validateSignatureFields(array $input, bool $requireRoleAndPhone = true): array
{
    $clean = [
        'name'  => cleanText($input['name'] ?? '', 100),
        'role'  => cleanText($input['role'] ?? '', 100),
        'email' => cleanText($input['email'] ?? '', 254),
        'phone' => cleanText($input['phone'] ?? '', 30),
    ];
    $errors = [];

    if ($clean['name'] === '') {
        $errors[] = t('Name is required.');
    }
    if ($requireRoleAndPhone && $clean['role'] === '') {
        $errors[] = t('Role is required.');
    }
    if ($clean['email'] === '' || !filter_var($clean['email'], FILTER_VALIDATE_EMAIL)) {
        $errors[] = t('A valid email address is required.');
    }
    if ($requireRoleAndPhone && $clean['phone'] === '') {
        $errors[] = t('Phone number is required.');
    }
    if ($clean['phone'] !== '') {
        $digits = preg_replace('/\D/', '', $clean['phone']);
        if (!preg_match('/^[\+\d\s\-\(\)\/\.]{5,30}$/', $clean['phone']) || strlen($digits) < 3) {
            $errors[] = t('Invalid phone number format.');
        }
    }
    return [$clean, $errors];
}

/**
 * Password policy shared by registration, installer, password change and
 * admin password reset. Returns a list of error messages (empty = OK).
 */
function validatePasswordPolicy($password): array
{
    $password = (string)$password;
    $errors = [];
    if (strlen($password) < 8) $errors[] = t('Password must be at least 8 characters');
    if (strlen($password) > 200) $errors[] = t('Password must not be longer than 200 characters');
    if (!preg_match('/[A-Z]/', $password)) $errors[] = t('At least one uppercase letter');
    if (!preg_match('/[a-z]/', $password)) $errors[] = t('At least one lowercase letter');
    if (!preg_match('/[0-9]/', $password)) $errors[] = t('At least one number');
    return $errors;
}

/**
 * Local usernames: letters, digits, underscore, dot, hyphen and @ (so that
 * directory account names such as "john.doe" are possible).
 */
function isValidUsername($username): bool
{
    return is_string($username) && preg_match('/^[A-Za-z0-9_.@\-]{3,64}$/', $username) === 1;
}

/**
 * Neutralises spreadsheet formula injection for CSV exports. Values that
 * start with = + - @ (or tab / CR) get a leading apostrophe, except values
 * that are plain phone numbers.
 */
function csvSafeCell($value): string
{
    $value = (string)$value;
    if ($value === '') {
        return $value;
    }
    if (preg_match('/^[=+\-@\t\r]/', $value) && !preg_match('/^\+?[\d\s()\-\/.]+$/', $value)) {
        return "'" . $value;
    }
    return $value;
}

// ---------------------------------------------------------------------
// 4. FILE SYSTEM & TEMPLATES
// ---------------------------------------------------------------------

/**
 * True if $path lies inside $dir (both are resolved with realpath first).
 * Uses a separator-aware comparison so "/var/www/tpl_evil" is not "inside"
 * "/var/www/tpl".
 */
function isPathInside(string $path, string $dir): bool
{
    $realPath = realpath($path);
    $realDir  = realpath($dir);
    if ($realPath === false || $realDir === false) {
        return false;
    }
    $realDir = rtrim($realDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    return strpos($realPath, $realDir) === 0;
}

/**
 * Valid signature template file name (no path, signature_ prefix, .html).
 */
function isValidTemplateName($name): bool
{
    return is_string($name) && preg_match('/^signature_[A-Za-z0-9_\-]{1,80}\.html$/', $name) === 1;
}

/**
 * Templates the admin may edit in the editor: signature templates plus the
 * notification mail wrapper.
 */
function isEditableTemplateName($name): bool
{
    return isValidTemplateName($name) || $name === 'email_notification.html';
}

/**
 * Lists all signature templates (file names), sorted.
 */
function listSignatureTemplates(): array
{
    $result = [];
    foreach (glob(TEMPLATES_DIR . '/signature_*.html') ?: [] as $file) {
        $name = basename($file);
        if (isValidTemplateName($name) && is_file($file)) {
            $result[] = $name;
        }
    }
    sort($result);
    return $result;
}

/**
 * Human readable template title, e.g. "signature_modern_blue.html" -> "Modern blue".
 */
function templateDisplayName(string $filename): string
{
    return ucfirst(str_replace(['signature_', '.html', '_'], ['', '', ' '], $filename));
}

/**
 * The system-wide default template (set by an admin), validated.
 */
function getDefaultTemplateName(): string
{
    $configFile = TEMPLATES_DIR . '/default_config.txt';
    if (is_file($configFile)) {
        $name = trim((string)file_get_contents($configFile));
        if (isValidTemplateName($name) && is_file(TEMPLATES_DIR . '/' . $name)) {
            return $name;
        }
    }
    if (is_file(TEMPLATES_DIR . '/signature_default.html')) {
        return 'signature_default.html';
    }
    $all = listSignatureTemplates();
    return $all[0] ?? 'signature_default.html';
}

/**
 * Returns an existing, valid template name; falls back to the default.
 */
function resolveTemplateName($name): string
{
    if (isValidTemplateName($name) && is_file(TEMPLATES_DIR . '/' . $name) && isPathInside(TEMPLATES_DIR . '/' . $name, TEMPLATES_DIR)) {
        return $name;
    }
    return getDefaultTemplateName();
}

/**
 * Reads a signature template (with fallback to the default template).
 */
function loadSignatureTemplate($name): string
{
    $resolved = resolveTemplateName($name);
    $path = TEMPLATES_DIR . '/' . $resolved;
    if (is_file($path) && isPathInside($path, TEMPLATES_DIR)) {
        return (string)file_get_contents($path);
    }
    return '';
}

/**
 * Fills a template with signature data. All values are HTML-escaped and the
 * replacement happens in a single pass, so a value like "{{EMAIL}}" inside a
 * name is not expanded a second time.
 *
 * Per-signature placeholders: {{NAME}} {{ROLE}} {{EMAIL}} {{PHONE}} {{PHONE_CLEAN}}
 * Company-wide placeholders:   {{COMPANY}} {{WEBSITE}} {{ADDRESS}} {{DISCLAIMER}}
 * (ADDRESS and DISCLAIMER keep their line breaks as <br>.)
 */
function renderSignatureHtml(string $template, array $fields): string
{
    $phone = (string)($fields['phone'] ?? '');
    $company = companyFields();
    // The result is sanitised once more: a placeholder used as a whole URL (href="{{ROLE}}")
    // must not be able to smuggle in a "javascript:" value from the data.
    return sanitizeTemplateHtml(strtr($template, [
        '{{NAME}}'        => e($fields['name'] ?? ''),
        '{{ROLE}}'        => e($fields['role'] ?? ''),
        '{{EMAIL}}'       => e($fields['email'] ?? ''),
        '{{PHONE}}'       => e($phone),
        '{{PHONE_CLEAN}}' => e(preg_replace('/[^0-9+]/', '', $phone)),
        '{{COMPANY}}'     => e($company['company']),
        '{{WEBSITE}}'     => e($company['website']),
        '{{ADDRESS}}'     => nl2br(e($company['address']), false),
        '{{DISCLAIMER}}'  => nl2br(e($company['disclaimer']), false),
    ]));
}

/**
 * Renders a stored signature row (user_signatures) to a final HTML fragment:
 * template lookup with fallback, server-side sanitising, escaped placeholders.
 */
function renderStoredSignature(array $sig): string
{
    $template = sanitizeTemplateHtml(loadSignatureTemplate($sig['template'] ?? ''));
    return renderSignatureHtml($template, $sig);
}

/**
 * Builds a safe ASCII file name part from free text.
 */
function safeFileNamePart($text, string $fallback = 'signature'): string
{
    $clean = trim((string)preg_replace('/[^a-z0-9]+/i', '_', strtolower((string)$text)), '_');
    return $clean === '' ? $fallback : substr($clean, 0, 60);
}

/**
 * Removes active content from template HTML.
 *
 * Templates are written by administrators AND technicians and are rendered in other
 * people's browsers, mails and downloads, so this is a security boundary. It is applied
 * when a template is saved, imported, previewed, sent and rendered, which also cleans
 * templates that were stored by an older version.
 *
 * The HTML is tokenised (comments, tags, quoted attribute values) and every start tag is
 * REBUILT from the attributes that were actually parsed - always double-quoted. What the
 * browser sees is therefore exactly what was inspected, so tricks like <img/onerror=...>,
 * <img src="x"onerror=...>, a ">" inside an attribute value or entity-encoded
 * "javascript:" URLs do not get through. In detail it
 *   - removes scripts, frames, plug-ins, forms, SVG/MathML, templates and other raw-text or
 *     foreign-content elements together with their content,
 *   - drops event handler attributes (on*), srcdoc, invalid attribute names,
 *   - allows only safe URL schemes in href/src/... (data: only for images),
 *   - cleans <style> blocks and style attributes (no @import, expression(), behavior, ...),
 *   - escapes a "<" that does not form a complete tag, and fails closed (returns '')
 *     when the regular expression engine gives up.
 * The browser side additionally sanitises through js/safe-html.js, and standalone previews
 * are sandboxed by a Content-Security-Policy.
 */
function sanitizeTemplateHtml(string $html): string
{
    // Quote-aware attribute section of a tag (a ">" inside quotes does not end the tag).
    $attrs = '(?:[^>"\']|"[^"]*"|\'[^\']*\')*';

    $html = str_replace("\0", '', $html);

    // 1. Elements that are removed together with their content. Repeated, so that
    //    split constructions like <scr<script>ipt> collapse completely.
    $withContent = 'script|iframe|frameset|frame|object|embed|applet|form|textarea|select|button|'
                 . 'svg|math|noscript|noembed|noframes|xmp|title|template';
    $re = '#<\s*(' . $withContent . ')\b' . $attrs . '>.*?<\s*/\s*\1\s*>#is';
    for ($i = 0; $i < 20; $i++) {
        $next = preg_replace($re, '', $html);
        if ($next === null) {
            return '';
        }
        if ($next === $html) {
            break;
        }
        $html = $next;
    }

    // 2. <style> blocks: the content is raw text for the browser, so it is cleaned separately
    //    (an unclosed block runs to the end of the document).
    $html = preg_replace_callback(
        '#(<style\b' . $attrs . '>)(.*?)(?:<\s*/\s*style\s*>|\z)#is',
        function (array $m): string {
            return $m[1] . sanitizeTemplateCss($m[2]) . '</style>';
        },
        $html
    );
    if ($html === null) {
        return '';
    }

    // 3. Tokenise and rebuild.
    $dropTags = array_flip([
        'script', 'iframe', 'frameset', 'frame', 'object', 'embed', 'applet', 'form', 'input', 'textarea',
        'select', 'option', 'optgroup', 'button', 'base', 'link', 'svg', 'math', 'noscript', 'noembed',
        'noframes', 'xmp', 'title', 'template', 'plaintext', 'audio', 'video', 'source', 'track', 'canvas',
        'portal', 'bgsound', 'isindex', 'keygen',
    ]);
    $urlAttrs = array_flip([
        'href', 'src', 'action', 'formaction', 'background', 'poster', 'xlink:href', 'data', 'cite',
        'longdesc', 'lowsrc', 'dynsrc', 'ping', 'codebase', 'manifest', 'profile', 'usemap', 'icon',
    ]);

    // comment (browser-compatible endings: "-->", "--!>", "<!-->", "<!--->") | <!doctype> and
    // <![if ...] markers | processing instruction | end tag | start tag | stray "<"
    $token = '#<!--(?:-?>|.*?--!?>)|<![^>]*>|<\?[^>]*>|</[a-zA-Z][^>]*>|<([a-zA-Z][a-zA-Z0-9:_-]*)(' . $attrs . ')>|<(?=[a-zA-Z/!?])#s';

    $out = preg_replace_callback($token, function (array $m) use ($dropTags, $urlAttrs): string {
        $tok = $m[0];
        if (strncmp($tok, '<!', 2) === 0) {
            return $tok;                       // comments, doctype, conditional-comment markers
        }
        if (strncmp($tok, '<?', 2) === 0) {
            return '';
        }
        if (strncmp($tok, '</', 2) === 0) {
            if (preg_match('#^</([a-zA-Z][a-zA-Z0-9:_-]*)#', $tok, $n) === 1 && !isset($dropTags[strtolower($n[1])])) {
                return '</' . $n[1] . '>';     // attributes on end tags are meaningless
            }
            return '';
        }
        if (!isset($m[1]) || $m[1] === '') {
            return '&lt;';                     // a "<" that is not part of a complete tag
        }

        $name = strtolower($m[1]);
        if (isset($dropTags[$name])) {
            return '';
        }

        preg_match_all(
            '#([^\s"\'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'=<>`]+)))?#',
            $m[2],
            $found,
            PREG_SET_ORDER | PREG_UNMATCHED_AS_NULL
        );

        $parts = [];
        foreach ($found as $a) {
            $an = strtolower($a[1]);
            if (!preg_match('/^[a-z_:][a-z0-9_:.\-]*$/', $an) || strncmp($an, 'on', 2) === 0 || $an === 'srcdoc') {
                continue;
            }
            $raw = $a[2] ?? $a[3] ?? $a[4] ?? null;
            $val = (string)($raw ?? '');

            if (isset($urlAttrs[$an]) && !templateUrlIsSafe($val)) {
                continue;
            }
            if ($an === 'style' && !templateCssIsSafe($val)) {
                continue;
            }
            if ($name === 'meta' && $an === 'http-equiv' && strtolower(trim($val)) !== 'content-type') {
                continue;                      // refresh, set-cookie, content-security-policy, ...
            }
            $parts[] = $raw === null ? $an : $an . '="' . str_replace(['"', '<', '>'], ['&quot;', '&lt;', '&gt;'], $val) . '"';
        }

        $selfClose = preg_match('#/\s*$#', $m[2]) === 1;
        return '<' . $m[1] . ($parts ? ' ' . implode(' ', $parts) : '') . ($selfClose ? ' /' : '') . '>';
    }, $html);

    return $out === null ? '' : $out;
}

/**
 * Decodes HTML entities the way a browser does for attribute values: numeric references
 * (also control characters and without ";") and named references. Decoding slightly too
 * much is harmless here - the result is only inspected, never output.
 */
function templateDecodeEntities(string $value): string
{
    $out = preg_replace_callback(
        '/&(?:#([0-9]{1,10})|#[xX]([0-9a-fA-F]{1,8})|([A-Za-z][A-Za-z0-9]{1,31}));?/',
        function (array $m): string {
            if (isset($m[3]) && $m[3] !== '') {
                $d = html_entity_decode('&' . $m[3] . ';', ENT_QUOTES | ENT_HTML5, 'UTF-8');
                return $d === '&' . $m[3] . ';' ? $m[0] : $d;
            }
            $cp = (isset($m[2]) && $m[2] !== '') ? hexdec($m[2]) : (int)$m[1];
            if ($cp < 1 || $cp > 0x10FFFF || ($cp >= 0xD800 && $cp <= 0xDFFF)) {
                return "\u{FFFD}";
            }
            return (string)mb_chr((int)$cp, 'UTF-8');
        },
        $value
    );
    return $out ?? '';
}

/**
 * True if a URL attribute value is safe: relative, a fragment, a {{placeholder}} or one of the
 * schemes below. data: is only accepted for raster images.
 */
function templateUrlIsSafe(string $value): bool
{
    $v = templateDecodeEntities($value);
    // Browsers ignore control characters, spaces and a few invisible characters inside the scheme.
    $v = preg_replace('/[\x00-\x20\x7f-\x9f\x{00AD}\x{200B}-\x{200F}\x{2028}\x{2029}\x{FEFF}]+/u', '', $v);
    if ($v === null) {
        return false;                          // invalid UTF-8
    }
    if (preg_match('#^([a-z][a-z0-9+.\-]*):#i', $v, $m) !== 1) {
        return true;                           // relative URL, "#fragment", "{{PLACEHOLDER}}"
    }
    $scheme = strtolower($m[1]);
    if ($scheme === 'data') {
        return preg_match('#^data:image/(png|gif|jpe?g|webp|bmp)[;,]#i', $v) === 1;
    }
    return in_array($scheme, [
        'http', 'https', 'mailto', 'tel', 'sms', 'callto', 'cid', 'ftp', 'ftps', 'geo', 'skype', 'sip', 'sips',
        'facetime', 'facetime-audio', 'whatsapp', 'viber', 'tg', 'msteams', 'xmpp', 'webcal', 'maps',
    ], true);
}

/** CSS constructs that can run script or load code in (old) browsers. */
const TEMPLATE_CSS_BAD = '#expression\s*\(|(?:java|vb)script\s*:|behaviou?r\s*:|-moz-binding|@import#i';

/** True if the value of a style="" attribute is free of script-capable constructs. */
function templateCssIsSafe(string $value): bool
{
    $v = templateDecodeEntities($value);
    $v = preg_replace('#/\*.*?\*/#s', '', $v) ?? '';
    $v = str_replace('\\', '', $v);            // CSS escapes such as \6a avascript
    return preg_match(TEMPLATE_CSS_BAD, $v) !== 1;
}

/** Cleans the text of a <style> element. */
function sanitizeTemplateCss(string $css): string
{
    // Old-school "<!-- ... -->" wrappers are harmless for CSS; remove them, then every "<".
    $css = str_replace(['<!--', '-->', '<', "\0"], '', $css);
    $css = preg_replace('#@import\b[^;{}]*;?#i', '', $css) ?? '';
    $probe = preg_replace('#/\*.*?\*/#s', '', $css) ?? '';
    $probe = str_replace('\\', '', $probe);
    return preg_match(TEMPLATE_CSS_BAD, $probe) === 1 ? '' : $css;
}

// ---------------------------------------------------------------------
// 5. RATE LIMITING (database backed, cannot be bypassed by dropping cookies)
// ---------------------------------------------------------------------

function rateLimitKey(string $action, ?string $subject): string
{
    return hash('sha256', $action . '|' . ($subject ?? getClientIp()));
}

/**
 * True if the action is currently blocked (does not count a hit).
 */
function rateLimitIsBlocked(string $action, int $limit, int $window, ?string $subject = null): bool
{
    global $db;
    $stmt = $db->prepare('SELECT hits, window_start FROM rate_limits WHERE rl_key = ?');
    $stmt->bindValue(1, rateLimitKey($action, $subject), SQLITE3_TEXT);
    $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if (!$row) {
        return false;
    }
    if (time() - (int)$row['window_start'] > $window) {
        return false;
    }
    return (int)$row['hits'] >= $limit;
}

/**
 * Registers one hit (e.g. a failed login) for the action.
 */
function rateLimitHit(string $action, int $window, ?string $subject = null): void
{
    global $db;
    $key = rateLimitKey($action, $subject);
    $now = time();
    $db->exec('BEGIN IMMEDIATE');
    try {
        $stmt = $db->prepare('SELECT hits, window_start FROM rate_limits WHERE rl_key = ?');
        $stmt->bindValue(1, $key, SQLITE3_TEXT);
        $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

        if (!$row || $now - (int)$row['window_start'] > $window) {
            $up = $db->prepare('INSERT OR REPLACE INTO rate_limits (rl_key, hits, window_start) VALUES (?, 1, ?)');
            $up->bindValue(1, $key, SQLITE3_TEXT);
            $up->bindValue(2, $now, SQLITE3_INTEGER);
        } else {
            $up = $db->prepare('UPDATE rate_limits SET hits = hits + 1 WHERE rl_key = ?');
            $up->bindValue(1, $key, SQLITE3_TEXT);
        }
        $up->execute();
        $db->exec('COMMIT');
    } catch (Exception $e) {
        $db->exec('ROLLBACK');
        error_log('rateLimitHit failed: ' . $e->getMessage());
    }
}

function rateLimitReset(string $action, ?string $subject = null): void
{
    global $db;
    $stmt = $db->prepare('DELETE FROM rate_limits WHERE rl_key = ?');
    $stmt->bindValue(1, rateLimitKey($action, $subject), SQLITE3_TEXT);
    $stmt->execute();
}

/**
 * Check-and-count in one call: returns false when the limit is exceeded,
 * otherwise registers the hit and returns true.
 */
function checkRateLimit(string $action, int $limit = 5, int $timeframe = 300, ?string $subject = null): bool
{
    global $db;
    if (rateLimitIsBlocked($action, $limit, $timeframe, $subject)) {
        logSecurityEventToDB($db, 'RATE_LIMIT_EXCEEDED', null, 'Action: ' . $action . ', IP: ' . getClientIp());
        return false;
    }
    rateLimitHit($action, $timeframe, $subject);
    return true;
}

// ---------------------------------------------------------------------
// 6. AUDIT LOGGING & HOUSEKEEPING
// ---------------------------------------------------------------------

function logSecurityEventToDB($db, string $event_type, $user_id = null, string $details = ''): void
{
    $ua = cleanText($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown', 255);
    try {
        $stmt = $db->prepare('INSERT INTO security_events (event_type, user_id, ip_address, user_agent, details) VALUES (?, ?, ?, ?, ?)');
        $stmt->bindValue(1, $event_type, SQLITE3_TEXT);
        $stmt->bindValue(2, $user_id, $user_id === null ? SQLITE3_NULL : SQLITE3_INTEGER);
        $stmt->bindValue(3, getClientIp(), SQLITE3_TEXT);
        $stmt->bindValue(4, $ua, SQLITE3_TEXT);
        $stmt->bindValue(5, cleanText($details, 1000), SQLITE3_TEXT);
        $stmt->execute();
    } catch (Exception $e) {
        error_log('Audit log error: ' . $e->getMessage());
    }
}

/**
 * Writes one row to the mail log (used by the signature rollout).
 */
function logMail($db, $signatureId, string $recipient, string $status, string $message): void
{
    try {
        $stmt = $db->prepare('INSERT INTO mail_logs (signature_id, recipient, status, message) VALUES (?, ?, ?, ?)');
        $stmt->bindValue(1, $signatureId, $signatureId === null ? SQLITE3_NULL : SQLITE3_INTEGER);
        $stmt->bindValue(2, cleanText($recipient, 254), SQLITE3_TEXT);
        $stmt->bindValue(3, $status, SQLITE3_TEXT);
        $stmt->bindValue(4, cleanText($message, 1000), SQLITE3_TEXT);
        $stmt->execute();
    } catch (Exception $e) {
        error_log('Mail log error: ' . $e->getMessage());
    }
}

/**
 * Deletes log rows older than LOG_RETENTION_DAYS and stale rate-limit rows.
 * Cheap; runs on roughly 1 % of logins.
 */
function pruneOldLogs($db): void
{
    $days = max(7, (int)LOG_RETENTION_DAYS);
    foreach ([
        ['login_attempts', 'attempted_at'],
        ['security_events', 'created_at'],
        ['mail_logs', 'created_at'],
    ] as [$table, $column]) {
        $stmt = $db->prepare("DELETE FROM $table WHERE $column < datetime('now', ?)");
        $stmt->bindValue(1, '-' . $days . ' days', SQLITE3_TEXT);
        $stmt->execute();
    }
    $stmt = $db->prepare('DELETE FROM rate_limits WHERE window_start < ?');
    $stmt->bindValue(1, time() - 86400, SQLITE3_INTEGER);
    $stmt->execute();

    // Remove abandoned temporary files (LDAP previews etc.) older than 2 hours.
    foreach (glob(TMP_DIR . '/*.json') ?: [] as $file) {
        if (is_file($file) && filemtime($file) < time() - 7200) {
            @unlink($file);
        }
    }
}

// ---------------------------------------------------------------------
// 9. SYSTEM HEALTH (Admin -> System Configuration)
// ---------------------------------------------------------------------

/**
 * Runs read-only checks of the installation.
 *
 * @return array<int, array{label: string, status: string, detail: string}> status: ok | warn | fail
 */
function systemHealthChecks(): array
{
    global $db;
    $rows = [];
    $add = function (string $label, string $status, string $detail = '') use (&$rows) {
        $rows[] = ['label' => $label, 'status' => $status, 'detail' => $detail];
    };

    $add(t('PHP version'), version_compare(PHP_VERSION, '7.4.0', '>=') ? 'ok' : 'fail', PHP_VERSION);
    foreach (['sqlite3' => true, 'mbstring' => true, 'zip' => true, 'json' => true, 'ldap' => false] as $ext => $required) {
        $loaded = extension_loaded($ext);
        $add(t('PHP extension: {name}', ['name' => $ext]), $loaded ? 'ok' : ($required ? 'fail' : 'warn'),
            $loaded ? t('loaded') : ($required ? t('missing') : t('missing (optional, needed for the LDAP import)')));
    }
    $add(t('Password encryption'), function_exists('sodium_crypto_secretbox') ? 'ok' : (extension_loaded('openssl') ? 'ok' : 'fail'),
        function_exists('sodium_crypto_secretbox') ? 'libsodium' : 'OpenSSL AES-256-GCM');

    $add(t('Data directory writable'), is_writable(BASE_DIR) ? 'ok' : 'fail', BASE_DIR);
    $insideWebRoot = strpos((string)realpath(BASE_DIR), (string)realpath(APP_ROOT)) === 0;
    $add(t('Data directory outside the web root'), $insideWebRoot ? 'warn' : 'ok',
        $insideWebRoot ? t('Inside the web root: only the .htaccess protects it. Move it out or set SUBSIG_DATA_DIR.') : t('yes'));

    if (is_file(SECRET_KEY_FILE)) {
        $perms = substr(sprintf('%o', fileperms(SECRET_KEY_FILE)), -4);
        $add(t('Secret key file'), ($perms === '0600' || $perms === '0400') ? 'ok' : 'warn',
            t('present, mode {mode}. Back it up together with the database.', ['mode' => $perms]));
    } else {
        $add(t('Secret key file'), 'warn', t('not created yet (created when the first password is encrypted)'));
    }

    $add(t('HTTPS'), isHttpsRequest() ? 'ok' : 'warn', isHttpsRequest() ? t('active') : t('This request is not HTTPS. Use HTTPS in production.'));
    $add(t('Installer removed'), is_file(APP_ROOT . '/install.php') ? 'warn' : 'ok',
        is_file(APP_ROOT . '/install.php') ? t('install.php is still present. It locks itself, but you can delete it.') : t('yes'));
    $add(t('Templates directory writable'), is_writable(TEMPLATES_DIR) ? 'ok' : 'warn', TEMPLATES_DIR);

    if ($db instanceof SQLite3) {
        $add(t('Database schema'), 'ok', 'v' . (int)$db->querySingle('PRAGMA user_version') . ', ' . round((is_file(DB_PATH) ? filesize(DB_PATH) : 0) / 1024) . ' KB');
    }
    $add(t('Languages'), 'ok', implode(', ', array_keys(availableLanguages())));
    $add(t('Application version'), 'ok', APP_VERSION);

    return $rows;
}


// ---------------------------------------------------------------------
// 9. SIGNATURE TAGS (labels for the signature overview)
// ---------------------------------------------------------------------

const MAX_SIGNATURE_TAGS = 100;

/**
 * Colour keys a tag may use. The key is mapped to a CSS class, so no free
 * text ever reaches a style attribute.
 */
function signatureTagColors(): array
{
    return ['blue', 'green', 'amber', 'red', 'purple', 'teal', 'pink', 'gray'];
}

function signatureTagColorLabel(string $color): string
{
    switch ($color) {
        case 'blue':   return t('Blue');
        case 'green':  return t('Green');
        case 'amber':  return t('Amber');
        case 'red':    return t('Red');
        case 'purple': return t('Purple');
        case 'teal':   return t('Teal');
        case 'pink':   return t('Pink');
        default:       return t('Gray');
    }
}

function normalizeTagColor($color): string
{
    return in_array($color, signatureTagColors(), true) ? $color : 'gray';
}

/**
 * Validates a tag name; returns the cleaned name or '' if it is not allowed.
 * Letters, digits, spaces and a few separators, 1-32 characters.
 */
function normalizeTagName($name): string
{
    $name = cleanText($name, 64);
    if (mb_strlen($name, 'UTF-8') > 32) {
        return '';
    }
    return preg_match('/^[\p{L}\p{N}][\p{L}\p{N} ._\-\/&]*$/u', $name) === 1 ? $name : '';
}
