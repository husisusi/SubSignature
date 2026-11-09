<?php
/**
 * includes/i18n.php
 *
 * Internationalisation: one JSON file per language in /lang (e.g. lang/de.json).
 *
 * The English source text is the key, as in gettext:
 *     t('Save')   ->  "Speichern" when the current language is German
 * A missing translation silently falls back to the English text, so a language
 * file may be incomplete. A new language is just a new file plus one line in
 * languageRegistry() below (see docs/TRANSLATING.md).
 *
 * This file is self-contained (no database or session needed) so that it also
 * works in the installer. Choosing a language: cookie "subsig_lang" (set by
 * set_language.php) > browser language (Accept-Language) > site default
 * (system setting "default_language") > English.
 */

const I18N_COOKIE = 'subsig_lang';
const I18N_DEFAULT = 'en';

/**
 * All languages the application knows: code => [native name, text direction].
 * Built-in ones plus drop-in files (see below). A language is offered only if
 * its file lang/<code>.json exists (English is built in and needs no file).
 */
function languageRegistry(): array
{
    static $all = null;
    if ($all !== null) {
        return $all;
    }
    $all = builtinLanguages();

    // Drop-in languages: any lang/<code>.json that is not built in is
    // registered from its "@meta" block ({"code": "sv", "name": "Svenska",
    // "dir": "ltr"}). "name" is required, "dir" defaults to ltr.
    foreach (glob(__DIR__ . '/../lang/*.json') ?: [] as $file) {
        $code = basename($file, '.json');
        if (isset($all[$code]) || !preg_match('/^[a-z]{2,3}$/', $code)) {
            continue;
        }
        $data = json_decode((string)@file_get_contents($file), true);
        $meta = is_array($data) && is_array($data['@meta'] ?? null) ? $data['@meta'] : [];
        $name = isset($meta['name']) && is_string($meta['name']) ? trim($meta['name']) : '';
        if ($name === '' || $name === strtoupper($code)) {
            continue; // not named yet (placeholder from "tools/i18n.php new")
        }
        $dir = (($meta['dir'] ?? 'ltr') === 'rtl') ? 'rtl' : 'ltr';
        $all[$code] = [mb_substr($name, 0, 40), $dir];
    }
    return $all;
}

/** Languages shipped with the application: code => [native name, direction]. */
function builtinLanguages(): array
{
    return [
        'en'    => ['English', 'ltr'],
        'de'    => ['Deutsch', 'ltr'],
        'es'    => ['Español', 'ltr'],
        'fr'    => ['Français', 'ltr'],
        'it'    => ['Italiano', 'ltr'],
        'pt'    => ['Português', 'ltr'],
        'nl'    => ['Nederlands', 'ltr'],
        'pl'    => ['Polski', 'ltr'],
        'tr'    => ['Türkçe', 'ltr'],
        'ru'    => ['Русский', 'ltr'],
        'uk'    => ['Українська', 'ltr'],
        'ar'    => ['العربية', 'rtl'],
        'hi'    => ['हिन्दी', 'ltr'],
        'id'    => ['Bahasa Indonesia', 'ltr'],
        'zh'    => ['简体中文', 'ltr'],
        'ja'    => ['日本語', 'ltr'],
        'ko'    => ['한국어', 'ltr'],
    ];
}

/**
 * Languages that can actually be selected (registry entry + existing file).
 *
 * @return array<string, string> code => native name
 */
function availableLanguages(): array
{
    static $list = null;
    if ($list === null) {
        $list = [];
        foreach (languageRegistry() as $code => $info) {
            if ($code === I18N_DEFAULT || is_file(__DIR__ . '/../lang/' . $code . '.json')) {
                $list[$code] = $info[0];
            }
        }
    }
    return $list;
}

function isSupportedLanguage($code): bool
{
    return is_string($code) && isset(availableLanguages()[$code]);
}

/**
 * Picks the best supported language from an Accept-Language header value.
 */
function negotiateLanguage(string $header): ?string
{
    $candidates = [];
    foreach (explode(',', $header) as $position => $part) {
        $bits = explode(';', trim($part));
        $tag = strtolower(trim($bits[0]));
        $q = 1.0;
        foreach (array_slice($bits, 1) as $param) {
            if (preg_match('/^\s*q\s*=\s*([0-9.]+)\s*$/i', $param, $m)) {
                $q = (float)$m[1];
            }
        }
        if ($tag !== '' && $tag !== '*' && $q > 0) {
            // "zh-CN", "pt-BR" ... -> primary subtag
            $candidates[] = [$q, $position, preg_replace('/[-_].*$/', '', $tag)];
        }
    }
    usort($candidates, function ($a, $b) {
        return $b[0] <=> $a[0] ?: $a[1] <=> $b[1];
    });
    foreach ($candidates as $c) {
        if (isSupportedLanguage($c[2])) {
            return $c[2];
        }
    }
    return null;
}

/**
 * The language used for the current request (memoised).
 */
function currentLang(): string
{
    static $lang = null;
    if ($lang !== null) {
        return $lang;
    }

    $cookie = $_COOKIE[I18N_COOKIE] ?? null;
    if (isSupportedLanguage($cookie)) {
        return $lang = $cookie;
    }

    $browser = negotiateLanguage((string)($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''));
    if ($browser !== null) {
        return $lang = $browser;
    }

    // Site default chosen by the administrator (only if the database is up).
    if (isset($GLOBALS['db']) && $GLOBALS['db'] instanceof SQLite3) {
        $default = getSetting($GLOBALS['db'], 'default_language', I18N_DEFAULT);
        if (isSupportedLanguage($default)) {
            return $lang = $default;
        }
    }
    return $lang = I18N_DEFAULT;
}

/**
 * Text direction ("ltr" / "rtl") of the current language.
 */
function langDir(): string
{
    $registry = languageRegistry();
    return $registry[currentLang()][1] ?? 'ltr';
}

/**
 * Loads the translation map of a language (memoised). English needs none.
 *
 * @return array<string, string>
 */
function loadTranslations(string $code): array
{
    static $cache = [];
    if (isset($cache[$code])) {
        return $cache[$code];
    }
    $map = [];
    if ($code !== I18N_DEFAULT && preg_match('/^[a-z]{2,3}$/', $code)) {
        $file = __DIR__ . '/../lang/' . $code . '.json';
        if (is_file($file)) {
            $data = json_decode((string)file_get_contents($file), true);
            if (is_array($data)) {
                foreach ($data as $key => $value) {
                    // "@meta" and non-string values are not translations.
                    if (is_string($key) && $key !== '' && $key[0] !== '@' && is_string($value) && $value !== '') {
                        $map[$key] = $value;
                    }
                }
            }
        }
    }
    return $cache[$code] = $map;
}

/**
 * Translates an English text. {name} placeholders are replaced from $params.
 * The result is PLAIN text (not escaped): use et() inside HTML.
 */
function t(string $text, array $params = []): string
{
    $map = loadTranslations(currentLang());
    $out = $map[$text] ?? $text;
    if ($params) {
        $replace = [];
        foreach ($params as $name => $value) {
            $replace['{' . $name . '}'] = (string)$value;
        }
        $out = strtr($out, $replace);
    }
    return $out;
}

/**
 * Translated and HTML-escaped (text and attributes). Parameters are escaped too.
 */
function et(string $text, array $params = []): string
{
    $map = loadTranslations(currentLang());
    $out = e($map[$text] ?? $text);
    if ($params) {
        $replace = [];
        foreach ($params as $name => $value) {
            $replace['{' . $name . '}'] = e($value);
        }
        $out = strtr($out, $replace);
    }
    return $out;
}

/**
 * Like et(), but the parameters are trusted HTML fragments (e.g. "<code>x</code>")
 * that are inserted unescaped. Never pass user input here.
 */
function eth(string $text, array $htmlParams): string
{
    $map = loadTranslations(currentLang());
    $out = e($map[$text] ?? $text);
    $replace = [];
    foreach ($htmlParams as $name => $html) {
        $replace['{' . $name . '}'] = (string)$html;
    }
    return strtr($out, $replace);
}

/**
 * Translated text as a JSON string literal for inline <script> blocks:
 *     alert(<?= tj('Saved') ?>);
 * Slashes and angle brackets are escaped so "</script>" cannot break out.
 */
function tj(string $text, array $params = []): string
{
    return json_encode(t($text, $params), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
}

/**
 * Strings that the shared JavaScript files (theme.js ...) need. Printed in
 * every page head before the scripts as window.SUBSIG_I18N.
 */
function i18nHead(): string
{
    $strings = [
        'Colour theme'          => t('Colour theme'),
        'Light'                 => t('Light'),
        'Dark'                  => t('Dark'),
        'Follow system setting' => t('Follow system setting'),
    ];
    return '<script>window.SUBSIG_I18N=' . json_encode($strings, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) . ';</script>';
}

/**
 * Language selector (a small POST form that auto-submits on change).
 *
 * @param bool $floating true on pages without sidebar (login, installer)
 */
function langSwitcher(bool $floating = false): string
{
    $langs = availableLanguages();
    if (count($langs) < 2) {
        return '';
    }
    $current = currentLang();
    $return = basename((string)parse_url((string)($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH));
    $query = (string)parse_url((string)($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_QUERY);
    if ($query !== '' && preg_match('/^[A-Za-z0-9_=&%.\-]*$/', $query)) {
        $return .= '?' . $query;
    }
    $csrf = function_exists('generateCSRFToken') ? generateCSRFToken() : '';

    $html = '<form method="post" action="set_language.php" class="lang-switch' . ($floating ? ' floating' : '') . '">';
    $html .= '<input type="hidden" name="csrf_token" value="' . e($csrf) . '">';
    $html .= '<input type="hidden" name="return" value="' . e($return) . '">';
    $html .= '<label class="lang-switch-label"><i class="fas fa-language" aria-hidden="true"></i>';
    $html .= '<span class="sr-only">' . et('Language') . '</span>';
    $html .= '<select name="lang" class="lang-select" onchange="this.form.submit()" aria-label="' . et('Language') . '">';
    foreach ($langs as $code => $name) {
        $html .= '<option value="' . e($code) . '"' . ($code === $current ? ' selected' : '') . '>' . e($name) . '</option>';
    }
    $html .= '</select></label>';
    $html .= '<noscript><button type="submit" class="btn btn-sm">OK</button></noscript>';
    $html .= '</form>';
    return $html;
}

/**
 * Stores the language choice in a cookie (one year).
 */
function setLanguageCookie(string $code): void
{
    if (!isSupportedLanguage($code) || headers_sent()) {
        return;
    }
    setcookie(I18N_COOKIE, $code, [
        'expires'  => time() + 365 * 86400,
        'path'     => '/',
        'secure'   => function_exists('isHttpsRequest') ? isHttpsRequest() : false,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    $_COOKIE[I18N_COOKIE] = $code;
}
