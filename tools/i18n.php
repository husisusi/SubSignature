<?php
/**
 * tools/i18n.php - maintenance tool for the translation files (CLI only).
 *
 *   php tools/i18n.php extract        rebuild public_html/lang/en.json (master list of all texts)
 *   php tools/i18n.php check          report missing / unused / broken entries in every language
 *   php tools/i18n.php new <code>     create public_html/lang/<code>.json from the master list
 *                                     (untranslated texts are left empty and fall back to English)
 *   php tools/i18n.php sync           add newly found texts (empty) to all language files
 *
 * The English text is the key. Texts are found in calls of t(), et(), eth() and
 * tj() with a string literal as first argument.
 */

if (PHP_SAPI !== 'cli') {
    exit("CLI only.\n");
}

$root = dirname(__DIR__) . '/public_html';
$langDir = $root . '/lang';

/** @return array<string, string[]> text => files that use it */
function collectTexts(string $root): array
{
    $found = [];
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $file) {
        $path = $file->getPathname();
        if (substr($path, -4) !== '.php' || strpos($path, '/PHPMailer/') !== false) {
            continue;
        }
        $src = (string)file_get_contents($path);
        $rel = substr($path, strlen($root) + 1);
        $patterns = [
            "/\\b(?:t|et|eth|tj)\\(\\s*'((?:[^'\\\\]|\\\\.)*)'/s" => 's',
            '/\\b(?:t|et|eth|tj)\\(\\s*"((?:[^"\\\\$]|\\\\.)*)"/s' => 'd',
        ];
        foreach ($patterns as $re => $kind) {
            if (preg_match_all($re, $src, $m)) {
                foreach ($m[1] as $raw) {
                    $text = $kind === 's' ? strtr($raw, ["\\'" => "'", '\\\\' => '\\']) : stripcslashes($raw);
                    if ($text !== '') {
                        $found[$text][$rel] = true;
                    }
                }
            }
        }
    }
    ksort($found, SORT_NATURAL | SORT_FLAG_CASE);
    return array_map('array_keys', $found);
}

function readLang(string $file): array
{
    $data = json_decode((string)file_get_contents($file), true);
    return is_array($data) ? $data : [];
}

function writeLang(string $file, array $meta, array $entries): void
{
    $out = ['@meta' => $meta] + $entries;
    file_put_contents($file, json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n");
}

function placeholders(string $s): array
{
    preg_match_all('/\{[a-z_]+\}/', $s, $m);
    sort($m[0]);
    return $m[0];
}

$cmd = $argv[1] ?? '';
$texts = collectTexts($root);

switch ($cmd) {
    case 'extract':
        $entries = [];
        foreach (array_keys($texts) as $t) {
            $entries[$t] = $t;
        }
        writeLang($langDir . '/en.json', ['code' => 'en', 'name' => 'English', 'note' => 'Master list. English is built in; this file is the template for translators.'], $entries);
        echo count($entries) . " texts written to lang/en.json\n";
        break;

    case 'new':
        $code = $argv[2] ?? '';
        if (!preg_match('/^[a-z]{2,3}$/', $code)) {
            exit("Usage: php tools/i18n.php new <code>   (e.g. fr)\n");
        }
        $file = "$langDir/$code.json";
        if (is_file($file)) {
            exit("$file already exists. Use 'sync' to add new texts.\n");
        }
        $entries = array_fill_keys(array_keys($texts), '');
        writeLang($file, ['code' => $code, 'name' => strtoupper($code)], $entries);
        echo "Created $file with " . count($entries) . " empty entries.\nAdd the language to languageRegistry() in public_html/includes/i18n.php.\n";
        break;

    case 'sync':
        foreach (glob("$langDir/*.json") as $file) {
            if (basename($file) === 'en.json') {
                continue;
            }
            $data = readLang($file);
            $meta = $data['@meta'] ?? [];
            unset($data['@meta']);
            $added = 0;
            foreach (array_keys($texts) as $t) {
                if (!array_key_exists($t, $data)) {
                    $data[$t] = '';
                    $added++;
                }
            }
            if ($added) {
                writeLang($file, $meta, $data);
            }
            echo basename($file) . ": $added added\n";
        }
        break;

    case 'check':
        $exit = 0;
        $total = count($texts);
        foreach (glob("$langDir/*.json") as $file) {
            $code = basename($file, '.json');
            if ($code === 'en') {
                continue;
            }
            $data = readLang($file);
            unset($data['@meta']);
            $missing = $unused = $badPlaceholders = [];
            foreach (array_keys($texts) as $t) {
                if (!isset($data[$t]) || $data[$t] === '') {
                    $missing[] = $t;
                } elseif (placeholders($t) !== placeholders($data[$t])) {
                    $badPlaceholders[] = $t;
                }
            }
            foreach (array_keys($data) as $k) {
                if (!isset($texts[$k])) {
                    $unused[] = $k;
                }
            }
            $done = $total - count($missing);
            printf("%-4s %4d/%d translated (%d%%), %d unused, %d placeholder mismatches\n",
                $code, $done, $total, $total ? round(100 * $done / $total) : 100, count($unused), count($badPlaceholders));
            foreach ($badPlaceholders as $t) {
                echo "     placeholder mismatch: " . substr($t, 0, 80) . "\n";
                $exit = 1;
            }
            if (in_array('-v', $argv, true)) {
                foreach ($missing as $t) {
                    echo "     missing: " . substr($t, 0, 80) . "\n";
                }
                foreach ($unused as $t) {
                    echo "     unused:  " . substr($t, 0, 80) . "\n";
                }
            }
        }
        exit($exit);

    default:
        echo "Usage: php tools/i18n.php extract|check [-v]|new <code>|sync\n";
}
