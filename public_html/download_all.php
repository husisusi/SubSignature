<?php
/**
 * download_all.php - ZIP with all signatures of one user as HTML files.
 * Users get their own signatures; administrators may pass ?user_id=.
 */
require_once 'includes/config.php';
requireLogin();

set_time_limit(300);
ini_set('memory_limit', '256M');

$target_user_id = (int)$_SESSION['user_id'];
if (isAdmin() && isset($_GET['user_id'])) {
    $target_user_id = (int)$_GET['user_id'];
}

$stmt = $db->prepare('SELECT * FROM user_signatures WHERE user_id = ? ORDER BY created_at DESC');
$stmt->bindValue(1, $target_user_id, SQLITE3_INTEGER);
$result = $stmt->execute();
$signatures = [];
while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
    $signatures[] = $row;
}

if (!$signatures) {
    header('Location: generator.php');
    exit;
}

$stmt = $db->prepare('SELECT username, full_name FROM users WHERE id = ?');
$stmt->bindValue(1, $target_user_id, SQLITE3_INTEGER);
$info = $stmt->execute()->fetchArray(SQLITE3_ASSOC) ?: [];
$display_name = $info['full_name'] ?? ($info['username'] ?? 'user');
if ($display_name === '') {
    $display_name = $info['username'] ?? 'user';
}

$zip_path = tempnam(TMP_DIR, 'zip_');
$zip = new ZipArchive();
if ($zip->open($zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
    @unlink($zip_path);
    die('Cannot create ZIP file.');
}

$index_lines = [];
foreach ($signatures as $i => $sig) {
    $file = sprintf('%s_%s_%d.html', safeFileNamePart($sig['name']), date('Y-m-d', strtotime($sig['created_at']) ?: time()), $sig['id']);
    $zip->addFromString('signatures/' . $file, renderStoredSignature($sig));
    $index_lines[] = sprintf('%03d. %s (%s)', $i + 1, cleanText($sig['name'], 100), $file);
}
$zip->addFromString('README.txt', "EXPORT SUMMARY\nUser: " . cleanText($display_name, 100) . "\nCount: " . count($signatures) . "\nDate: " . date('Y-m-d') . "\n\n" . implode("\n", $index_lines) . "\n");
$zip->addFromString('manifest.json', json_encode([
    'user'  => $display_name,
    'count' => count($signatures),
    'date'  => date('Y-m-d H:i:s'),
], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
$zip->close();

while (ob_get_level()) {
    ob_end_clean();
}
header('Content-Type: application/zip');
header('Content-Disposition: attachment; filename="signatures_' . safeFileNamePart($display_name, 'user') . '_' . date('Y-m-d_H-i') . '.zip"');
header('Content-Length: ' . filesize($zip_path));
header('X-Content-Type-Options: nosniff');
readfile($zip_path);
@unlink($zip_path);
exit;
