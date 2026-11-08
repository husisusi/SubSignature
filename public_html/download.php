<?php
/**
 * download.php - downloads one saved signature as an HTML file.
 * Users can only download their own signatures (IDOR protection).
 */
require_once 'includes/config.php';
requireLogin();

$stmt = $db->prepare('SELECT * FROM user_signatures WHERE id = ? AND user_id = ?');
$stmt->bindValue(1, (int)($_GET['id'] ?? 0), SQLITE3_INTEGER);
$stmt->bindValue(2, (int)$_SESSION['user_id'], SQLITE3_INTEGER);
$sig = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

if (!$sig) {
    header('Location: generator.php');
    exit;
}

$content  = renderStoredSignature($sig);
$filename = 'signature_' . safeFileNamePart($sig['name']) . '_' . date('Y-m-d_H-i') . '.html';

// Discard anything that was buffered so the file is not corrupted.
while (ob_get_level()) {
    ob_end_clean();
}

header('Content-Type: text/html; charset=utf-8');
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Content-Length: ' . strlen($content));
header('X-Content-Type-Options: nosniff');
echo $content;
exit;
