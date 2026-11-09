<?php
/**
 * set_language.php - stores the chosen interface language and returns to the
 * page the user came from. POST only.
 *
 * The choice is kept in a cookie (also for visitors who are not logged in) and,
 * for logged-in users, in their account so it follows them to other devices.
 */
require_once 'includes/config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: index.php');
    exit;
}

$lang = $_POST['lang'] ?? '';
if (verifyCSRFToken($_POST['csrf_token'] ?? '') && isSupportedLanguage($lang)) {
    setLanguageCookie($lang);

    if (isLoggedIn() && !empty($_SESSION['user_id'])) {
        $stmt = $db->prepare('UPDATE users SET language = ? WHERE id = ?');
        $stmt->bindValue(1, $lang, SQLITE3_TEXT);
        $stmt->bindValue(2, (int)$_SESSION['user_id'], SQLITE3_INTEGER);
        $stmt->execute();
    }
}

// Only a plain relative page name (optionally with a simple query string) is
// accepted as return target, so this cannot be used as an open redirect.
$return = (string)($_POST['return'] ?? '');
if ($return === '' || !preg_match('/^[A-Za-z0-9_\-]+(\.php)?(\?[A-Za-z0-9_=&%.\-]*)?$/', $return)) {
    $return = 'index.php';
}
header('Location: ' . $return, true, 303);
exit;
