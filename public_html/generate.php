<?php
/**
 * generate.php - saves or deletes a signature of the logged-in user.
 * POST only, CSRF protected. Ownership is enforced in the SQL statements.
 */
require_once 'includes/config.php';
requireLogin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: generator.php');
    exit;
}
requireCsrf();

$user_id = (int)$_SESSION['user_id'];
$action  = $_POST['action'] ?? 'preview';

// --- Delete one signature (only the owner's) ---
if ($action === 'delete') {
    $stmt = $db->prepare('DELETE FROM user_signatures WHERE id = ? AND user_id = ?');
    $stmt->bindValue(1, (int)($_POST['id'] ?? 0), SQLITE3_INTEGER);
    $stmt->bindValue(2, $user_id, SQLITE3_INTEGER);
    $stmt->execute();
    header('Location: generator.php');
    exit;
}

// --- Preview / save ---
[$fields, $errors] = validateSignatureFields($_POST, true);
$template = resolveTemplateName($_POST['template'] ?? '');

// Remember the form so the generator page can refill it.
$_SESSION['form_data'] = $fields + ['template' => $template];

if ($errors) {
    $_SESSION['error'] = implode(' ', $errors);
    header('Location: generator.php');
    exit;
}

$_SESSION['preview'] = renderSignatureHtml(sanitizeTemplateHtml(loadSignatureTemplate($template)), $fields);

if ($action === 'save') {
    $stmt = $db->prepare('INSERT INTO user_signatures (user_id, name, role, email, phone, template) VALUES (?, ?, ?, ?, ?, ?)');
    $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
    $stmt->bindValue(2, $fields['name'], SQLITE3_TEXT);
    $stmt->bindValue(3, $fields['role'], SQLITE3_TEXT);
    $stmt->bindValue(4, $fields['email'], SQLITE3_TEXT);
    $stmt->bindValue(5, $fields['phone'], SQLITE3_TEXT);
    $stmt->bindValue(6, $template, SQLITE3_TEXT);
    $stmt->execute();
    $_SESSION['last_generated_id'] = $db->lastInsertRowID();
    $_SESSION['success'] = 'Signature saved successfully.';
}

header('Location: generator.php');
exit;
