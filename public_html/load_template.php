<?php
/**
 * load_template.php - returns the raw source of a template for the editor.
 * Admin only; delivered as plain text so a browser never renders it as a page.
 */
require_once 'includes/config.php';
requireAdmin();

$filename = basename((string)($_GET['file'] ?? ''));
$path = TEMPLATES_DIR . '/' . $filename;

if (isEditableTemplateName($filename) && is_file($path) && isPathInside($path, TEMPLATES_DIR)) {
    header('Content-Type: text/plain; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    echo file_get_contents($path);
    exit;
}

http_response_code(404);
header('Content-Type: text/plain; charset=utf-8');
echo 'Template not found or access denied.';
