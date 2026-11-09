<?php
/**
 * preview_template.php - renders a template with sample data in its own tab.
 *
 * The document is served with a sandboxing Content-Security-Policy: even if a
 * template contains active content, scripts cannot run and the page has no
 * access to the application's origin or session.
 */
require_once 'includes/config.php';
requireAdmin();

$filename = basename((string)($_GET['template'] ?? ''));

if (isEditableTemplateName($filename) && is_file(TEMPLATES_DIR . '/' . $filename) && isPathInside(TEMPLATES_DIR . '/' . $filename, TEMPLATES_DIR)) {
    $content = sanitizeTemplateHtml((string)file_get_contents(TEMPLATES_DIR . '/' . $filename));

    // Sample data (escaped like real data).
    $preview = renderSignatureHtml($content, [
        'name'  => 'John Doe',
        'role'  => 'Senior Developer',
        'email' => 'john.doe@company.com',
        'phone' => '+49 89 12345678',
    ]);
    $preview = strtr($preview, ['{{ATTACHMENT_NAME}}' => 'signature.html', '{{PREVIEW}}' => '']);

    header('Content-Type: text/html; charset=utf-8');
    header("Content-Security-Policy: sandbox; default-src 'none'; img-src 'self' data: https: http:; style-src 'unsafe-inline'; font-src data:");
    header('X-Content-Type-Options: nosniff');
    echo $preview;
    exit;
}

http_response_code(404);
echo '<h1>' . et('Template not found!') . '</h1>';
