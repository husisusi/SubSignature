<?php
// download.php
require_once 'includes/config.php';

// Check authentication
requireLogin();

// 1. Output Buffer Cleanup
// Ensure no whitespace/warnings are sent before the file content.
// This prevents corrupted HTML files.
while (ob_get_level()) {
    ob_end_clean();
}

$content = '';
$filename_base = 'signature';

// 2. Handle Saved Signature Download
if (isset($_GET['id'])) {
    $signature_id = (int)$_GET['id'];
    $user_id = $_SESSION['user_id'];
    
    // Secure Database Query
    // We strictly check if the signature belongs to the logged-in user (IDOR protection).
    $stmt = $db->prepare("SELECT * FROM user_signatures WHERE id = ? AND user_id = ?");
    $stmt->bindValue(1, $signature_id, SQLITE3_INTEGER);
    $stmt->bindValue(2, $user_id, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $sig = $result->fetchArray(SQLITE3_ASSOC);
    
    if ($sig) {
        // Define secure paths
        $templates_dir = __DIR__ . '/templates';
        $real_templates_dir = realpath($templates_dir);
        
        // Determine template filename (sanitize input)
        $template_file = basename($sig['template'] ?? 'signature_default.html');
        $template_path = realpath($templates_dir . '/' . $template_file);

        // SECURITY CHECK: Path Traversal / Symlink Protection
        // Ensure the resolved path starts with the templates directory.
        if ($template_path && $real_templates_dir && strpos($template_path, $real_templates_dir) === 0 && file_exists($template_path)) {
             $raw_template = file_get_contents($template_path);
        } else {
             // Fallback to default if malicious path or missing file
             $fallback = $templates_dir . '/signature_default.html';
             if (file_exists($fallback)) {
                 $raw_template = file_get_contents($fallback);
             } else {
                 die('Error: Template file not found.');
             }
        }
        
        // Replace Placeholders
        // htmlspecialchars helps prevent XSS inside the HTML body.
        $content = str_replace(
            ['{{NAME}}', '{{ROLE}}', '{{EMAIL}}', '{{PHONE}}'],
            [
                htmlspecialchars($sig['name'] ?? ''), 
                htmlspecialchars($sig['role'] ?? ''), 
                htmlspecialchars($sig['email'] ?? ''), 
                htmlspecialchars($sig['phone'] ?? '')
            ],
            $raw_template
        );
        
        $filename_base = $sig['name'] ?? 'signature';
        
    } else {
        // ID not found or does not belong to user
        header('Location: generator.php');
        exit;
    }

// 3. Handle Preview Download
} elseif (isset($_GET['type']) && $_GET['type'] === 'preview' && isset($_SESSION['preview'])) {
    // Note: We assume the generator logic has already sanitized input for the preview.
    $content = $_SESSION['preview'];
    $filename_base = 'preview';
    
} else {
    // Invalid request
    header('Location: generator.php');
    exit;
}

// 4. Sanitize Filename
// Allow only alphanumeric chars, underscores, and hyphens.
$clean_name = preg_replace('/[^a-z0-9_-]/i', '', $filename_base);
if (empty($clean_name)) {
    $clean_name = 'signature';
}
$final_filename = "signature_" . $clean_name . "_" . date('Y-m-d_H-i') . ".html";

// 5. Send Headers & Content
header('Content-Description: File Transfer');
header('Content-Type: text/html; charset=utf-8');
header('Content-Disposition: attachment; filename="' . $final_filename . '"');
header('Expires: 0');
header('Cache-Control: must-revalidate');
header('Pragma: public');
header('Content-Length: ' . strlen($content));
header('X-Content-Type-Options: nosniff');

echo $content;
exit;
?>
