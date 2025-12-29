<?php
// preview_template.php

// 1. Include Configuration
require_once 'includes/config.php';

// 2. Authentication Check
// Restrict access to logged-in users.
// This prevents unauthorized users from enumerating files on your server.
requireLogin();

// 3. Define Secure Paths
// Use absolute paths to ensure we are working in the correct directory.
$templates_dir = __DIR__ . '/templates';
$real_templates_dir = realpath($templates_dir);

// Get input safely
$template = $_GET['template'] ?? 'signature_default.html';

// 4. Path Construction & Validation
// basename() strips directory traversal characters (../)
$filename = basename($template);
$target_path = $templates_dir . '/' . $filename;

// realpath() resolves symlinks and checks existence
$real_target_path = realpath($target_path);

// SECURITY CHECK:
// 1. $real_target_path: File must exist.
// 2. strpos check: File must be strictly inside the templates folder (prevents symlink attacks).
// 3. Extension check: Allow only .html files to be loaded.
// 4. is_file: Ensure it is a file, not a directory.
if ($real_target_path && 
    $real_templates_dir && 
    strpos($real_target_path, $real_templates_dir) === 0 && 
    pathinfo($real_target_path, PATHINFO_EXTENSION) === 'html' &&
    is_file($real_target_path)) {

    // 5. Load Content
    $content = file_get_contents($real_target_path);
    
    // Replace placeholders with dummy data for preview
    $preview = str_replace(
        ['{{NAME}}', '{{ROLE}}', '{{EMAIL}}', '{{PHONE}}'],
        ['John Doe', 'Senior Developer', 'john.doe@company.com', '+49 89 12345678'],
        $content
    );
    
    // Set correct header
    header('Content-Type: text/html; charset=utf-8');
    echo $preview;

} else {
    // 6. Error Handling
    http_response_code(404);
    echo '<h1>Template not found!</h1>';
    
    // XSS Protection:
    // When echoing user input ($template) back to the screen, always use htmlspecialchars with ENT_QUOTES.
    echo '<p>Template: ' . htmlspecialchars($template, ENT_QUOTES, 'UTF-8') . '</p>';
}
?>
