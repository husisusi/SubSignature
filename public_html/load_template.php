<?php
// load_template.php

// 1. Include Configuration
require_once 'includes/config.php';

// 2. Authentication Check
// Restrict access to logged-in users only.
// This prevents public enumeration of your template files.
requireLogin();

// 3. Define Safe Directories
// Use absolute paths to avoid ambiguity.
$templates_dir = __DIR__ . '/templates';
$real_templates_dir = realpath($templates_dir);

// 4. Process Input
$file = $_GET['file'] ?? '';
// basename() is the first line of defense against directory traversal (../)
$filename = basename($file);

// Construct the full path
$target_path = $templates_dir . '/' . $filename;

// Resolve the real path (handles symlinks and checks existence)
$real_target_path = realpath($target_path);

// 5. Security Validation
// We perform multiple checks to ensure the file is safe to load:
// a) $real_target_path: Ensures file exists (realpath returns false otherwise).
// b) strpos check: CRITICAL - The resolved path must be INSIDE the templates directory.
//    This prevents attacks using symbolic links pointing to sensitive system files.
// c) Extension check: Strictly allow only .html files.
// d) is_file: Ensures we are not trying to read a directory.
if ($real_target_path && 
    $real_templates_dir && 
    strpos($real_target_path, $real_templates_dir) === 0 && 
    pathinfo($real_target_path, PATHINFO_EXTENSION) === 'html' &&
    is_file($real_target_path)) {

    // 6. Set Secure Headers
    header('Content-Type: text/html; charset=utf-8');
    header('X-Content-Type-Options: nosniff');

    // Output the file content
    echo file_get_contents($real_target_path);

} else {
    // 7. Error Handling
    // Return standard 404 if file is missing or validation fails.
    http_response_code(404);
    echo "Template not found or access denied.";
}
?>
