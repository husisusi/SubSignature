<?php
require_once 'includes/config.php';

// Security Check: Ensure only admins can access this script
requireAdmin();

// 1. Configuration & Stability
// Prevent the script from stopping if the user cancels the download.
// This is crucial to ensure the temporary file is deleted (cleanup) at the end.
ignore_user_abort(true);

// Increase execution time limit for large archives (e.g., 5 minutes)
set_time_limit(300); 

// Clear Output Buffering
// Essential to prevent whitespace or warnings from corrupting the binary ZIP file
while (ob_get_level()) {
    ob_end_clean();
}

// 2. Define Secure Paths
// Use absolute paths based on __DIR__ to avoid ambiguity
$base_dir = __DIR__; 
$templates_dir = $base_dir . '/templates';

// Verify directory exists
if (!is_dir($templates_dir)) {
    header('Location: admin_templates.php?error=' . urlencode('Error: Templates directory not found.'));
    exit;
}

// 3. Create Secure Temporary File
// 'tempnam' creates a unique file in the system temp directory.
// This is safer than time-based naming to prevent race conditions or collisions.
$zip_path = tempnam(sys_get_temp_dir(), 'tpl_backup_');

if ($zip_path === false) {
    die("Error: Could not create temporary file.");
}

// The filename the user will see when downloading
$download_filename = 'templates_backup_' . date('Y-m-d_H-i-s') . '.zip';

$zip = new ZipArchive();
if ($zip->open($zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) {
    unlink($zip_path); // Cleanup empty file on error
    die("Error: Could not open ZIP file.");
}

// 4. Load Templates Securely
// Use glob with the absolute path
$template_files = glob($templates_dir . '/*.html');
$count = 0;

// Resolve the real physical path of the directory (handles symlinks)
$real_templates_dir = realpath($templates_dir);

if ($template_files) {
    foreach ($template_files as $file) {
        // Resolve the real path of the specific file
        $real_file_path = realpath($file);

        // SECURITY CHECKS:
        // 1. $real_file_path: Ensure file exists and path resolution succeeded.
        // 2. is_file: Ensure it is a file, not a directory.
        // 3. is_readable: Ensure we have permission to read it.
        // 4. strpos check: CRITICAL - Ensure the file is actually *inside* the template directory.
        //    This prevents "Directory Traversal" attacks via malicious symbolic links.
        if ($real_file_path && 
            is_file($real_file_path) && 
            is_readable($real_file_path) && 
            strpos($real_file_path, $real_templates_dir) === 0) {
            
            // Add file to ZIP
            // basename() ensures only the filename is stored, not the folder structure
            $zip->addFile($real_file_path, basename($real_file_path));
            $count++;
        }
    }
}

$zip->close();

// 5. Download Handling
if (file_exists($zip_path) && $count > 0) {
    // Set Headers
    header('Content-Description: File Transfer');
    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="' . $download_filename . '"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($zip_path));
    
    // Security Header: Prevent browsers from MIME-sniffing the response
    header('X-Content-Type-Options: nosniff');
    
    // Ensure buffer is clean before outputting file
    if (ob_get_level()) ob_end_clean();
    flush();
    
    // Send file to browser
    readfile($zip_path);
    
    // 6. CLEANUP
    // Delete the temporary file immediately.
    // Because of ignore_user_abort(true), this runs even if the user cancels the download.
    unlink($zip_path);
    exit;
} else {
    // Error case: Cleanup if file exists but is empty or invalid
    if (file_exists($zip_path)) {
        unlink($zip_path);
    }
    
    // Redirect back with error message
    header('Location: admin_templates.php?error=' . urlencode('Backup failed: No valid templates found.'));
    exit;
}
?>
