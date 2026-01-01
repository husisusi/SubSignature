<?php
// download_all.php

// 1. Configuration & Security
require_once 'includes/config.php';
requireLogin();

// Increase limits for large zip generation
set_time_limit(300);
ini_set('memory_limit', '256M');

// Clean output buffer to prevent zip corruption
while (ob_get_level()) {
    ob_end_clean();
}

// -------------------------------------------------------------------------
// 2. TARGET USER LOGIC (SECURITY PRIORITY 1)
// -------------------------------------------------------------------------
$current_user_id = $_SESSION['user_id'];
$target_user_id = $current_user_id; // Default to self

// Only Administrators are allowed to download data for other users
if (isAdmin()) {
    // Check GET request (Standard Download Link)
    if (isset($_GET['user_id'])) {
        $target_user_id = (int)$_GET['user_id'];
    }
    // Check POST request (Batch Init)
    if (isset($_POST['user_id'])) {
        $target_user_id = (int)$_POST['user_id'];
    }
}
// -------------------------------------------------------------------------

$batch_size = 50;

// --- Helper Function: Secure Template Loading ---
function getSecureTemplateContent($templateName) {
    $base_dir = __DIR__ . '/templates';
    $real_base = realpath($base_dir);
    
    // Sanitize filename
    $safe_name = basename($templateName);
    $target = realpath($base_dir . '/' . $safe_name);
    
    // Security Check: Ensure path is within templates directory
    if ($target && $real_base && strpos($target, $real_base) === 0 && file_exists($target)) {
        return file_get_contents($target);
    }
    
    // Fallback
    $fallback = $base_dir . '/signature_default.html';
    return file_exists($fallback) ? file_get_contents($fallback) : '';
}

// =========================================================================
// SECTION A: BATCH MODE INITIALIZATION
// =========================================================================
if (isset($_POST['batch_download']) && $_POST['batch_download'] == '1') {
    header('Content-Type: application/json');
    
    // Use $target_user_id instead of session user
    $stmt = $db->prepare("SELECT COUNT(*) as total FROM user_signatures WHERE user_id = ?");
    $stmt->bindValue(1, $target_user_id, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $total = $result->fetchArray(SQLITE3_ASSOC)['total'];
    
    if ($total == 0) {
        echo json_encode(['error' => 'No signatures to download']);
        exit;
    }
    
    $batches = ceil($total / $batch_size);
    
    // SECURITY: Use cryptographically secure random ID
    $batch_id = bin2hex(random_bytes(16));
    
    $batch_file = sys_get_temp_dir() . '/batch_' . $batch_id . '.json';
    
    $batch_data = [
        'user_id' => $target_user_id, // Store the TARGET ID (owner of data)
        'requester_id' => $current_user_id, // Store who requested it (for audit/checks)
        'total_signatures' => $total,
        'batch_size' => $batch_size,
        'batches' => $batches,
        'created_at' => date('Y-m-d H:i:s'),
        'status' => 'pending',
        'processed_batches' => 0,
        'temp_files' => []
    ];
    
    if (file_put_contents($batch_file, json_encode($batch_data, JSON_PRETTY_PRINT)) === false) {
         echo json_encode(['error' => 'Could not create batch file']);
         exit;
    }
    
    // Start processing
    processBatch($batch_id, 0);
    
    echo json_encode([
        'batch_id' => $batch_id,
        'total' => $total,
        'batches' => $batches,
        'message' => "Processing started"
    ]);
    exit;
}

// =========================================================================
// SECTION B: CHECK BATCH STATUS
// =========================================================================
if (isset($_GET['check_batch']) && isset($_GET['batch_id'])) {
    header('Content-Type: application/json');

    $batch_id = basename($_GET['batch_id']); // Sanitize input
    $batch_file = sys_get_temp_dir() . '/batch_' . $batch_id . '.json';
    
    if (!file_exists($batch_file)) {
        echo json_encode(['error' => 'Batch not found']);
        exit;
    }
    
    $batch_data = json_decode(file_get_contents($batch_file), true);
    
    // SECURITY: Access Control
    // Allow if user is Admin OR if user owns the batch data
    $is_owner = (isset($batch_data['user_id']) && $batch_data['user_id'] == $current_user_id);
    
    if (!isAdmin() && !$is_owner) {
        http_response_code(403);
        echo json_encode(['error' => 'Access denied']);
        exit;
    }
    
    echo json_encode($batch_data);
    exit;
}

// =========================================================================
// SECTION C: DOWNLOAD COMPLETED BATCH
// =========================================================================
if (isset($_GET['download_batch']) && isset($_GET['batch_id'])) {
    $batch_id = basename($_GET['batch_id']); // Sanitize
    $batch_file = sys_get_temp_dir() . '/batch_' . $batch_id . '.json';
    
    if (!file_exists($batch_file)) {
        die('Batch not found');
    }
    
    $batch_data = json_decode(file_get_contents($batch_file), true);
    
    // SECURITY: Access Control
    $is_owner = (isset($batch_data['user_id']) && $batch_data['user_id'] == $current_user_id);
    
    if (!isAdmin() && !$is_owner) {
        die('Access denied');
    }
    
    if ($batch_data['status'] != 'completed') {
        die('Batch not completed yet');
    }
    
    // Get info of the data owner (not necessarily the logged-in admin)
    $data_owner_id = $batch_data['user_id'];
    
    $user_stmt = $db->prepare("SELECT username, full_name FROM users WHERE id = ?");
    $user_stmt->bindValue(1, $data_owner_id, SQLITE3_INTEGER);
    $user_result = $user_stmt->execute();
    $user_info = $user_result->fetchArray(SQLITE3_ASSOC);
    
    $display_name = $user_info['full_name'] ?? $user_info['username'] ?? 'user';
    $clean_name = preg_replace('/[^a-z0-9]/i', '_', strtolower($display_name));
    
    // Create Secure Temp File for Final ZIP
    $zip_path = tempnam(sys_get_temp_dir(), 'final_zip_');
    $zipFilename = 'signatures_' . $clean_name . '_' . date('Y-m-d_H-i') . '.zip';
    
    $zip = new ZipArchive();
    if ($zip->open($zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) {
        die('Cannot create ZIP file');
    }
    
    // Add temp files to main zip
    foreach ($batch_data['temp_files'] as $temp_file) {
        if (file_exists($temp_file)) {
             // Add partial zips to the main zip to allow merging
             $zip->addFile($temp_file, 'parts/' . basename($temp_file));
        }
    }
    
    addMetadataToZip($zip, $display_name, $batch_data['total_signatures']);
    
    $zip->close();
    
    // Send File
    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="' . $zipFilename . '"');
    header('Content-Length: ' . filesize($zip_path));
    header('X-Content-Type-Options: nosniff');
    
    readfile($zip_path);
    
    // CLEANUP
    unlink($zip_path);
    if (!empty($batch_data['temp_files'])) {
        foreach ($batch_data['temp_files'] as $tf) {
            if (file_exists($tf)) unlink($tf);
        }
    }
    if (file_exists($batch_file)) unlink($batch_file);
    exit;
}

// =========================================================================
// SECTION D: NORMAL DOWNLOAD (Standard HTML Zip)
// =========================================================================

// Use $target_user_id here!
$stmt = $db->prepare("SELECT * FROM user_signatures WHERE user_id = ? ORDER BY created_at DESC");
$stmt->bindValue(1, $target_user_id, SQLITE3_INTEGER);
$result = $stmt->execute();

$signatures = [];
while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
    $signatures[] = $row;
}

if (empty($signatures)) {
    // Redirect back if empty
    header('Location: export_signatures.php?error=' . urlencode('No signatures to download'));
    exit;
}

// Get User Info for Filename
$user_stmt = $db->prepare("SELECT username, full_name FROM users WHERE id = ?");
$user_stmt->bindValue(1, $target_user_id, SQLITE3_INTEGER);
$user_info = $user_stmt->execute()->fetchArray(SQLITE3_ASSOC);
$display_name = $user_info['full_name'] ?? $user_info['username'] ?? 'user';

// Create Temp Zip
$zip_path = tempnam(sys_get_temp_dir(), 'sig_zip_');
$clean_name = preg_replace('/[^a-z0-9]/i', '_', strtolower($display_name));
$download_filename = 'signatures_' . $clean_name . '_' . date('Y-m-d_H-i') . '.zip';

$zip = new ZipArchive();
if ($zip->open($zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) {
    die('Cannot create ZIP file');
}

// Process Signatures
$readme_content = "";

foreach ($signatures as $index => $sig) {
    // 1. Secure Template Loading
    $template_content = getSecureTemplateContent($sig['template']);
    
    // 2. XSS Protection for HTML Content
    $html = str_replace(
        ['{{NAME}}', '{{ROLE}}', '{{EMAIL}}', '{{PHONE}}'],
        [
            htmlspecialchars($sig['name'], ENT_QUOTES, 'UTF-8'), 
            htmlspecialchars($sig['role'], ENT_QUOTES, 'UTF-8'), 
            htmlspecialchars($sig['email'], ENT_QUOTES, 'UTF-8'), 
            htmlspecialchars($sig['phone'], ENT_QUOTES, 'UTF-8')
        ],
        $template_content
    );
    
    // 3. Optional: Clean Phone Link
    $cleanPhone = preg_replace('/[^0-9+]/', '', $sig['phone']);
    $html = str_replace('{{PHONE_CLEAN}}', $cleanPhone, $html);
    
    // 4. Safe Filename
    $cleanSigName = preg_replace('/[^a-z0-9]/i', '_', strtolower($sig['name']));
    if(empty($cleanSigName)) $cleanSigName = "signature";
    
    // Ensure filename uniqueness with ID
    $filename = sprintf("%s_%s_%d.html", $cleanSigName, date('Y-m-d', strtotime($sig['created_at'])), $sig['id']);
    
    $zip->addFromString('signatures/' . $filename, $html);
    
    // Build Readme string
    $readme_content .= sprintf("%03d. %s (%s)\n", $index + 1, $sig['name'], $filename);
}

addMetadataToZip($zip, $display_name, count($signatures));

$zip->close();

// Download headers
header('Content-Type: application/zip');
header('Content-Disposition: attachment; filename="' . $download_filename . '"');
header('Content-Length: ' . filesize($zip_path));
header('X-Content-Type-Options: nosniff');
header('Cache-Control: private, max-age=0, must-revalidate');

readfile($zip_path);
unlink($zip_path);
exit;

// --- UTILITY FUNCTIONS ---

function addMetadataToZip($zip, $display_name, $count) {
    $readme = "EXPORT SUMMARY\nUser: $display_name\nCount: $count\nDate: " . date('Y-m-d');
    $zip->addFromString("README.txt", $readme);
    
    $manifest = [
        'user' => $display_name,
        'count' => $count,
        'date' => date('Y-m-d H:i:s')
    ];
    $zip->addFromString("manifest.json", json_encode($manifest, JSON_PRETTY_PRINT));
}

function processBatch($batch_id, $batch_index) {
    global $db, $batch_size;
    
    // Security: Validate batch ID format
    if (!preg_match('/^[a-f0-9]+$/', $batch_id)) return;
    
    $batch_file = sys_get_temp_dir() . '/batch_' . $batch_id . '.json';
    if (!file_exists($batch_file)) return;
    
    $batch_data = json_decode(file_get_contents($batch_file), true);
    
    $user_id = $batch_data['user_id'];
    $offset = $batch_index * $batch_size;
    
    // Fetch data for this batch
    $stmt = $db->prepare("SELECT * FROM user_signatures WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?");
    $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
    $stmt->bindValue(2, $batch_size, SQLITE3_INTEGER);
    $stmt->bindValue(3, $offset, SQLITE3_INTEGER);
    $result = $stmt->execute();
    
    $signatures = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $signatures[] = $row;
    }
    
    if (empty($signatures)) {
        $batch_data['status'] = 'completed';
        file_put_contents($batch_file, json_encode($batch_data));
        return;
    }
    
    // Create partial zip for this batch
    $temp_zip = sys_get_temp_dir() . '/part_' . $batch_id . '_' . $batch_index . '.zip';
    $zip = new ZipArchive();
    if ($zip->open($temp_zip, ZipArchive::CREATE) === TRUE) {
        foreach ($signatures as $index => $sig) {
             $content = getSecureTemplateContent($sig['template']);
             $html = str_replace(
                ['{{NAME}}', '{{ROLE}}', '{{EMAIL}}', '{{PHONE}}'],
                [htmlspecialchars($sig['name']), htmlspecialchars($sig['role']), htmlspecialchars($sig['email']), htmlspecialchars($sig['phone'])],
                $content
            );
            $cleanName = preg_replace('/[^a-z0-9]/i', '_', $sig['name']);
            $zip->addFromString($cleanName . '_' . $sig['id'] . '.html', $html);
        }
        $zip->close();
        
        $batch_data['temp_files'][] = $temp_zip;
        $batch_data['processed_batches'] = $batch_index + 1;
        
        // Next step logic
        if ($batch_data['processed_batches'] >= $batch_data['batches']) {
            $batch_data['status'] = 'completed';
        } else {
             $batch_data['status'] = 'processing';
             register_shutdown_function(function() use ($batch_id, $batch_index) {
                processBatch($batch_id, $batch_index + 1);
            });
        }
        file_put_contents($batch_file, json_encode($batch_data));
    }
}
?>
