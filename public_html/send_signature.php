<?php
// send_signature.php

require_once 'includes/config.php';
require_once 'includes/MailHelper.php';

// 1. SECURITY CHECKS
requireAdmin();

// Set JSON Header
header('Content-Type: application/json');

// Allow only POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['status' => 'error', 'message' => 'Invalid request']);
    exit;
}

// CSRF Protection
if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    echo json_encode(['status' => 'error', 'message' => 'Invalid CSRF Token']);
    exit;
}

// Validate IDs
$ids = $_POST['ids'] ?? [];
if (empty($ids) || !is_array($ids)) {
    echo json_encode(['status' => 'error', 'message' => 'No items selected']);
    exit;
}

// 2. PERFORMANCE SETUP
// Increase time limit to 5 minutes for bulk sending
set_time_limit(300);

// Disable output buffering to save memory
if (function_exists('apache_setenv')) {
    @apache_setenv('no-gzip', 1);
}
@ini_set('zlib.output_compression', 0);

// Initialize results
$results = ['total' => count($ids), 'success' => 0, 'failed' => 0, 'details' => []];

/**
 * Helper function: Load template securely
 * Prevents directory traversal and allows only .html files
 */
function getSecureTemplateContent($templateName) {
    $cleanName = basename($templateName);
    
    // SECURITY: Allow only .html files
    if (pathinfo($cleanName, PATHINFO_EXTENSION) !== 'html') {
        return '';
    }

    $path = __DIR__ . '/templates/' . $cleanName;
    return file_exists($path) ? file_get_contents($path) : '';
}

// Counter for throttling
$sentCounter = 0;

foreach ($ids as $sig_id) {
    $sig_id = (int)$sig_id;
    
    // 3. PROCESS DATA
    // Prepared statement for security
    $stmt = $db->prepare("SELECT name, role, email, phone, template FROM user_signatures WHERE id = ?");
    $stmt->bindValue(1, $sig_id, SQLITE3_INTEGER);
    $res = $stmt->execute();
    $data = $res->fetchArray(SQLITE3_ASSOC);

    if (!$data) {
        $results['failed']++;
        continue;
    }

    // Email validation
    $recipient = $data['email']; 
    if (empty($recipient) || !filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
        $results['failed']++;
        $results['details'][] = "ID $sig_id: Invalid Email ($recipient)";
        continue;
    }

    // Load & replace template
    $rawHtml = getSecureTemplateContent($data['template']);
    if (empty($rawHtml)) {
        $results['failed']++;
        $results['details'][] = "ID $sig_id: Template missing or invalid ($data[template])";
        continue;
    }

    $finalHtml = str_replace(
        ['{{NAME}}', '{{ROLE}}', '{{EMAIL}}', '{{PHONE}}'],
        [
            htmlspecialchars($data['name']), 
            htmlspecialchars($data['role']), 
            htmlspecialchars($data['email']), 
            htmlspecialchars($data['phone'])
        ],
        $rawHtml
    );

    // Assemble email body
    $subject = "Your New Email Signature";
    $body  = "<h3>Hello " . htmlspecialchars($data['name']) . ",</h3>";
    $body .= "<p>Your new signature is attached as <strong>" . htmlspecialchars($data['template']) . "</strong>.</p>";
    $body .= "<p>Please open the attachment in your browser, copy everything (Ctrl+A, Ctrl+C), and paste it into your email signature settings.</p>";
    $body .= "<hr><h4>Preview:</h4>";
    $body .= "<div style='border:1px dashed #ccc; padding:10px;'>" . $finalHtml . "</div>";

    // Prepare attachment
    $attachments = [
        [
            'content' => $finalHtml,
            'name'    => $data['template']
        ]
    ];

    // 4. SENDING (via MailHelper)
    // Debug is FALSE here to keep logs clean
    $sendResult = MailHelper::send($recipient, $subject, $body, '', false, $attachments);

    if ($sendResult['success']) {
        $results['success']++;
        $sentCounter++;
    } else {
        $results['failed']++;
        $results['details'][] = "ID $sig_id: " . $sendResult['message'];
    }

    // 5. THROTTLING (Spam Protection)
    // 0.5 second pause after every mail
    usleep(500000); 

    // Every 10 mails a longer pause (2 seconds) to calm the SMTP server
    if ($sentCounter > 0 && $sentCounter % 10 === 0) {
        sleep(2);
    }
}

// 6. CLEANUP
// Close the persistent connection if MailHelper supports it
if (method_exists('MailHelper', 'closeConnection')) {
    MailHelper::closeConnection();
}

echo json_encode(['status' => 'success', 'data' => $results]);
?>
