<?php
// send_signature.php

require_once 'includes/config.php';
require_once 'includes/MailHelper.php';

// 1. SECURITY CHECKS
requireAdmin();

// Disable buffering to ensure real-time streaming to the browser
if (function_exists('apache_setenv')) {
    @apache_setenv('no-gzip', 1);
}
@ini_set('zlib.output_compression', 0);
@ini_set('implicit_flush', 1);
while (ob_get_level() > 0) {
    ob_end_clean();
}

// Set Headers for Server-Sent Events (SSE) behavior
header('Content-Type: text/event-stream');
header('Cache-Control: no-cache');
header('Connection: keep-alive');

// 2. INPUT VALIDATION
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendStreamResponse('fatal_error', 'Invalid request method.');
    exit;
}

// CSRF Protection
if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    sendStreamResponse('fatal_error', 'Invalid CSRF Token.');
    exit;
}

// Validate IDs
$ids = $_POST['ids'] ?? [];
if (empty($ids) || !is_array($ids)) {
    sendStreamResponse('fatal_error', 'No items selected.');
    exit;
}

// 3. PERFORMANCE SETUP
// Increase time limit for bulk sending (5 minutes)
set_time_limit(300);

// Initialize statistics
$total = count($ids);
$successCount = 0;
$failCount = 0;
$processed = 0;

/**
 * Helper: Send JSON chunk to browser
 */
function sendStreamResponse($status, $message, $progress = null) {
    $data = [
        'status' => $status,
        'message' => $message,
        'progress' => $progress
    ];
    echo "data: " . json_encode($data) . "\n\n";
    flush(); // Force output to browser immediately
}

/**
 * Helper: Secure Template Loading
 */
function getSecureTemplateContent($templateName) {
    $cleanName = basename($templateName);
    if (pathinfo($cleanName, PATHINFO_EXTENSION) !== 'html') {
        return '';
    }
    $path = __DIR__ . '/templates/' . $cleanName;
    return file_exists($path) ? file_get_contents($path) : '';
}

/**
 * Helper: Create Safe Filename for Attachment
 * Example: "John Doe" + "template.html" -> "John_Doe_template.html"
 */
function createSafeFilename($userName, $templateName) {
    $safeName = str_replace(' ', '_', $userName);
    $safeName = preg_replace('/[^a-zA-Z0-9_\-]/', '', $safeName);
    return $safeName . '_' . $templateName;
}

// 4. PROCESSING LOOP
foreach ($ids as $sig_id) {
    
    // --- CRITICAL SECURITY: PANIC BUTTON CHECK ---
    // If the user clicked "Stop" in the browser, the connection is dropped.
    // We detect this and kill the script immediately.
    if (connection_aborted()) {
        // Optional: Log this event if needed
        // error_log("Bulk send aborted by user.");
        exit; // Hard stop
    }
    
    $processed++;
    $sig_id = (int)$sig_id;

    // Fetch Data
    $stmt = $db->prepare("SELECT name, role, email, phone, template FROM user_signatures WHERE id = ?");
    $stmt->bindValue(1, $sig_id, SQLITE3_INTEGER);
    $res = $stmt->execute();
    $data = $res->fetchArray(SQLITE3_ASSOC);

    // Progress State
    $progData = ['current' => $processed, 'total' => $total];

    if (!$data) {
        $failCount++;
        sendStreamResponse('error', "ID $sig_id: Signature not found.", $progData);
        continue;
    }

    $recipient = $data['email'];

    // Validate Email
    if (empty($recipient) || !filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
        $failCount++;
        $msg = "ID $sig_id: Invalid Email ($recipient)";
        
        // Log Error to DB
        $db->exec("INSERT INTO mail_logs (signature_id, recipient, status, message) VALUES ($sig_id, '$recipient', 'error', '$msg')");
        
        sendStreamResponse('error', $msg, $progData);
        continue;
    }

    // Load Template
    $rawHtml = getSecureTemplateContent($data['template']);
    if (empty($rawHtml)) {
        $failCount++;
        $msg = "ID $sig_id: Template missing ($data[template])";
        
        // Log Error to DB
        $db->exec("INSERT INTO mail_logs (signature_id, recipient, status, message) VALUES ($sig_id, '$recipient', 'error', '$msg')");
        
        sendStreamResponse('error', $msg, $progData);
        continue;
    }

    // Replace Placeholders
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

    // Prepare Dynamic Attachment Name
    $attachmentName = createSafeFilename($data['name'], $data['template']);

    // Prepare Email Body
    $subject = "Your New Email Signature";
    $body  = "<p>Hello " . htmlspecialchars($data['name']) . ",</p>";
    $body .= "<p>Your new signature is attached as <strong>" . htmlspecialchars($attachmentName) . "</strong>.</p>";
    $body .= "<p>Please open the attachment in your browser, copy everything (Ctrl+A, Ctrl+C), and paste it into your email signature settings.</p>";
    $body .= "<p>Best regards,</p>";
    $body .= "<hr><h4>Preview:</h4>";
    $body .= "<div style='border:1px dashed #ccc; padding:10px;'>" . $finalHtml . "</div>";

    $attachments = [
        [
            'content' => $finalHtml,
            'name'    => $attachmentName
        ]
    ];

    // SEND MAIL
    $sendResult = MailHelper::send($recipient, $subject, $body, '', false, $attachments);

    // LOG TO DATABASE
    $status = $sendResult['success'] ? 'success' : 'error';
    $logMsg = $db->escapeString($sendResult['message']);
    
    $logSql = "INSERT INTO mail_logs (signature_id, recipient, status, message) VALUES ($sig_id, '$recipient', '$status', '$logMsg')";
    $db->exec($logSql);

    if ($sendResult['success']) {
        $successCount++;
        sendStreamResponse('success', "Sent to: $recipient", $progData);
    } else {
        $failCount++;
        sendStreamResponse('error', "Failed: $recipient (" . $sendResult['message'] . ")", $progData);
    }

    // THROTTLING (Anti-Spam)
    // 0.5s pause per mail
    usleep(500000); 
    // Every 10 mails, pause 2s
    if ($successCount > 0 && $successCount % 10 === 0) {
        sleep(2);
    }
}

// 5. CLEANUP & FINISH
if (method_exists('MailHelper', 'closeConnection')) {
    MailHelper::closeConnection();
}

$summary = "Finished! Success: $successCount, Failed: $failCount";
$finalData = [
    'status' => 'finished',
    'summary' => $summary,
    'progress' => ['current' => $total, 'total' => $total]
];
echo "data: " . json_encode($finalData) . "\n\n";
flush();
?>
