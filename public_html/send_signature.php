<?php
// send_signature.php
// PRODUCTION READY - Email body uses true CID images, attachment uses Base64 for offline capability.

require_once 'includes/config.php';
require_once 'includes/MailHelper.php';

// ---------------------------------------------------------
// 1. SECURITY & CONFIGURATION
// ---------------------------------------------------------
requireAdmin();

// Ensure output buffers are clean for Server-Sent Events (SSE)
if (function_exists('apache_setenv')) {
    @apache_setenv('no-gzip', 1);
}
@ini_set('zlib.output_compression', 0);
@ini_set('implicit_flush', 1);
while (ob_get_level() > 0) {
    ob_end_clean();
}

// Server-Sent Events (SSE) Headers
header('Content-Type: text/event-stream');
header('Cache-Control: no-cache');
header('Connection: keep-alive');

// ---------------------------------------------------------
// 2. INPUT VALIDATION
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendStreamResponse('fatal_error', 'Security Error: Invalid request method.');
    exit;
}

if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    sendStreamResponse('fatal_error', 'Security Error: Invalid CSRF Token. Request blocked.');
    exit;
}

$ids = $_POST['ids'] ?? [];
if (empty($ids) || !is_array($ids)) {
    sendStreamResponse('fatal_error', 'No signature items selected for processing.');
    exit;
}

// Extend script execution time for bulk operations
set_time_limit(300);

$total = count($ids);
$successCount = 0;
$failCount = 0;
$processed = 0;

// ---------------------------------------------------------
// 3. CORE HELPER FUNCTIONS
// ---------------------------------------------------------

/**
 * Sends a JSON string to the browser via SSE and flushes the buffer.
 */
function sendStreamResponse($status, $message, $progress = null) {
    $data = [
        'status'  => $status,
        'message' => $message,
        'progress'=> $progress
    ];
    echo "data: " . json_encode($data) . "\n\n";
    flush();
}

/**
 * Retrieves the email wrapper template or uses a hardcoded secure fallback.
 */
function getEmailBodyTemplate() {
    $path = __DIR__ . '/templates/email_notification.html';
    if (file_exists($path)) {
        return file_get_contents($path);
    }
    return "<p>Hello {{NAME}},</p>
            <p>Your new signature is attached as <strong>{{ATTACHMENT_NAME}}</strong>.</p>
            <hr>
            {{PREVIEW}}";
}

/**
 * Security Feature: Fetches template content preventing directory traversal.
 */
function getSecureTemplateContent($templateName) {
    // basename() strips any path logic (like ../../) to lock requests to the templates folder
    $cleanName = basename($templateName);
    if (pathinfo($cleanName, PATHINFO_EXTENSION) !== 'html') {
        return '';
    }
    $path = __DIR__ . '/templates/' . $cleanName;
    return file_exists($path) ? file_get_contents($path) : '';
}

/**
 * Security Feature: Sanitizes the generated filename.
 */
function createSafeFilename($userName, $templateName) {
    // Allow only alphanumeric characters, underscores, and dashes
    $safeName = str_replace(' ', '_', $userName);
    $safeName = preg_replace('/[^a-zA-Z0-9_\-]/', '', $safeName);
    return $safeName . '_' . $templateName;
}

/**
 * Converts ALL local image paths to Base64 Data URIs.
 * This is used ONLY for the attached offline .html file so the user can use it without an internet connection.
 *
 * @param string $html    The HTML containing image tags
 * @param string $baseDir Base directory for local images
 * @return string         HTML with safely embedded Data URIs
 */
function embedLocalImagesAsBase64($html, $baseDir) {
    if (!preg_match_all('/<img\s+[^>]*src=["\']([^"\']+)["\'][^>]*>/i', $html, $matches, PREG_SET_ORDER)) {
        return $html;
    }

    $realBase = realpath($baseDir);
    if ($realBase === false) return $html;
    
    $finfo = finfo_open(FILEINFO_MIME_TYPE);

    foreach ($matches as $imgTag) {
        $fullTag = $imgTag[0];
        $src     = $imgTag[1];

        // Skip external URLs and existing Data/CID URIs
        if (preg_match('/^(https?:|data:|cid:)/i', $src)) continue;

        $imagePath = realpath($baseDir . '/' . ltrim($src, '/'));
        if ($imagePath === false || !is_file($imagePath) || !is_readable($imagePath)) continue;

        // Security: Prevent directory traversal outside the base directory entirely
        if (strpos($imagePath, $realBase) !== 0) continue;

        // Security: Validate the actual file signature (MIME-Type) via finfo
        $mimeType = finfo_file($finfo, $imagePath);
        $allowed  = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        if (!in_array($mimeType, $allowed)) continue;

        $content = file_get_contents($imagePath);
        if ($content === false) continue;

        $base64   = base64_encode($content);
        $dataUri  = 'data:' . $mimeType . ';base64,' . $base64;

        $newTag = preg_replace('/src=["\']' . preg_quote($src, '/') . '["\']/i', 'src="' . $dataUri . '"', $fullTag);
        $html = str_replace($fullTag, $newTag, $html);
    }
    
    finfo_close($finfo);
    return $html;
}

/**
 * Prepares HTML for the LIVE Email Body by converting local image paths to CID references.
 * It strictly extracts those images into an array formatted for PHPMailer.
 *
 * @param string $html    The raw email HTML body
 * @param string $baseDir Base directory for local images
 * @return array          ['html' => modified HTML with CID tags, 'embedded' => MailHelper data array]
 */
function prepareCIDImages($html, $baseDir) {
    $embedded = [];
    if (!preg_match_all('/<img\s+[^>]*src=["\']([^"\']+)["\'][^>]*>/i', $html, $matches, PREG_SET_ORDER)) {
        return ['html' => $html, 'embedded' => []];
    }

    $realBase = realpath($baseDir);
    if ($realBase === false) {
        return ['html' => $html, 'embedded' => []];
    }

    $finfo = finfo_open(FILEINFO_MIME_TYPE);

    foreach ($matches as $imgTag) {
        $fullTag = $imgTag[0];
        $src     = $imgTag[1];

        // Ignore external URLs, Data-URIs, and existing CIDs
        if (preg_match('/^(https?:|data:|cid:)/i', $src)) {
            continue;
        }

        // Secure absolute path resolution
        $imagePath = realpath($baseDir . '/' . ltrim($src, '/'));
        if ($imagePath === false || !is_file($imagePath) || !is_readable($imagePath)) {
            continue;
        }

        // Security: Strictly prevent directory traversal outside the base directory
        if (strpos($imagePath, $realBase) !== 0) {
            continue;
        }

        // Security: Validate actual MIME-Type using finfo
        $mimeType = finfo_file($finfo, $imagePath);
        $allowed  = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        if (!in_array($mimeType, $allowed)) {
            continue;
        }

        // Generate a unique Content-ID (CID) for the email client
        $cid = md5($imagePath) . '@subsignature';
        $filename = basename($imagePath);

        // Store configuration for PHPMailer processing
        $embedded[$cid] = [
            'cid'  => $cid,
            'path' => $imagePath, // Supplying the path saves server memory (PHPMailer reads it)
            'name' => $filename,
            'mime' => $mimeType
        ];

        // Replace local src path with the robust CID reference
        $newTag = preg_replace(
            '/src=["\']' . preg_quote($src, '/') . '["\']/i',
            'src="cid:' . $cid . '"',
            $fullTag
        );

        $html = str_replace($fullTag, $newTag, $html);
    }

    finfo_close($finfo);
    return ['html' => $html, 'embedded' => array_values($embedded)];
}

// ---------------------------------------------------------
// 4. ENVIRONMENT PREPARATION
// ---------------------------------------------------------
$emailBodyTemplate = getEmailBodyTemplate();
$baseTemplatesDir = __DIR__;

// ---------------------------------------------------------
// 5. BATCH PROCESSING LOOP
// ---------------------------------------------------------

foreach ($ids as $sig_id) {
    // Terminate gracefully if the user closes their browser
    if (connection_aborted()) {
        exit;
    }

    $processed++;
    $sig_id = (int)$sig_id;

    $stmt = $db->prepare("SELECT name, role, email, phone, template FROM user_signatures WHERE id = ?");
    $stmt->bindValue(1, $sig_id, SQLITE3_INTEGER);
    $res = $stmt->execute();
    $data = $res->fetchArray(SQLITE3_ASSOC);

    $progData = ['current' => $processed, 'total' => $total];

    if (!$data) {
        $failCount++;
        sendStreamResponse('error', "ID $sig_id: Signature record not found in database.", $progData);
        continue;
    }

    $recipient = $data['email'];
    if (empty($recipient) || !filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
        $failCount++;
        $msg = "ID $sig_id: Invalid Email Address provided ($recipient)";
        $db->exec("INSERT INTO mail_logs (signature_id, recipient, status, message) VALUES ($sig_id, '" . $db->escapeString($recipient) . "', 'error', '" . $db->escapeString($msg) . "')");
        sendStreamResponse('error', $msg, $progData);
        continue;
    }

    $rawHtml = getSecureTemplateContent($data['template']);
    if (empty($rawHtml)) {
        $failCount++;
        $msg = "ID $sig_id: Associated template file missing (" . $data['template'] . ")";
        $db->exec("INSERT INTO mail_logs (signature_id, recipient, status, message) VALUES ($sig_id, '" . $db->escapeString($recipient) . "', 'error', '" . $db->escapeString($msg) . "')");
        sendStreamResponse('error', $msg, $progData);
        continue;
    }

    // Replace basic dynamic placeholders within the signature
    $finalSigHtml = str_replace(
        ['{{NAME}}', '{{ROLE}}', '{{EMAIL}}', '{{PHONE}}'],
        [
            htmlspecialchars($data['name']),
            htmlspecialchars($data['role']),
            htmlspecialchars($data['email']),
            htmlspecialchars($data['phone'])
        ],
        $rawHtml
    );

    // --- ARCHITECTURE STRATEGY: TWO-PRONGED APPROACH ---

    // 1. Prepare Base64 HTML exclusively for the .html attachment (Enables offline signature setup)
    $attachmentHtml = embedLocalImagesAsBase64($finalSigHtml, $baseTemplatesDir);
    $attachmentName = createSafeFilename($data['name'], $data['template']);

    // 2. Prepare raw email body wrapping the signature
    $previewBlock = "<div style='border:1px dashed #ccc; padding:15px; margin-top:10px; background:#fff;'>" . $finalSigHtml . "</div>";

    $mailBodyRaw = str_replace(
        ['{{NAME}}', '{{ATTACHMENT_NAME}}', '{{PREVIEW}}'],
        [
            htmlspecialchars($data['name']),
            htmlspecialchars($attachmentName),
            $previewBlock
        ],
        $emailBodyTemplate
    );

    // 3. Convert all local images in the entire email body (including the template) to standard CID references
    $cidData = prepareCIDImages($mailBodyRaw, $baseTemplatesDir);
    $finalMailBody  = $cidData['html'];
    $embeddedImages = $cidData['embedded'];

    $subject = "Your New Email Signature";

    // Setup standard attachment (The HTML file with embedded Base64 images for Outlook/Apple Mail importing)
    $attachments = [
        [
            'content' => $attachmentHtml,
            'name'    => $attachmentName
        ]
    ];

    // DISPATCH USING MAILHELPER (Passing the $embeddedImages array to trigger native CID handling)
    $sendResult = MailHelper::send($recipient, $subject, $finalMailBody, '', false, $attachments, $embeddedImages);

    $status = $sendResult['success'] ? 'success' : 'error';
    $logMsg = $db->escapeString($sendResult['message']);
    $db->exec("INSERT INTO mail_logs (signature_id, recipient, status, message) VALUES ($sig_id, '" . $db->escapeString($recipient) . "', '$status', '$logMsg')");

    if ($sendResult['success']) {
        $successCount++;
        sendStreamResponse('success', "Sent successfully to: $recipient", $progData);
    } else {
        $failCount++;
        sendStreamResponse('error', "Delivery failed for: $recipient (" . $sendResult['message'] . ")", $progData);
    }

    // Anti-Spam throttling implementation
    usleep(500000);
    if ($successCount > 0 && $successCount % 10 === 0) {
        sleep(2);
    }
}

// ---------------------------------------------------------
// 6. FINISHING OPERATIONS
// ---------------------------------------------------------

// Gracefully close the SMTP connection after the loop
if (method_exists('MailHelper', 'closeConnection')) {
    MailHelper::closeConnection();
}

$summary = "Batch operation complete! Success: $successCount, Failed: $failCount";
$finalData = [
    'status'   => 'finished',
    'summary'  => $summary,
    'progress' => ['current' => $total, 'total' => $total]
];
echo "data: " . json_encode($finalData) . "\n\n";
flush();
?>
