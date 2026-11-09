<?php
// send_signature.php
// Sends signatures by email (admin only, POST + CSRF, progress via Server-Sent Events).
// The mail body uses CID images, the attachment uses Base64 images for offline use.

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

header('Content-Type: text/event-stream');
header('Cache-Control: no-cache');
header('X-Accel-Buffering: no'); // disable nginx buffering

// ---------------------------------------------------------
// 2. INPUT VALIDATION
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendStreamResponse('fatal_error', t('Security Error: Invalid request method.'));
    exit;
}

if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
    sendStreamResponse('fatal_error', t('Security Error: Invalid CSRF Token. Request blocked.'));
    exit;
}

$ids = $_POST['ids'] ?? [];
if (empty($ids) || !is_array($ids)) {
    sendStreamResponse('fatal_error', t('No signature items selected for processing.'));
    exit;
}
// Integers only, unique, and capped to protect the SMTP server and this process.
$ids = array_values(array_unique(array_filter(array_map('intval', $ids), function ($v) { return $v > 0; })));
if (count($ids) > 500) {
    sendStreamResponse('fatal_error', t('Too many items selected (maximum 500 per run).'));
    exit;
}

// The mail run can take minutes. Release the session lock now, otherwise
// every other request of this user would block until the run is finished.
session_write_close();
set_time_limit(600);

$total = count($ids);
$successCount = 0;
$failCount = 0;
$processed = 0;
$adminId = (int)($_SESSION['user_id'] ?? 0);

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
    echo "data: " . json_encode($data, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) . "\n\n";
    flush();
}

/**
 * Retrieves the email wrapper template or uses a hardcoded secure fallback.
 */
function getEmailBodyTemplate() {
    $path = TEMPLATES_DIR . '/email_notification.html';
    if (is_file($path)) {
        return sanitizeTemplateHtml((string)file_get_contents($path));
    }
    return "<p>Hello {{NAME}},</p>
            <p>Your new signature is attached as <strong>{{ATTACHMENT_NAME}}</strong>.</p>
            <hr>
            {{PREVIEW}}";
}

/**
 * Security Feature: Sanitizes the generated filename.
 */
function createSafeFilename($userName, $templateName) {
    return safeFileNamePart($userName) . '_' . preg_replace('/[^A-Za-z0-9_.\-]/', '', (string)$templateName);
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

    $finfo = finfo_open(FILEINFO_MIME_TYPE);

    foreach ($matches as $imgTag) {
        $fullTag = $imgTag[0];
        $src     = $imgTag[1];

        // Skip external URLs and existing Data/CID URIs
        if (preg_match('/^(https?:|data:|cid:)/i', $src)) continue;

        $imagePath = realpath($baseDir . '/' . ltrim($src, '/'));
        if ($imagePath === false || !is_file($imagePath) || !is_readable($imagePath)) continue;

        // Security: only files inside the image directory may be embedded
        if (!isPathInside($imagePath, IMAGES_DIR)) continue;

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

        // Security: only files inside the image directory may be embedded
        if (!isPathInside($imagePath, IMAGES_DIR)) {
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
$baseTemplatesDir = APP_ROOT;

// ---------------------------------------------------------
// 5. BATCH PROCESSING LOOP
// ---------------------------------------------------------

foreach ($ids as $sig_id) {
    // Terminate gracefully if the user closes their browser
    if (connection_aborted()) {
        exit;
    }

    $processed++;

    $stmt = $db->prepare('SELECT name, role, email, phone, template FROM user_signatures WHERE id = ?');
    $stmt->bindValue(1, $sig_id, SQLITE3_INTEGER);
    $data = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    $progData = ['current' => $processed, 'total' => $total];

    if (!$data) {
        $failCount++;
        sendStreamResponse('error', t('ID {id}: Signature record not found in database.', ['id' => $sig_id]), $progData);
        continue;
    }

    $recipient = (string)$data['email'];
    if ($recipient === '' || !filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
        $failCount++;
        $msg = "ID $sig_id: Invalid email address ($recipient)";   // log entry stays English
        $msgUi = t('ID {id}: Invalid email address ({recipient})', ['id' => $sig_id, 'recipient' => $recipient]);
        logMail($db, $sig_id, $recipient, 'error', $msg);
        sendStreamResponse('error', $msgUi, $progData);
        continue;
    }

    // Signature HTML: template (sanitised) with escaped values.
    $finalSigHtml = renderStoredSignature($data);
    if (trim($finalSigHtml) === '') {
        $failCount++;
        $msg = "ID $sig_id: Template file missing (" . $data['template'] . ")";
        $msgUi = t('ID {id}: Template file missing ({template})', ['id' => $sig_id, 'template' => $data['template']]);
        logMail($db, $sig_id, $recipient, 'error', $msg);
        sendStreamResponse('error', $msgUi, $progData);
        continue;
    }

    // Attachment: all local images inlined as Base64 so the file works offline.
    $attachmentHtml = embedLocalImagesAsBase64($finalSigHtml, $baseTemplatesDir);
    $attachmentName = createSafeFilename($data['name'], $data['template']);

    // Mail body: the wrapper template around a preview of the signature (single pass replacement).
    $previewBlock = "<div style='border:1px dashed #ccc; padding:15px; margin-top:10px; background:#ffffff;'>" . $finalSigHtml . "</div>";
    $mailBodyRaw = strtr($emailBodyTemplate, [
        '{{NAME}}'            => e($data['name']),
        '{{ATTACHMENT_NAME}}' => e($attachmentName),
        '{{PREVIEW}}'         => $previewBlock,
    ]);

    // Local images in the body become CID references (real inline images).
    $cidData = prepareCIDImages($mailBodyRaw, $baseTemplatesDir);
    $finalMailBody  = $cidData['html'];
    $embeddedImages = $cidData['embedded'];

    $attachments = [[
        'content' => $attachmentHtml,
        'name'    => $attachmentName,
    ]];

    $sendResult = MailHelper::send($recipient, t('Your New Email Signature'), $finalMailBody, '', false, $attachments, $embeddedImages);

    $status = $sendResult['success'] ? 'success' : 'error';
    logMail($db, $sig_id, $recipient, $status, (string)$sendResult['message']);

    if ($sendResult['success']) {
        $successCount++;
        sendStreamResponse('success', t('Sent successfully to: {recipient}', ['recipient' => $recipient]), $progData);
    } else {
        $failCount++;
        sendStreamResponse('error', t('Delivery failed for: {recipient} ({message})', ['recipient' => $recipient, 'message' => $sendResult['message']]), $progData);
    }

    // Anti-spam throttling
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

$summary = t('Batch operation complete! Success: {success}, Failed: {failed}', ['success' => $successCount, 'failed' => $failCount]);
logSecurityEventToDB($db, 'SIGNATURE_MAIL_BATCH', $adminId, "Success: $successCount, Failed: $failCount");
$finalData = [
    'status'   => 'finished',
    'summary'  => $summary,
    'progress' => ['current' => $total, 'total' => $total]
];
echo "data: " . json_encode($finalData, JSON_UNESCAPED_UNICODE) . "\n\n";
flush();
?>
