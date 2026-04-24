<?php
// includes/MailHelper.php
// PRODUCTION READY - SMTP Keep-Alive, Bulk Sending & CID Embedding

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\SMTP;

require_once __DIR__ . '/config.php';

// Include PHPMailer (covers both possible paths for maximum compatibility)
if (file_exists(__DIR__ . '/PHPMailer/src/PHPMailer.php')) {
    require_once __DIR__ . '/PHPMailer/src/Exception.php';
    require_once __DIR__ . '/PHPMailer/src/PHPMailer.php';
    require_once __DIR__ . '/PHPMailer/src/SMTP.php';
} else {
    require_once __DIR__ . '/PHPMailer/Exception.php';
    require_once __DIR__ . '/PHPMailer/PHPMailer.php';
    require_once __DIR__ . '/PHPMailer/SMTP.php';
}

class MailHelper
{
    private static $mailerInstance = null;

    /**
     * Sends an HTML email with optional attachments and embedded CID images.
     *
     * @param string $toRecipient   Recipient email address
     * @param string $subject       Email subject
     * @param string $bodyHTML      HTML body content
     * @param string $bodyText      Plain text (if empty, stripped from HTML)
     * @param bool   $enableDebug   Log SMTP debug output (passwords are securely masked)
     * @param array  $attachments   Standard attachments: [['content' => '...', 'name' => '...'], ...]
     * @param array  $embedded      Embedded images (CID): [['cid' => '...', 'path' => '...', 'name' => '...', 'mime' => '...'], ...]
     *
     * @return array ['success' => bool, 'message' => string, 'debug_log' => string]
     */
    public static function send(
        $toRecipient,
        $subject,
        $bodyHTML,
        $bodyText = '',
        $enableDebug = false,
        $attachments = [],
        $embedded = []
    ) {
        global $db;
        $debugOutput = "";

        try {
            // Singleton: Establish SMTP connection only once (Crucial for performance in bulk sending)
            if (self::$mailerInstance === null) {
                $settings = [];
                $stmt = $db->prepare(
                    "SELECT setting_key, setting_value FROM system_settings WHERE setting_key LIKE 'smtp_%'"
                );
                $result = $stmt->execute();
                while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                    $settings[$row['setting_key']] = $row['setting_value'];
                }

                if (empty($settings['smtp_host'])) {
                    return ['success' => false, 'message' => 'SMTP Host missing in database.', 'debug_log' => ''];
                }

                $mail = new PHPMailer(true);
                $mail->isSMTP();
                $mail->Host       = $settings['smtp_host'];
                $mail->SMTPAuth   = (!isset($settings['smtp_auth']) || $settings['smtp_auth'] == '1');

                if ($mail->SMTPAuth) {
                    $mail->Username = $settings['smtp_user'];
                    $mail->Password = $settings['smtp_pass'] ?? '';
                }

                $secureMode = $settings['smtp_secure'] ?? 'tls';
                if ($secureMode === 'none') {
                    $mail->SMTPAutoTLS = false;
                    $mail->SMTPSecure  = false;
                } else {
                    $mail->SMTPSecure = $secureMode;
                }

                $mail->Port           = intval($settings['smtp_port'] ?? 587);
                $mail->CharSet        = 'UTF-8';
                $mail->Timeout        = 15;
                $mail->SMTPKeepAlive  = true; // Enable Keep-Alive for bulk sending efficiency

                $fromEmail = $settings['smtp_from_email'] ?? $settings['smtp_user'];
                if (empty($fromEmail)) {
                    $fromEmail = 'noreply@' . ($_SERVER['SERVER_NAME'] ?? 'localhost');
                }
                $fromName = $settings['smtp_from_name'] ?? 'SubSignature System';
                $mail->setFrom($fromEmail, $fromName);

                self::$mailerInstance = $mail;
            }

            $mail = self::$mailerInstance;

            // Security: Secure debug output by explicitly masking passwords and auth tokens
            if ($enableDebug) {
                $mail->SMTPDebug  = SMTP::DEBUG_CONNECTION;
                $mail->Debugoutput = function ($str, $level) use (&$debugOutput) {
                    $cleanStr = preg_replace('/(PASS\s+)[^\s]+/', '$1 *****', $str);
                    $cleanStr = preg_replace('/(auth\s+login\s+)[^\s]+/i', '$1 [HIDDEN]', $cleanStr);
                    $debugOutput .= "[$level] $cleanStr\n";
                };
            } else {
                $mail->SMTPDebug = 0;
            }

            // Security & Stability: Reset recipients & attachments before each loop iteration
            $mail->clearAddresses();
            $mail->clearAttachments();
            $mail->clearCustomHeaders();
            $mail->clearReplyTos();
            if (method_exists($mail, 'clearEmbeddedImages')) {
                $mail->clearEmbeddedImages();
            }

            $mail->addAddress($toRecipient);
            $mail->isHTML(true);
            $mail->Subject = $subject;
            $mail->Body    = $bodyHTML;
            $mail->AltBody = !empty($bodyText) ? $bodyText : strip_tags($bodyHTML);

            // 1. Process standard attachments (e.g., the .html offline signature file)
            if (!empty($attachments) && is_array($attachments)) {
                foreach ($attachments as $att) {
                    if (isset($att['content'], $att['name'])) {
                        $mail->addStringAttachment($att['content'], $att['name']);
                    }
                }
            }

            // 2. Process embedded images (CID) directly into the email body
            // Note: PHPMailer encodes these binary files to Base64 automatically for email transport compliance.
            if (!empty($embedded) && is_array($embedded)) {
                foreach ($embedded as $emb) {
                    if (isset($emb['cid'])) {
                        // Priority 1: If secure file path is provided (Memory efficient & highly secure)
                        if (isset($emb['path']) && is_file($emb['path'])) {
                            $mail->addEmbeddedImage(
                                $emb['path'],
                                $emb['cid'],
                                $emb['name'] ?? '',
                                'base64',
                                $emb['mime'] ?? ''
                            );
                        } 
                        // Fallback: If raw binary string content is provided directly
                        elseif (isset($emb['content'])) {
                            $mail->addStringEmbeddedImage(
                                $emb['content'],
                                $emb['cid'],
                                $emb['name'] ?? '',
                                'base64',
                                $emb['mime'] ?? ''
                            );
                        }
                    }
                }
            }

            $mail->send();
            return ['success' => true, 'message' => 'Sent', 'debug_log' => $debugOutput];
        } catch (Exception $e) {
            // On error, close connection to ensure a clean state for the next bulk attempt
            if (self::$mailerInstance) {
                self::$mailerInstance->smtpClose();
                self::$mailerInstance = null;
            }
            $debugOutput .= "\nMAILER ERROR: " . $e->getMessage();
            return ['success' => false, 'message' => $e->getMessage(), 'debug_log' => $debugOutput];
        }
    }

    /**
     * Closes the SMTP connection safely at the end of the script execution.
     */
    public static function closeConnection()
    {
        if (self::$mailerInstance) {
            self::$mailerInstance->smtpClose();
            self::$mailerInstance = null;
        }
    }
}
