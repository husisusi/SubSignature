<?php
// admin_config.php
// PRODUCTION READY VERSION

require_once 'includes/config.php';
requireAdmin();

// 1. Initialize Variables
$message = '';
$error = '';
$debug_log = '';

// Check for Session Flash Messages
if (isset($_SESSION['flash_message'])) {
    $message = $_SESSION['flash_message'];
    unset($_SESSION['flash_message']);
}
if (isset($_SESSION['flash_error'])) {
    $error = $_SESSION['flash_error'];
    unset($_SESSION['flash_error']);
}
if (isset($_SESSION['flash_debug'])) {
    $debug_log = $_SESSION['flash_debug'];
    unset($_SESSION['flash_debug']);
}

// Helper function
function getSetting($db, $key, $default = '') {
    $stmt = $db->prepare("SELECT setting_value FROM system_settings WHERE setting_key = ?");
    $stmt->bindValue(1, $key, SQLITE3_TEXT);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);
    return ($row) ? $row['setting_value'] : $default;
}

// ---------------------------------------------------------
// 2. HANDLE TEST EMAIL (POST -> REDIRECT)
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'test_email') {
    
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Security Error: Invalid CSRF Token");
    }

    if (!file_exists('includes/MailHelper.php')) {
        $_SESSION['flash_error'] = "MailHelper.php missing.";
    } else {
        require_once 'includes/MailHelper.php';
        
        $test_email = filter_var($_POST['test_recipient'], FILTER_SANITIZE_EMAIL);
        // NEU: Debugging nur aktivieren, wenn Checkbox gesetzt ist
        $show_debug = isset($_POST['show_debug_log']) && $_POST['show_debug_log'] == '1';
        
        if (filter_var($test_email, FILTER_VALIDATE_EMAIL)) {
            
            $logHeader = "--- SMTP TEST STARTED AT " . date('H:i:s') . " ---\n";
            
            // MailHelper aufrufen (mit Debug-Schalter)
            $result = MailHelper::send(
                $test_email, 
                'SMTP Test - SubSignature', 
                '<h3>SMTP Test Successful ✅</h3><p>Your configuration works.</p>',
                'SMTP Test Successful',
                $show_debug // Nur true, wenn User es will
            );
            
            // NEU: SECURITY - Passwörter aus dem Log entfernen, bevor es in die Session kommt
            $cleanLog = $result['debug_log'];
            $cleanLog = preg_replace('/(PASS\s+)[^\s]+/', '$1 *****', $cleanLog);
            $cleanLog = preg_replace('/(auth\s+login\s+)[^\s]+/i', '$1 [HIDDEN]', $cleanLog);
            
            // Log speichern (nur wenn vorhanden)
            if (!empty($cleanLog)) {
                $_SESSION['flash_debug'] = $logHeader . $cleanLog;
            }
            
            if ($result['success']) {
                $_SESSION['flash_message'] = "Test email sent to $test_email";
            } else {
                $_SESSION['flash_error'] = "Test failed. See debug log.";
            }
        } else {
            $_SESSION['flash_error'] = "Invalid email address.";
        }
    }
    
    header("Location: admin_config.php");
    exit;
}

// ---------------------------------------------------------
// 3. HANDLE SAVE CONFIG (POST -> REDIRECT)
// ---------------------------------------------------------
elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_config'])) {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Security Error");
    }

    // Save Default Active
    $default_status = isset($_POST['default_user_active']) ? (int)$_POST['default_user_active'] : 1;
    $stmt = $db->prepare("INSERT OR REPLACE INTO system_settings (setting_key, setting_value) VALUES ('default_user_active', ?)");
    $stmt->bindValue(1, $default_status, SQLITE3_TEXT);
    $stmt->execute();

    // Save SMTP Settings
    $smtp_keys = ['smtp_host', 'smtp_port', 'smtp_auth', 'smtp_user', 'smtp_secure', 'smtp_from_email', 'smtp_from_name'];
    foreach ($smtp_keys as $key) {
        $val = trim($_POST[$key] ?? '');
        $stmt = $db->prepare("INSERT OR REPLACE INTO system_settings (setting_key, setting_value) VALUES (?, ?)");
        $stmt->bindValue(1, $key, SQLITE3_TEXT);
        $stmt->bindValue(2, $val, SQLITE3_TEXT);
        $stmt->execute();
    }
    // Save Password only if set (nicht leeres Feld überschreibt bestehendes PW nicht)
    if (!empty($_POST['smtp_pass'])) {
        $stmt = $db->prepare("INSERT OR REPLACE INTO system_settings (setting_key, setting_value) VALUES ('smtp_pass', ?)");
        $stmt->bindValue(1, $_POST['smtp_pass'], SQLITE3_TEXT);
        $stmt->execute();
    }

    $_SESSION['flash_message'] = "Configuration saved successfully.";
    header("Location: admin_config.php");
    exit;
}

// 4. Fetch Settings for View
$current_default_active = (int)getSetting($db, 'default_user_active', '1');
$smtp_host = getSetting($db, 'smtp_host', '');
$smtp_port = getSetting($db, 'smtp_port', '587');
$smtp_auth = getSetting($db, 'smtp_auth', '1');
$smtp_user = getSetting($db, 'smtp_user', '');
$smtp_secure = getSetting($db, 'smtp_secure', 'tls');
$smtp_from_email = getSetting($db, 'smtp_from_email', '');
$smtp_from_name = getSetting($db, 'smtp_from_name', 'Signature Admin');

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Configuration - SubSignature</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/all.min.css">
    <style>
        .config-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 1.5rem; }
        .config-card { background: white; border: 1px solid var(--border); border-radius: 12px; padding: 2rem; height: 100%; }
        .config-item { display: flex; justify-content: space-between; align-items: center; padding: 1rem 0; border-bottom: 1px solid var(--border); }
        .config-item:last-child { border-bottom: none; }
        .form-group-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem; }
        .form-label { display: block; font-size: 0.85rem; font-weight: 600; color: #64748b; margin-bottom: 0.4rem; }
        .form-input { width: 100%; padding: 0.6rem; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 0.95rem; }
        .switch { position: relative; display: inline-block; width: 40px; height: 22px; }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #cbd5e1; transition: .4s; border-radius: 34px; }
        .slider:before { position: absolute; content: ""; height: 16px; width: 16px; left: 3px; bottom: 3px; background-color: white; transition: .4s; border-radius: 50%; }
        input:checked + .slider { background-color: var(--primary); }
        input:checked + .slider:before { transform: translateX(18px); }
        
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: none; justify-content: center; align-items: center; z-index: 999; backdrop-filter: blur(2px); }
        .modal-box { background: white; padding: 2rem; border-radius: 12px; width: 90%; max-width: 450px; box-shadow: 0 20px 25px rgba(0,0,0,0.1); }
        
        .debug-console {
            background: #1e293b; color: #bef264; 
            padding: 1rem; border-radius: 8px; 
            margin-top: 1rem; margin-bottom: 1rem;
            font-family: monospace; font-size: 0.85rem;
            max-height: 300px; overflow-y: auto;
            white-space: pre-wrap; word-wrap: break-word;
            border: 1px solid #334155;
        }
    </style>
</head>
<body>

    <aside class="sidebar">
        <?php include 'includes/navbar.php'; ?>
        <div class="sidebar-footer">
            <div class="user-profile">
                <div class="avatar"><?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?></div>
                <div class="user-info">
                    <div><?php echo htmlspecialchars($_SESSION['username']); ?></div>
                    <span>Administrator</span>
                </div>
            </div>
            <a href="logout.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> <span>Sign Out</span></a>
        </div>
    </aside>

    <main class="main-content">
        <header class="page-header">
            <h2>System Configuration</h2>
            <p>Manage settings and integrations.</p>
        </header>

        <?php if (!empty($debug_log)): ?>
            <div class="alert alert-<?php echo $error ? 'error' : 'success'; ?>">
                <strong>SMTP Debug Log</strong>
                <div class="debug-console"><?php echo htmlspecialchars($debug_log); ?></div>
            </div>
        <?php endif; ?>

        <?php if ($message && empty($debug_log)): ?>
            <div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>
        <?php if ($error && empty($debug_log)): ?>
            <div class="alert alert-error"><i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <form method="POST" action="admin_config.php">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <input type="hidden" name="save_config" value="1">
            
            <div class="config-grid">
                
                <section class="config-card">
                    <h3 style="font-size:1.1rem; margin-bottom:1.5rem; border-bottom:1px solid var(--border); padding-bottom:1rem;">
                        <i class="fas fa-users-cog"></i> General Settings
                    </h3>
                    <div class="config-item">
                        <div>
                            <h4 style="margin:0; font-size:0.95rem;">Active by Default</h4>
                            <p style="margin:0; color:#64748b; font-size:0.8rem;">New users are active immediately.</p>
                        </div>
                        <label class="switch">
                            <input type="hidden" name="default_user_active" value="0">
                            <input type="checkbox" name="default_user_active" value="1" <?php echo ($current_default_active == 1) ? 'checked' : ''; ?>>
                            <span class="slider"></span>
                        </label>
                    </div>
                </section>

                <section class="config-card">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 1.5rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem;">
                        <h3 style="font-size:1.1rem; margin:0;"><i class="fas fa-envelope"></i> SMTP Email Server</h3>
                        <button type="button" onclick="openTestModal()" class="btn btn-sm btn-secondary">
                            <i class="fas fa-paper-plane"></i> Test Email
                        </button>
                    </div>

                    <div class="form-group-grid">
                        <div>
                            <label class="form-label">SMTP Host</label>
                            <input type="text" name="smtp_host" class="form-input" placeholder="smtp.example.com" value="<?php echo htmlspecialchars($smtp_host); ?>">
                        </div>
                        <div>
                            <label class="form-label">SMTP Port</label>
                            <input type="number" name="smtp_port" class="form-input" placeholder="587" value="<?php echo htmlspecialchars($smtp_port); ?>">
                        </div>
                    </div>

                    <div class="config-item" style="margin-bottom:1rem; border-bottom:none; padding:0.5rem 0;">
                        <div>
                            <label class="form-label" style="margin:0;">SMTP Authentication</label>
                            <p style="margin:0; color:#64748b; font-size:0.75rem;">Enable if server requires login.</p>
                        </div>
                        <label class="switch">
                            <input type="hidden" name="smtp_auth" value="0">
                            <input type="checkbox" name="smtp_auth" value="1" <?php echo ($smtp_auth == 1) ? 'checked' : ''; ?> onchange="toggleAuthFields(this)">
                            <span class="slider"></span>
                        </label>
                    </div>

                    <div id="authFields" style="display: <?php echo ($smtp_auth == 1) ? 'block' : 'none'; ?>;">
                        <div class="form-group-grid">
                            <div>
                                <label class="form-label">Username</label>
                                <input type="text" name="smtp_user" class="form-input" value="<?php echo htmlspecialchars($smtp_user); ?>">
                            </div>
                            <div>
                                <label class="form-label">Password</label>
                                <input type="password" name="smtp_pass" class="form-input" placeholder="••••••••">
                            </div>
                        </div>
                    </div>

                    <div style="margin-bottom: 1rem;">
                         <label class="form-label">Encryption</label>
                         <select name="smtp_secure" class="form-input">
                            <option value="tls" <?php echo ($smtp_secure === 'tls') ? 'selected' : ''; ?>>TLS (Recommended)</option>
                            <option value="ssl" <?php echo ($smtp_secure === 'ssl') ? 'selected' : ''; ?>>SSL</option>
                            <option value="none" <?php echo ($smtp_secure === 'none') ? 'selected' : ''; ?>>None</option>
                        </select>
                    </div>

                    <hr style="border:0; border-top:1px solid #f1f5f9; margin: 1.5rem 0;">

                    <div class="form-group-grid">
                        <div>
                            <label class="form-label">Sender Email</label>
                            <input type="email" name="smtp_from_email" class="form-input" value="<?php echo htmlspecialchars($smtp_from_email); ?>">
                        </div>
                        <div>
                            <label class="form-label">Sender Name</label>
                            <input type="text" name="smtp_from_name" class="form-input" value="<?php echo htmlspecialchars($smtp_from_name); ?>">
                        </div>
                    </div>
                </section>
            </div>

            <div class="form-actions" style="margin-top: 2rem; display: flex; justify-content: flex-end;">
                <button type="submit" class="btn btn-primary" style="padding: 0.8rem 2rem;">
                    <i class="fas fa-save"></i> Save Configuration
                </button>
            </div>
        </form>

    </main>

    <div id="testEmailModal" class="modal-overlay">
        <div class="modal-box">
            <h3 style="margin-top:0;"><i class="fas fa-vial"></i> Send Test Email</h3>
            <p style="color:#64748b; font-size:0.9rem;">Check your configuration.</p>
            
            <form method="POST" action="admin_config.php">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <input type="hidden" name="action" value="test_email">
                
                <div style="margin: 1.5rem 0;">
                    <label class="form-label">Recipient</label>
                    <input type="email" name="test_recipient" required class="form-input" placeholder="your@email.com">
                </div>

                <div style="margin-bottom: 1.5rem;">
                    <label style="display:flex; align-items:center; gap:0.5rem; font-size:0.9rem; cursor:pointer;">
                        <input type="checkbox" name="show_debug_log" value="1">
                        <span>Show detailed SMTP connection log</span>
                    </label>
                    <p style="font-size:0.75rem; color:#94a3b8; margin:0.2rem 0 0 1.4rem;">Only use if connection fails. May contain technical details.</p>
                </div>
                
                <div style="display:flex; justify-content:flex-end; gap:0.5rem;">
                    <button type="button" onclick="closeTestModal()" class="btn btn-secondary">Cancel</button>
                    <button type="submit" class="btn btn-primary">Send Test</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        function openTestModal() { document.getElementById('testEmailModal').style.display = 'flex'; }
        function closeTestModal() { document.getElementById('testEmailModal').style.display = 'none'; }
        function toggleAuthFields(cb) { document.getElementById('authFields').style.display = cb.checked ? 'block' : 'none'; }
        window.onclick = function(e) { if(e.target == document.getElementById('testEmailModal')) closeTestModal(); }
    </script>
</body>
</html>
