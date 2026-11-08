<?php
// admin_config.php - system settings: registration, default account status, SMTP.

require_once 'includes/config.php';
requireAdmin();

// 1. Messages (flash data survives exactly one redirect)
$message = popFlash('success');
$error = popFlash('error');
$debug_log = popFlash('debug');

// ---------------------------------------------------------
// 2. HANDLE TEST EMAIL (POST -> REDIRECT)
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'test_email') {
    requireCsrf();
    require_once 'includes/MailHelper.php';

    $test_email = cleanText($_POST['test_recipient'] ?? '', 254);
    // SMTP debug output is only collected when the checkbox is ticked.
    $show_debug = ($_POST['show_debug_log'] ?? '') === '1';

    if (filter_var($test_email, FILTER_VALIDATE_EMAIL)) {
        $logHeader = '--- SMTP TEST STARTED AT ' . date('H:i:s') . " ---\n";

        $result = MailHelper::send(
            $test_email,
            'SMTP Test - SubSignature',
            '<h3>SMTP Test Successful ✅</h3><p>Your configuration works.</p>',
            'SMTP Test Successful',
            $show_debug
        );

        // Remove credentials from the log before it is stored in the session.
        $cleanLog = (string)$result['debug_log'];
        $cleanLog = preg_replace('/(PASS\s+)[^\s]+/', '$1 *****', $cleanLog);
        $cleanLog = preg_replace('/(auth\s+login\s+)[^\s]+/i', '$1 [HIDDEN]', $cleanLog);
        if ($cleanLog !== '') {
            setFlash('debug', $logHeader . $cleanLog);
        }

        if ($result['success']) {
            setFlash('success', 'Test email sent to ' . $test_email);
        } else {
            setFlash('error', 'Test failed. See debug log.');
        }
    } else {
        setFlash('error', 'Invalid email address.');
    }

    header('Location: admin_config.php');
    exit;
}

// ---------------------------------------------------------
// 3. HANDLE SAVE CONFIG (POST -> REDIRECT)
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_config'])) {
    requireCsrf();

    $problems = [];

    // General settings (booleans are normalised to '0' / '1')
    setSetting($db, 'default_user_active', ($_POST['default_user_active'] ?? '1') === '1' ? '1' : '0');
    setSetting($db, 'allow_registration', ($_POST['allow_registration'] ?? '1') === '1' ? '1' : '0');

    // SMTP settings with validation
    $smtp_host = cleanText($_POST['smtp_host'] ?? '', 255);
    if ($smtp_host !== '' && !preg_match('/^[A-Za-z0-9.\-]+$|^\[[0-9A-Fa-f:.]+\]$/', $smtp_host)) {
        $problems[] = 'Invalid SMTP host name.';
        $smtp_host = '';
    }
    $smtp_port = (int)($_POST['smtp_port'] ?? 587);
    if ($smtp_port < 1 || $smtp_port > 65535) {
        $problems[] = 'SMTP port must be between 1 and 65535.';
        $smtp_port = 587;
    }
    $smtp_secure = $_POST['smtp_secure'] ?? 'tls';
    if (!in_array($smtp_secure, ['tls', 'ssl', 'none'], true)) {
        $smtp_secure = 'tls';
    }
    $smtp_from_email = cleanText($_POST['smtp_from_email'] ?? '', 254);
    if ($smtp_from_email !== '' && !filter_var($smtp_from_email, FILTER_VALIDATE_EMAIL)) {
        $problems[] = 'Invalid sender email address.';
        $smtp_from_email = '';
    }

    setSetting($db, 'smtp_host', $smtp_host);
    setSetting($db, 'smtp_port', (string)$smtp_port);
    setSetting($db, 'smtp_auth', ($_POST['smtp_auth'] ?? '') === '1' ? '1' : '0');
    setSetting($db, 'smtp_user', cleanText($_POST['smtp_user'] ?? '', 255));
    setSetting($db, 'smtp_secure', $smtp_secure);
    setSetting($db, 'smtp_from_email', $smtp_from_email);
    setSetting($db, 'smtp_from_name', cleanText($_POST['smtp_from_name'] ?? '', 100));

    // The password is only replaced when a new one was entered, and it is stored encrypted.
    if (is_string($_POST['smtp_pass'] ?? null) && $_POST['smtp_pass'] !== '') {
        setSetting($db, 'smtp_pass', encryptSecret($_POST['smtp_pass']));
    }

    logSecurityEventToDB($db, 'CONFIG_CHANGED', (int)$_SESSION['user_id'], 'System / SMTP settings saved');

    if ($problems) {
        setFlash('error', implode(' ', $problems) . ' Other settings were saved.');
    } else {
        setFlash('success', 'Configuration saved successfully.');
    }
    header('Location: admin_config.php');
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

$allow_registration = getSetting($db, 'allow_registration', '1') === '1';
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
                    <div><?php echo e($_SESSION['username']); ?></div>
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
                <div class="debug-console"><?php echo e($debug_log); ?></div>
            </div>
        <?php endif; ?>

        <?php if ($message && empty($debug_log)): ?>
            <div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo e($message); ?></div>
        <?php endif; ?>
        <?php if ($error && empty($debug_log)): ?>
            <div class="alert alert-error"><i class="fas fa-exclamation-circle"></i> <?php echo e($error); ?></div>
        <?php endif; ?>

        <form method="POST" action="admin_config.php">
            <?php echo csrfField(); ?>
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
                    <div class="config-item">
                        <div>
                            <h4 style="margin:0; font-size:0.95rem;">Allow Self-Registration</h4>
                            <p style="margin:0; color:#64748b; font-size:0.8rem;">Show the public registration page.</p>
                        </div>
                        <label class="switch">
                            <input type="hidden" name="allow_registration" value="0">
                            <input type="checkbox" name="allow_registration" value="1" <?php echo $allow_registration ? 'checked' : ''; ?>>
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
                            <input type="text" name="smtp_host" class="form-input" placeholder="smtp.example.com" value="<?php echo e($smtp_host); ?>">
                        </div>
                        <div>
                            <label class="form-label">SMTP Port</label>
                            <input type="number" name="smtp_port" class="form-input" placeholder="587" value="<?php echo e($smtp_port); ?>">
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
                                <input type="text" name="smtp_user" class="form-input" value="<?php echo e($smtp_user); ?>">
                            </div>
                            <div>
                                <label class="form-label">Password</label>
                                <input type="password" name="smtp_pass" class="form-input" autocomplete="new-password" placeholder="••••••••">
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
                            <input type="email" name="smtp_from_email" class="form-input" value="<?php echo e($smtp_from_email); ?>">
                        </div>
                        <div>
                            <label class="form-label">Sender Name</label>
                            <input type="text" name="smtp_from_name" class="form-input" value="<?php echo e($smtp_from_name); ?>">
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
                <?php echo csrfField(); ?>
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
