<?php
/**
 * install.php - one-time installer that creates the first administrator.
 *
 * The installer locks itself as soon as an administrator exists. Run it right
 * after deployment (or restrict access to it until you have done so).
 */

$error = '';
$success = '';
$redirect_target = '';

// -----------------------------------------------------------
// 1. PRE-FLIGHT CHECKS (before the application core is loaded)
// -----------------------------------------------------------
$data_dir = getenv('SUBSIG_DATA_DIR') ?: (__DIR__ . '/../private_data');
$tpl_dir  = __DIR__ . '/templates';

function checkWritable($path)
{
    // Existing path: must be writable. Otherwise its parent must be (so it can be created).
    if (file_exists($path)) {
        return is_writable($path);
    }
    return is_writable(dirname($path));
}

$requirements = [
    'PHP Version >= 7.4'           => version_compare(PHP_VERSION, '7.4.0', '>='),
    'SQLite3 Extension'            => extension_loaded('sqlite3'),
    'MBString Extension'           => extension_loaded('mbstring'),
    'ZIP Extension'                => extension_loaded('zip'),
    'JSON Extension'               => extension_loaded('json'),
    'Data Directory Writable'      => checkWritable($data_dir),
    'Templates Directory Writable' => checkWritable($tpl_dir),
];
$allRequirementsMet = !in_array(false, $requirements, true);

// -----------------------------------------------------------
// 2. LOAD THE APPLICATION CORE
// -----------------------------------------------------------
$csrf_token = '';
if ($allRequirementsMet) {
    try {
        require_once 'includes/config.php';

        $adminCount = (int)$db->querySingle("SELECT COUNT(*) FROM users WHERE role = 'admin'");
        if ($adminCount > 0) {
            http_response_code(403);
            die('<div style="font-family:sans-serif; text-align:center; padding:50px;"><h1>System already installed</h1><p>An administrator account exists. Delete the database file in private_data if you really want to reinstall.</p><p><a href="index.php">Go to Login</a></p></div>');
        }
        $csrf_token = generateCSRFToken();
    } catch (Exception $e) {
        error_log('Installer error: ' . $e->getMessage());
        $error = 'Critical database error. Check the PHP error log.';
        $allRequirementsMet = false;
    }
}

// -----------------------------------------------------------
// 3. INSTALLATION PROCESS
// -----------------------------------------------------------
if ($allRequirementsMet && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = 'Security violation: invalid CSRF token. Please reload the page.';
    } else {
        $username = cleanText($_POST['username'] ?? '', 64);
        $password = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
        $confirm  = is_string($_POST['confirm_password'] ?? null) ? $_POST['confirm_password'] : '';
        $email    = cleanText($_POST['email'] ?? '', 254);
        $policyErrors = validatePasswordPolicy($password);

        if ($username === '' || $password === '' || $confirm === '') {
            $error = 'All fields are required.';
        } elseif (!isValidUsername($username)) {
            $error = 'Username must be 3-64 characters (letters, numbers, . _ - @ only).';
        } elseif ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Invalid email address format.';
        } elseif ($password !== $confirm) {
            $error = 'Passwords do not match.';
        } elseif ($policyErrors) {
            $error = implode("\n", $policyErrors);
        } else {
            try {
                $db->exec('BEGIN IMMEDIATE');
                // Re-check inside the transaction: two simultaneous installs must not both succeed.
                if ((int)$db->querySingle("SELECT COUNT(*) FROM users WHERE role = 'admin'") > 0) {
                    $db->exec('ROLLBACK');
                    $error = 'System already installed.';
                } else {
                    $stmt = $db->prepare("INSERT INTO users (username, password_hash, email, full_name, role, is_active)
                                          VALUES (?, ?, ?, 'System Administrator', 'admin', 1)");
                    $stmt->bindValue(1, $username, SQLITE3_TEXT);
                    $stmt->bindValue(2, password_hash($password, PASSWORD_DEFAULT), SQLITE3_TEXT);
                    $stmt->bindValue(3, $email, SQLITE3_TEXT);
                    $stmt->execute();
                    $user_id = (int)$db->lastInsertRowID();

                    $stmt = $db->prepare('INSERT INTO user_settings (user_id) VALUES (?)');
                    $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
                    $stmt->execute();
                    $db->exec('COMMIT');

                    logSecurityEventToDB($db, 'INSTALLATION_SUCCESS', $user_id, 'Admin created: ' . $username);

                    // Sign the new administrator in.
                    $stmt = $db->prepare('SELECT * FROM users WHERE id = ?');
                    $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
                    startUserSession($stmt->execute()->fetchArray(SQLITE3_ASSOC));

                    $success = 'Installation successful!';
                    $redirect_target = 'generator.php';
                }
            } catch (Exception $e) {
                @$db->exec('ROLLBACK');
                error_log('Installer error: ' . $e->getMessage());
                $error = 'System error. Check the PHP error log.';
            }
        }
    }
    $csrf_token = generateCSRFToken();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Installation - SubSignature</title>
    
    <?php if ($success): ?>
        <meta http-equiv="refresh" content="3;url=<?php echo $redirect_target; ?>">
    <?php endif; ?>

    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #e4edf5 100%);
            min-height: 100vh;
            display: flex; align-items: center; justify-content: center; padding: 20px;
        }
        .install-box {
            background: white; border-radius: 16px; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.08);
            width: 100%; max-width: 500px; padding: 40px; border: 1px solid #eaeaea;
        }
        .header { text-align: center; margin-bottom: 30px; }
        .title { font-size: 1.8rem; font-weight: 700; color: #2c3e50; margin-top: 10px; }
        .subtitle { color: #718096; margin-top: 5px; }
        
        .section { margin-bottom: 25px; border-bottom: 1px solid #eee; padding-bottom: 20px; }
        .section-title { font-weight: 600; color: #2d3748; margin-bottom: 15px; display: flex; align-items: center; gap: 8px; }
        
        /* SVG Icons Style */
        .icon { width: 1.2em; height: 1.2em; fill: currentColor; display: inline-block; vertical-align: text-bottom; }
        .text-green { color: #10b981; }
        .text-red { color: #ef4444; }
        
        .req-list { list-style: none; }
        .req-item { display: flex; justify-content: space-between; padding: 8px 0; font-size: 0.9rem; border-bottom: 1px dashed #f0f0f0; }
        .req-item:last-child { border-bottom: none; }
        .status { font-weight: 600; display:flex; align-items:center; gap:5px; }
        .status.ok { color: #10b981; }
        .status.fail { color: #ef4444; }
        
        .input-group { margin-bottom: 15px; }
        .label { display: block; margin-bottom: 6px; font-weight: 500; font-size: 0.9rem; color: #4a5568; }
        .input { width: 100%; padding: 10px; border: 2px solid #e2e8f0; border-radius: 8px; transition: 0.2s; }
        .input:focus { border-color: #4a6cf7; outline: none; }
        
        .btn { width: 100%; padding: 12px; background: #4a6cf7; color: white; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; transition: 0.2s; font-size: 1rem; display:flex; align-items:center; justify-content:center; gap:8px;}
        .btn:hover:not(:disabled) { background: #3b5bdb; transform: translateY(-1px); }
        .btn:disabled { background: #cbd5e1; cursor: not-allowed; }
        
        .alert { padding: 12px; border-radius: 8px; margin-bottom: 20px; font-size: 0.9rem; }
        .alert-error { background: #fef2f2; color: #991b1b; border: 1px solid #fecaca; }
        
        /* Success Animation Styles */
        .success-container { text-align: center; padding: 20px 0; }
        .success-icon-wrap { width: 80px; height: 80px; margin: 0 auto 20px; color: #10b981; animation: popIn 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275); }
        .success-title { font-size: 1.5rem; color: #1e293b; margin-bottom: 10px; font-weight: 700; }
        .success-text { color: #64748b; margin-bottom: 20px; }
        .progress-bar { width: 100%; height: 4px; background: #e2e8f0; border-radius: 2px; overflow: hidden; margin-top: 20px; }
        .progress-fill { height: 100%; background: #10b981; width: 0%; transition: width 3s linear; }
        
        @keyframes popIn { 0% { transform: scale(0); opacity: 0; } 100% { transform: scale(1); opacity: 1; } }
        
        .hint { font-size: 0.8rem; color: #64748b; margin-top: 5px; }
    </style>
</head>
<body>

<div class="install-box">
    
    <?php if ($success): ?>
        <div class="success-container">
            <div class="success-icon-wrap">
                <svg viewBox="0 0 24 24" fill="currentColor" style="width:100%;height:100%"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
            </div>
            <div class="success-title">Success!</div>
            <div class="success-text">
                System installed successfully.<br>
                Redirecting to Dashboard...
            </div>
            
            <div class="progress-bar">
                <div class="progress-fill" id="progBar"></div>
            </div>
        </div>
        
        <script>
            document.addEventListener("DOMContentLoaded", function() {
                setTimeout(function() { document.getElementById('progBar').style.width = '100%'; }, 100);
                setTimeout(function() { window.location.href = "<?php echo $redirect_target; ?>"; }, 3000);
            });
        </script>

    <?php else: ?>
        <div class="header">
            <img src="img/subsig.svg" alt="SubSignature Logo" style="height: 120px; width: auto; object-fit: contain;">
            <div class="title">System Installation</div>
            <div class="subtitle">Setup your Admin Account</div>
        </div>

        <div class="section">
            <div class="section-title">
                <svg class="icon" viewBox="0 0 24 24"><path d="M2 20h20v-4H2v4zm2-3h2v2H4v-2zM2 4v4h20V4H2zm4 3H4V5h2v2zm-4 7h20v-4H2v4zm2-3h2v2H4v-2z"/></svg>
                System Check
            </div>
            <ul class="req-list">
                <?php foreach ($requirements as $label => $met): ?>
                <li class="req-item">
                    <span><?php echo e($label); ?></span>
                    <span class="status <?php echo $met ? 'ok' : 'fail'; ?>">
                        <?php if ($met): ?>
                            <svg class="icon" viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg> OK
                        <?php else: ?>
                            <svg class="icon" viewBox="0 0 24 24"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg> FAIL
                        <?php endif; ?>
                    </span>
                </li>
                <?php endforeach; ?>
            </ul>
        </div>

        <?php if ($allRequirementsMet): ?>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo e($csrf_token); ?>">
                
                <div class="section">
                    <div class="section-title">
                        <svg class="icon" viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
                        Create Administrator
                    </div>
                    
                    <?php if ($error): ?>
                        <div class="alert alert-error">
                            <svg class="icon" viewBox="0 0 24 24" style="margin-right:5px"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>
                            <?php echo nl2br(e($error)); ?>
                        </div>
                    <?php endif; ?>

                    <div class="input-group">
                        <label class="label">Username</label>
                        <input type="text" name="username" class="input" required placeholder="admin" value="<?php echo isset($_POST['username']) && is_string($_POST['username']) ? e($_POST['username']) : ''; ?>">
                    </div>
                    
                    <div class="input-group">
                        <label class="label">Email Address</label>
                        <input type="email" name="email" class="input" placeholder="admin@example.com" value="<?php echo isset($_POST['email']) && is_string($_POST['email']) ? e($_POST['email']) : ''; ?>">
                    </div>

                    <div class="input-group">
                        <label class="label">Password</label>
                        <input type="password" name="password" class="input" required placeholder="Strong password">
                        <div class="hint">Min. 8 chars, 1 uppercase, 1 lowercase, 1 number</div>
                    </div>

                    <div class="input-group">
                        <label class="label">Confirm Password</label>
                        <input type="password" name="confirm_password" class="input" required placeholder="Repeat password">
                    </div>

                    <button type="submit" class="btn">
                        <svg class="icon" viewBox="0 0 24 24"><path d="M2.81 14.12L5.64 14l.79-.79c.26-.26.26-.67 0-.93A5.006 5.006 0 0 1 5.92 7L13 14a5.006 5.006 0 0 1-5.28.51c-.26-.26-.67-.26-.93 0l-.79.79-.12 2.83 2.83-.12.79-.79c.26-.26.67-.26.93 0 .42.42 1.34.42 1.76 0 .42-.42.42-1.34 0-1.76l6.36-6.36c3.9-3.9 3.9-10.23 0-14.13L15 4.93V2h-3v4.93l-3.93 3.93-1.42-1.42c-.26-.26-.67-.26-.93 0L2.94 11.3c-.39.39-.39 1.02 0 1.41l.79.79-.92 2.62zM15 9l5-5"/></svg>
                        Install & Create Admin
                    </button>
                </div>
            </form>
        <?php else: ?>
            <div class="alert alert-error">
                <strong>Installation Blocked:</strong><br>
                Please resolve the system requirements marked as FAIL above before proceeding.
            </div>
            <button class="btn" onclick="location.reload()">Check Again</button>
        <?php endif; ?>
    <?php endif; ?>
</div>

</body>
</html>
