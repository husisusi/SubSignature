<?php
/**
 * index.php - login page and login handler.
 */
require_once 'includes/config.php';

if (isLoggedIn()) {
    header('Location: generator.php');
    exit;
}

$error = '';
$notice = '';
$csrf_token = generateCSRFToken();

if (isset($_GET['timeout'])) {
    $notice = t('Your session has expired. Please sign in again.');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = cleanText($_POST['username'] ?? '', 64);
    $password = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';

    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = t('Security violation: invalid session. Please reload the page.');
        logSecurityEventToDB($db, 'CSRF_FAILED', null, 'Login form');
    } elseif (rateLimitIsBlocked('login_ip', 10, 300)) {
        // Per-IP throttle (counts failed attempts only).
        $error = t('Too many login attempts. Please try again in 5 minutes.');
        logSecurityEventToDB($db, 'RATE_LIMIT_EXCEEDED', null, 'Action: login_ip');
    } elseif (isAccountLocked($db, $username)) {
        // Per-username throttle; applies to unknown names too, so it does not
        // reveal which accounts exist.
        $error = t('Too many failed attempts for this account. Try again in 15 minutes.');
        logSecurityEventToDB($db, 'ACCOUNT_LOCKED', null, 'User: ' . $username);
    } else {
        $stmt = $db->prepare('SELECT id, username, password_hash, role, full_name, email, is_active FROM users WHERE username = ?');
        $stmt->bindValue(1, $username, SQLITE3_TEXT);
        $user = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

        // Always run one password_verify() so the response time is the same
        // for unknown and known accounts.
        $hash = $user ? $user['password_hash'] : DUMMY_PASSWORD_HASH;
        $passwordOk = password_verify($password, $hash) && $user;

        if ($passwordOk && (int)$user['is_active'] === 1) {
            if (password_needs_rehash($user['password_hash'], PASSWORD_DEFAULT)) {
                $re = $db->prepare('UPDATE users SET password_hash = ? WHERE id = ?');
                $re->bindValue(1, password_hash($password, PASSWORD_DEFAULT), SQLITE3_TEXT);
                $re->bindValue(2, (int)$user['id'], SQLITE3_INTEGER);
                $re->execute();
                $user['password_hash'] = password_hash($password, PASSWORD_DEFAULT);
                // re-read the stored hash so the session fingerprint matches
                $rs = $db->prepare('SELECT password_hash FROM users WHERE id = ?');
                $rs->bindValue(1, (int)$user['id'], SQLITE3_INTEGER);
                $user['password_hash'] = $rs->execute()->fetchArray(SQLITE3_ASSOC)['password_hash'];
            }
            startUserSession($user);
            rateLimitReset('login_user', mb_strtolower($username, 'UTF-8'));
            logLoginAttempt($db, $username, true);
            if (random_int(1, 100) === 1) {
                pruneOldLogs($db);
            }
            header('Location: generator.php');
            exit;
        }

        if ($passwordOk) {
            // Correct password but deactivated account: only now it is safe
            // to tell the user (the caller proved they know the password).
            $error = t('Your account is deactivated. Please contact the administrator.');
        } else {
            usleep(random_int(100000, 300000));
            $error = t('Invalid username or password!');
        }
        rateLimitHit('login_ip', 300);
        rateLimitHit('login_user', 900, mb_strtolower($username, 'UTF-8'));
        logLoginAttempt($db, $username, false);
    }

    if ($error !== '') {
        $_SESSION['failed_logins'] = ($_SESSION['failed_logins'] ?? 0) + 1;
    }
}
?>
<!DOCTYPE html>
<html lang="<?= e(currentLang()) ?>" dir="<?= e(langDir()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= et('Login') ?> - SubSignature</title>
    <?= i18nHead() ?>
    <script src="<?= assetUrl('js/theme.js') ?>"></script>
    <link rel="stylesheet" href="<?= assetUrl('css/theme.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/all.min.css') ?>">
    <style>
        /* Page styles (unchanged UI) */
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, var(--bg-body) 0%, var(--border) 100%);
            min-height: 100vh;
            display: flex; align-items: center; justify-content: center; padding: 20px;
        }
        .login-box {
            background: var(--bg-white); border-radius: 16px; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.08);
            width: 100%; max-width: 400px; padding: 40px; text-align: center; border: 1px solid var(--border);
        }
        .logo { font-size: 2.8rem; color: #4a6cf7; margin-bottom: 10px; }
        .logo-text { font-size: 1.8rem; font-weight: 700; color: var(--text-main); margin-bottom: 5px; letter-spacing: -0.5px; }
        .tagline { color: var(--text-muted); font-size: 0.95rem; margin-bottom: 30px; font-weight: 500; }
        .error-alert {
            background: var(--danger-bg); color: var(--danger-text); padding: 12px 16px; border-radius: 10px;
            border-left: 4px solid #f56565; margin-bottom: 25px; font-size: 0.9rem;
            display: flex; align-items: center; justify-content: center; gap: 8px; text-align: left; animation: shake 0.5s;
        }
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            10%, 30%, 50%, 70%, 90% { transform: translateX(-5px); }
            20%, 40%, 60%, 80% { transform: translateX(5px); }
        }
        .success-alert {
            background: var(--success-bg); color: var(--success-text); padding: 12px 16px; border-radius: 10px;
            border-left: 4px solid #48bb78; margin-bottom: 25px; font-size: 0.9rem;
            display: flex; align-items: center; justify-content: center; gap: 8px; text-align: left;
        }
        .input-group { margin-bottom: 20px; text-align: left; }
        .input-label { display: block; color: var(--text-muted); font-size: 0.9rem; font-weight: 600; margin-bottom: 8px; display: flex; align-items: center; gap: 6px; }
        .input-field {
            width: 100%; padding: 14px 16px; border: 2px solid var(--border); border-radius: 10px;
            font-size: 1rem; transition: all 0.2s; background: var(--bg-subtle);
        }
        .input-field:focus { outline: none; border-color: #4a6cf7; background: var(--bg-white); box-shadow: 0 0 0 3px rgba(74, 108, 247, 0.1); }
        .input-field.error { border-color: #f44336; background: var(--danger-bg); }
        .password-wrapper { position: relative; }
        .toggle-password {
            position: absolute; right: 12px; top: 50%; transform: translateY(-50%);
            background: none; border: none; color: var(--text-faint); cursor: pointer; padding: 5px;
        }
        .login-btn {
            width: 100%; background: linear-gradient(135deg, #4a6cf7 0%, #3a0ca3 100%);
            color: white; border: none; padding: 15px; border-radius: 10px; font-size: 1rem;
            font-weight: 600; cursor: pointer; transition: all 0.2s; margin-top: 10px;
            display: flex; align-items: center; justify-content: center; gap: 8px;
        }
        .login-btn:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 5px 15px rgba(74, 108, 247, 0.3); }
        .login-btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .register-link { margin-top: 20px; font-size: 0.9rem; color: var(--text-muted); }
        .register-link a { color: #4a6cf7; text-decoration: none; font-weight: 600; }
        .register-link a:hover { text-decoration: underline; }
        .failed-attempts {
            margin-top: 10px; font-size: 0.8rem; color: var(--danger-text); background: var(--danger-bg);
            padding: 8px 12px; border-radius: 6px; border-left: 3px solid #f44336; display: none;
        }
        @media (max-width: 480px) { .login-box { padding: 30px 25px; } .logo { font-size: 2.4rem; } .logo-text { font-size: 1.6rem; } }
    </style>
</head>
<body>
    <?= langSwitcher(true) ?>
    <div class="login-box">
        <img src="img/subsig.svg" alt="SubSignature Logo" style="height: 100px; width: auto; object-fit: contain;">
        <div class="logo-text">SubSignature</div>
        <div class="tagline"><?= et('Professional Email Signatures') ?></div>
        
        <?php if (isset($_GET['error']) && $_GET['error'] === 'deactivated'): ?>
            <div class="error-alert">
                <i class="fas fa-ban"></i>
                <div><strong><?= et('Account Deactivated') ?></strong><br><?= et('Contact administrator.') ?></div>
            </div>
        <?php endif; ?>
        
        <?php if (isset($_GET['success']) && $_GET['success'] == 'registered'): ?>
            <div class="success-alert">
                <i class="fas fa-check-circle"></i>
                <div><strong><?= et('Registration Successful!') ?></strong><br><?= et('Wait for activation.') ?></div>
            </div>
        <?php endif; ?>
        
        <?php if (isset($_GET['msg']) && $_GET['msg'] == 'loggedout'): ?>
            <div class="success-alert">
                <i class="fas fa-sign-out-alt"></i>
                <div><strong><?= et('Logged Out') ?></strong><br><?= et('See you soon.') ?></div>
            </div>
        <?php endif; ?>
        
        <?php if (isset($_SESSION['failed_logins']) && $_SESSION['failed_logins'] > 0): ?>
            <div class="failed-attempts" id="failedAttempts">
                <i class="fas fa-exclamation-triangle"></i>
                <?= et('Failed attempts: {count}', ['count' => (int)$_SESSION['failed_logins']]) ?>
            </div>
        <?php endif; ?>
        
        <?php if ($notice !== ''): ?>
            <div class="success-alert">
                <i class="fas fa-clock"></i>
                <div><?php echo e($notice); ?></div>
            </div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="error-alert">
                <i class="fas fa-exclamation-circle"></i>
                <div><?php echo e($error); ?></div>
            </div>
        <?php endif; ?>
        
        <form method="POST" id="loginForm" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?php echo e($csrf_token); ?>">
            
            <div class="input-group">
                <label class="input-label"><i class="fas fa-user"></i> <?= et('Username') ?></label>
                <input type="text" name="username" class="input-field" placeholder="<?= et('Enter username') ?>" 
                       required autofocus autocomplete="username"
                       value="<?php echo isset($_POST['username']) && is_string($_POST['username']) ? e($_POST['username']) : ''; ?>"
                       id="usernameInput">
            </div>
            
            <div class="input-group">
                <label class="input-label"><i class="fas fa-lock"></i> <?= et('Password') ?></label>
                <div class="password-wrapper">
                    <input type="password" name="password" id="password" class="input-field" 
                           placeholder="<?= et('Enter password') ?>" required autocomplete="current-password">
                    <button type="button" class="toggle-password" onclick="togglePassword()">
                        <i class="fas fa-eye"></i>
                    </button>
                </div>
            </div>
            
            <button type="submit" class="login-btn" id="loginBtn">
                <i class="fas fa-sign-in-alt"></i> <?= et('Sign In') ?>
            </button>
        </form>
        
        <div class="register-link">
            <?= eth('New user? {link}', ['link' => '<a href="register.php">' . et('Create account') . '</a>']) ?>
        </div>
        
    </div>
    
    <script>
    function togglePassword() {
        const password = document.getElementById('password');
        const icon = document.querySelector('.toggle-password i');
        if (password.type === 'password') {
            password.type = 'text';
            icon.className = 'fas fa-eye-slash';
        } else {
            password.type = 'password';
            icon.className = 'fas fa-eye';
        }
    }
    
    document.getElementById('loginForm').addEventListener('submit', function(e) {
        const btn = document.getElementById('loginBtn');
        const username = document.getElementById('usernameInput').value;
        const password = document.getElementById('password').value;
        
        if (!username.trim() || !password.trim()) {
            e.preventDefault();
            if(!username.trim()) document.getElementById('usernameInput').classList.add('error');
            if(!password.trim()) document.getElementById('password').classList.add('error');
            return false;
        }
        
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ' + <?= tj('Signing in...') ?>;
        btn.disabled = true;
        // Re-enable button after 5 seconds to prevent spam if server is slow
        setTimeout(() => {
            btn.innerHTML = '<i class="fas fa-sign-in-alt"></i> ' + <?= tj('Sign In') ?>;
            btn.disabled = false;
        }, 5000);
        return true;
    });
    
    document.getElementById('usernameInput')?.addEventListener('input', function() { this.classList.remove('error'); });
    document.getElementById('password')?.addEventListener('input', function() { this.classList.remove('error'); });
    
    document.addEventListener('DOMContentLoaded', function() {
        const usernameInput = document.getElementById('usernameInput');
        if (usernameInput) usernameInput.focus();
        
        const failedAttempts = document.getElementById('failedAttempts');
        if (failedAttempts) failedAttempts.style.display = 'block';
        
        // Simple animation for elements
        const elements = document.querySelectorAll('.input-group, .login-btn, .register-link, .features');
        elements.forEach((el, i) => {
            el.style.opacity = '0';
            el.style.transform = 'translateY(10px)';
            setTimeout(() => {
                el.style.transition = 'opacity 0.3s, transform 0.3s';
                el.style.opacity = '1';
                el.style.transform = 'translateY(0)';
            }, i * 100);
        });
        
        // Prevent double submission
        let lastSubmitTime = 0;
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            const now = Date.now();
            if (now - lastSubmitTime < 1000) {
                e.preventDefault();
                return false;
            }
            lastSubmitTime = now;
        });
    });
    
    // Auto-hide failed attempts message after 5 seconds
    setTimeout(() => {
        const failedAttempts = document.getElementById('failedAttempts');
        if (failedAttempts) {
            failedAttempts.style.transition = 'opacity 0.5s';
            failedAttempts.style.opacity = '0';
            setTimeout(() => { failedAttempts.style.display = 'none'; }, 500);
        }
    }, 5000);
    </script>
</body>
</html>
