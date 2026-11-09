<?php
// change_password.php - lets a logged-in user change their own password.

require_once 'includes/config.php';
requireLogin();

$message = '';
$error = '';
$user_id = (int)$_SESSION['user_id'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    requireCsrf();

    // Passwords are not trimmed: spaces are valid characters.
    $current_password = is_string($_POST['current_password'] ?? null) ? $_POST['current_password'] : '';
    $new_password = is_string($_POST['new_password'] ?? null) ? $_POST['new_password'] : '';
    $confirm_password = is_string($_POST['confirm_password'] ?? null) ? $_POST['confirm_password'] : '';
    $policyErrors = validatePasswordPolicy($new_password);

    if (rateLimitIsBlocked('change_password', 5, 900, 'uid:' . $user_id)) {
        // Guessing the current password is throttled per account (not per session).
        $error = t('Too many attempts. Please try again in 15 minutes.');
    } elseif ($current_password === '' || $new_password === '' || $confirm_password === '') {
        $error = t('All fields are required!');
    } elseif ($new_password !== $confirm_password) {
        $error = t('New passwords do not match!');
    } elseif ($policyErrors) {
        $error = t('Password too weak: {details}.', ['details' => implode('; ', $policyErrors)]);
    } elseif ($new_password === $current_password) {
        $error = t('The new password must differ from the current one!');
    } else {
        $stmt = $db->prepare('SELECT id, password_hash FROM users WHERE id = ?');
        $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
        $user = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

        if ($user && password_verify($current_password, $user['password_hash'])) {
            $new_hash = password_hash($new_password, PASSWORD_DEFAULT);

            $update_stmt = $db->prepare('UPDATE users SET password_hash = ? WHERE id = ?');
            $update_stmt->bindValue(1, $new_hash, SQLITE3_TEXT);
            $update_stmt->bindValue(2, $user_id, SQLITE3_INTEGER);
            $update_stmt->execute();

            // Other sessions of this user become invalid (fingerprint changes);
            // this session stays valid with a fresh ID and the new fingerprint.
            session_regenerate_id(true);
            $_SESSION['pw_fp'] = passwordFingerprint($new_hash);
            rateLimitReset('change_password', 'uid:' . $user_id);
            logSecurityEventToDB($db, 'PASSWORD_CHANGED', $user_id, 'Self-service');
            $message = t('✅ Password successfully changed!');
        } else {
            rateLimitHit('change_password', 900, 'uid:' . $user_id);
            usleep(random_int(500000, 1000000));
            $error = t('❌ Current password is incorrect!');
        }
    }
}
?>
<!DOCTYPE html>
<html lang="<?= e(currentLang()) ?>" dir="<?= e(langDir()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= et('Change Password') ?> - SubSignature</title>
    
    <?= i18nHead() ?>
    
    <script src="<?= assetUrl('js/theme.js') ?>"></script>
    <link rel="stylesheet" href="<?= assetUrl('css/theme.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/style.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/all.min.css') ?>">    
    
    <style>
        /* Page styles (unchanged UI) */
        .password-strength-container {
            margin-top: 0.5rem;
            background: var(--bg-subtle);
            height: 4px;
            border-radius: 2px;
            overflow: hidden;
            display: flex;
        }
        
        .strength-bar {
            height: 100%;
            width: 0%;
            transition: width 0.3s ease, background-color 0.3s ease;
        }

        .strength-label {
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-top: 0.25rem;
            display: block;
            text-align: right;
        }

        .input-with-icon {
            position: relative;
        }
        .input-with-icon input {
            padding-right: 40px;
        }
        .toggle-password {
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
            cursor: pointer;
            z-index: 2;
        }
        .toggle-password:hover { color: var(--primary); }

        .security-tips {
            background: var(--success-bg);
            border: 1px solid var(--success-border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-top: 2rem;
        }
        .security-tips h4 {
            color: var(--success-text);
            margin-bottom: 0.75rem;
            font-size: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .security-tips ul {
            padding-left: 1.25rem;
            margin: 0;
            color: var(--success-text);
            font-size: 0.9rem;
        }
        .security-tips li { margin-bottom: 0.25rem; }

        @media (max-width: 768px) {
            .form-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>

    <aside class="sidebar">

        <?php 
        // Safe Include Check
        if (file_exists('includes/navbar.php')) {
            include 'includes/navbar.php';
        } else {
            // Fallback Menu
            echo '<nav class="nav-menu">
                    <span class="nav-label">Menu</span>
                    <a href="generator.php" class="nav-link"><i class="fas fa-home"></i> Home</a>
                    <a href="logout.php" class="nav-link"><i class="fas fa-sign-out-alt"></i> Logout</a>
                  </nav>';
        }
        ?>

        <div class="sidebar-footer">
        <?= langSwitcher() ?>
            <div class="user-profile">
                <div class="avatar">
                    <?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?>
                </div>
                <div class="user-info">
                    <div><?php echo e($_SESSION['username']); ?></div>
                    <span><?= isAdmin() ? et('Administrator') : et('User') ?></span>
                </div>
            </div>
            <a href="logout.php" class="btn-logout">
                <i class="fas fa-sign-out-alt"></i> <span><?= et('Sign Out') ?></span>
            </a>
        </div>
    </aside>

    <main class="main-content">
        
        <header class="page-header">
            <h2><?= et('Change Password') ?></h2>
            <p><?= et('Update your credentials to keep your account secure.') ?></p>
        </header>

        <?php if ($message): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i> <?php echo e($message); ?>
            </div>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="alert alert-error">
                <i class="fas fa-exclamation-circle"></i> <?php echo e($error); ?>
            </div>
        <?php endif; ?>

        <div class="form-grid" style="grid-template-columns: 2fr 1fr; gap: 2rem;">
            
            <section class="card">
                <div class="card-header">
                    <h3><i class="fas fa-lock"></i> <?= et('Security Credentials') ?></h3>
                </div>

                <form method="POST">
                    <?php echo csrfField(); ?>

                    <div class="form-group">
                        <label for="current_password"><?= et('Current Password') ?></label>
                        <input type="password" id="current_password" name="current_password" required>
                    </div>

                    <div style="margin: 1.5rem 0; border-bottom: 1px solid var(--border);"></div>

                    <div class="form-group">
                        <label for="new_password"><?= et('New Password') ?></label>
                        <div class="input-with-icon">
                            <input type="password" id="new_password" name="new_password" required 
                                   oninput="checkStrength(this.value)">
                            <i class="fas fa-eye toggle-password" onclick="togglePass('new_password')"></i>
                        </div>
                        
                        <div class="password-strength-container">
                            <div id="strengthBar" class="strength-bar"></div>
                        </div>
                        <span id="strengthText" class="strength-label"><?= et('Enter new password') ?></span>
                    </div>

                    <div class="form-group">
                        <label for="confirm_password"><?= et('Confirm New Password') ?></label>
                        <div class="input-with-icon">
                            <input type="password" id="confirm_password" name="confirm_password" required oninput="checkMatch()">
                             <i class="fas fa-eye toggle-password" onclick="togglePass('confirm_password')"></i>
                        </div>
                        <span id="matchText" class="strength-label" style="text-align:left;"></span>
                    </div>

                    <div class="form-actions">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save"></i> <?= et('Update Password') ?>
                        </button>
                        <a href="profile.php" class="btn btn-danger" style="background:var(--bg-white); color:var(--text-main); border:1px solid var(--border)">
                            <?= et('Cancel') ?>
                        </a>
                    </div>
                </form>
            </section>

            <div>
                <div class="security-tips">
                    <h4><i class="fas fa-shield-alt"></i> <?= et('Password Guidelines') ?></h4>
                    <ul>
                        <li><?= et('At least 8 characters long') ?></li>
                        <li><?= et('Include uppercase & lowercase letters') ?></li>
                        <li><?= et('Include at least one number') ?></li>
                        <li><?= et('Avoid using your name or email') ?></li>
                    </ul>
                </div>
                
                <div class="card" style="margin-top: 1.5rem; text-align: center; padding: 1.5rem;">
                    <i class="fas fa-key" style="font-size: 2.5rem; color: var(--border-strong); margin-bottom: 1rem;"></i>
                    <p style="color: var(--text-muted); font-size: 0.9rem;">
                        <?= et('Changing your password will not affect existing signatures, but you will need to use the new password for your next login.') ?>
                    </p>
                </div>
            </div>

        </div>
    </main>

    <script>
    // JS Logic remains the same
    function togglePass(id) {
        const input = document.getElementById(id);
        const type = input.type === 'password' ? 'text' : 'password';
        input.type = type;
    }

    function checkStrength(password) {
        const bar = document.getElementById('strengthBar');
        const text = document.getElementById('strengthText');
        
        let strength = 0;
        
        if (password.length >= 8) strength += 25;
        if (password.match(/[a-z]+/)) strength += 25;
        if (password.match(/[A-Z]+/)) strength += 25;
        if (password.match(/[0-9]+/)) strength += 25;

        bar.style.width = strength + '%';

        if (strength < 50) {
            bar.style.backgroundColor = '#ef4444';
            text.textContent = <?= tj('Weak') ?>;
            text.style.color = '#ef4444';
        } else if (strength < 75) {
            bar.style.backgroundColor = '#f59e0b';
            text.textContent = <?= tj('Medium') ?>;
            text.style.color = '#f59e0b';
        } else {
            bar.style.backgroundColor = '#10b981';
            text.textContent = <?= tj('Strong') ?>;
            text.style.color = '#10b981';
        }
    }

    function checkMatch() {
        const p1 = document.getElementById('new_password').value;
        const p2 = document.getElementById('confirm_password').value;
        const text = document.getElementById('matchText');

        if (p2.length === 0) {
            text.textContent = '';
            return;
        }

        if (p1 === p2) {
            text.textContent = '✓ ' + <?= tj('Passwords match') ?>;
            text.style.color = '#10b981';
        } else {
            text.textContent = <?= tj('Passwords do not match') ?>;
            text.style.color = '#ef4444';
        }
    }
    </script>
</body>
</html>
