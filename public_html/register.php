<?php
/**
 * register.php - self registration and admin-side user creation.
 */
require_once 'includes/config.php';

// Admin creation mode requires a verified admin session (role re-read from DB).
$admin_create = false;
if (isLoggedIn() && isset($_GET['admin']) && $_GET['admin'] === '1') {
    requireAdmin();
    $admin_create = true;
} elseif (isLoggedIn()) {
    header('Location: generator.php');
    exit;
}

// Public registration can be switched off in the admin configuration.
if (!$admin_create && getSetting($db, 'allow_registration', '1') !== '1') {
    header('Location: index.php');
    exit;
}

// Default status for new accounts (configurable): 1 = active, 0 = needs approval.
$config_default_active = getSetting($db, 'default_user_active', '1') === '1' ? 1 : 0;

$error = '';
$success = '';
$username = '';
$email = '';
$full_name = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    requireCsrf();

    // Throttle only real submissions (a plain page view must not count).
    if (!$admin_create && !checkRateLimit('registration', 5, 900)) {
        http_response_code(429);
        die('Too many registration attempts. Please try again later.');
    }

    $username         = cleanText($_POST['username'] ?? '', 64);
    $password         = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
    $confirm_password = is_string($_POST['confirm_password'] ?? null) ? $_POST['confirm_password'] : '';
    $email            = cleanText($_POST['email'] ?? '', 254);
    $full_name        = cleanText($_POST['full_name'] ?? '', 100);

    $policyErrors = validatePasswordPolicy($password);

    if ($username === '' || $password === '' || $confirm_password === '') {
        $error = t('All mandatory fields are required.');
    } elseif (!isValidUsername($username)) {
        $error = t('Username must be 3-64 characters (letters, numbers, . _ - @ only).');
    } elseif ($password !== $confirm_password) {
        $error = t('Passwords do not match.');
    } elseif ($policyErrors) {
        $error = t('Password too weak: {details}.', ['details' => implode('; ', $policyErrors)]);
    } elseif ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = t('Invalid email address format.');
    } elseif ($admin_create && isset($_POST['new_role']) && !isValidRole($_POST['new_role'])) {
        $error = t('Invalid role.');
    }

    if ($error === '') {
        try {
            $stmt = $db->prepare("SELECT COUNT(*) FROM users WHERE username = ? OR (email = ? AND email != '')");
            $stmt->bindValue(1, $username, SQLITE3_TEXT);
            $stmt->bindValue(2, $email, SQLITE3_TEXT);
            $exists = (int)$stmt->execute()->fetchArray(SQLITE3_NUM)[0];

            if ($exists > 0) {
                usleep(random_int(100000, 300000));
                $error = t('Username or Email already exists.');
            } else {
                // Public registrations always follow the system setting; the
                // status field is only honoured for admins.
                $is_active = $config_default_active;
                if ($admin_create && isset($_POST['user_status'])) {
                    $is_active = $_POST['user_status'] === '1' ? 1 : 0;
                }

                // The role can only be chosen by an administrator (whitelist). Public
                // self-registration always creates a normal user, whatever is posted.
                $new_role = ($admin_create && isset($_POST['new_role'])) ? $_POST['new_role'] : ROLE_USER;

                $db->exec('BEGIN IMMEDIATE');
                try {
                    $stmt = $db->prepare("INSERT INTO users (username, password_hash, email, full_name, role, is_active, created_at)
                                          VALUES (?, ?, ?, ?, ?, ?, datetime('now'))");
                    $stmt->bindValue(1, $username, SQLITE3_TEXT);
                    $stmt->bindValue(2, password_hash($password, PASSWORD_DEFAULT), SQLITE3_TEXT);
                    $stmt->bindValue(3, $email, SQLITE3_TEXT);
                    $stmt->bindValue(4, $full_name, SQLITE3_TEXT);
                    $stmt->bindValue(5, $new_role, SQLITE3_TEXT);
                    $stmt->bindValue(6, $is_active, SQLITE3_INTEGER);
                    $stmt->execute();
                    $user_id = $db->lastInsertRowID();

                    $stmtSettings = $db->prepare('INSERT INTO user_settings (user_id) VALUES (?)');
                    $stmtSettings->bindValue(1, $user_id, SQLITE3_INTEGER);
                    $stmtSettings->execute();
                    $db->exec('COMMIT');
                } catch (Exception $inner) {
                    $db->exec('ROLLBACK');
                    throw $inner;
                }

                logSecurityEventToDB(
                    $db,
                    $admin_create ? 'USER_CREATED_BY_ADMIN' : 'USER_REGISTERED',
                    $admin_create ? (int)$_SESSION['user_id'] : (int)$user_id,
                    'New user: ' . $username . ' (' . $new_role . ')'
                );

                if ($admin_create) {
                    $success = t('User {user} created successfully.', ['user' => $username]);
                } elseif ($is_active === 1) {
                    $success = t('Account created! You can log in immediately.');
                } else {
                    $success = t('Account created! Please wait for administrator approval.');
                }
                $username = $email = $full_name = '';
            }
        } catch (Exception $e) {
            error_log('Registration error: ' . $e->getMessage());
            $error = t('System error occurred. Please try again.');
        }
    }
}

$csrf_token = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="<?= e(currentLang()) ?>" dir="<?= e(langDir()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= $admin_create ? et('Create User') : et('Register') ?> - SubSignature</title>
    
    <?= i18nHead() ?>
    
    <script src="<?= assetUrl('js/theme.js') ?>"></script>
    <script src="<?= assetUrl('js/alerts.js') ?>"></script>
    <link rel="stylesheet" href="<?= assetUrl('css/theme.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/style.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/all.min.css') ?>">    
    
    <style>
        .register-body {
            background: linear-gradient(135deg, var(--bg-body) 0%, var(--border) 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
        }
        
        .register-card {
            background: var(--bg-white);
            padding: 2.5rem;
            border-radius: 16px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.08);
            width: 100%;
            max-width: 480px;
            border: 1px solid var(--border);
        }

        .strength-meter {
            height: 4px;
            background: var(--border);
            border-radius: 2px;
            margin-top: 0.5rem;
            overflow: hidden;
        }
        .strength-fill { height: 100%; width: 0%; transition: all 0.3s; }
        .strength-text { font-size: 0.75rem; margin-top: 0.25rem; text-align: right; }

        .password-group { position: relative; }
        .toggle-password {
            position: absolute; right: 12px; top: 42px; color: var(--text-faint); cursor: pointer; z-index: 10;
        }
        .toggle-password:hover { color: var(--primary); }

        .auth-footer { margin-top: 1.5rem; text-align: center; font-size: 0.9rem; color: var(--text-muted); }
        .auth-footer a { color: var(--primary); text-decoration: none; font-weight: 600; }
        
        .status-toggle-wrapper {
            background: var(--bg-subtle);
            padding: 1rem;
            border-radius: 8px;
            border: 1px solid var(--border);
            margin-bottom: 1.5rem;
        }
    </style>
</head>
<body class="<?php echo $admin_create ? '' : 'register-body'; ?>">

    <?php if ($admin_create): ?>
        <aside class="sidebar">
            <?php include 'includes/navbar.php'; ?>
            <div class="sidebar-footer">
        <?= langSwitcher() ?>
                <div class="user-profile">
                    <div class="avatar">
                        <?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?>
                    </div>
                    <div class="user-info">
                        <div><?php echo e($_SESSION['username']); ?></div>
                        <span><?= et('Administrator') ?></span>
                    </div>
                </div>
                <a href="logout.php" class="btn-logout">
                    <i class="fas fa-sign-out-alt"></i> <span><?= et('Sign Out') ?></span>
                </a>
            </div>
        </aside>

        <main class="main-content">
            <header class="page-header">
                <h2><?= et('Create User') ?></h2>
                <p><?= et('Manually register a new user account.') ?></p>
            </header>
    <?php endif; ?>

    <div class="<?php echo $admin_create ? 'card' : 'register-card'; ?>">
        
        <?php if (!$admin_create): ?>
            <div style="text-align: center; margin-bottom: 2rem;">
                <div style="margin-bottom: 1rem;">
                    <img src="img/subsig.svg" alt="SubSignature Logo" style="height: 100px; width: auto; object-fit: contain;">
                </div>
                <h2 style="font-size:1.5rem;"><?= et('Create Account') ?></h2>
                <p style="color:var(--text-muted);"><?= et('Join SubSignature today') ?></p>
            </div>
        <?php endif; ?>

        <?php if ($success): ?>
            <?= alertBox('success', (string)$success) ?>
            
            <div style="margin-top: 1.5rem; text-align: center;">
                <?php if ($admin_create): ?>
                    <a href="admin_users.php" class="btn btn-secondary"><?= et('Back to User List') ?></a>
                    <a href="register.php?admin=1" class="btn btn-primary"><?= et('Create Another') ?></a>
                <?php else: ?>
                    <a href="index.php" class="btn btn-primary" style="width:100%"><?= et('Go to Login') ?></a>
                <?php endif; ?>
            </div>
        <?php else: ?>  
            
            <?php if ($error): ?>
                <?= alertBox('error', (string)$error) ?>
            <?php endif; ?>

            <div data-alert-host></div>
            <form method="POST" id="regForm" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?php echo e($csrf_token); ?>">
                
                <?php if ($admin_create): ?>
                <div class="status-toggle-wrapper">
                    <div class="form-group" style="margin-bottom:0;">
                        <label for="user_status"><?= et('Initial Account Status') ?></label>
                        <select name="user_status" id="user_status" style="width:100%; padding:0.6rem; border:1px solid var(--border); border-radius:6px;">
                            <option value="1" <?php echo ($config_default_active == 1) ? 'selected' : ''; ?>><?= et('Active (Can login immediately)') ?></option>
                            <option value="0" <?php echo ($config_default_active == 0) ? 'selected' : ''; ?>><?= et('Inactive (Requires activation)') ?></option>
                        </select>
                    </div>
                    <div class="form-group" style="margin:1rem 0 0;">
                        <label for="new_role"><?= et('Role') ?></label>
                        <select name="new_role" id="new_role" style="width:100%; padding:0.6rem; border:1px solid var(--border); border-radius:6px;">
                            <option value="user" selected><?= et('User') ?></option>
                            <option value="technician"><?= et('Technician') ?></option>
                            <option value="admin"><?= et('Administrator') ?></option>
                        </select>
                        <small style="color:var(--text-muted); display:block; margin-top:0.4rem;"><?= et('Technicians can use all tools and work with all signatures, but have no access to Users, System Configuration and System Logs.') ?></small>
                    </div>
                </div>
                <?php endif; ?>

                <div class="form-group">
                    <label for="username"><?= et('Username') ?></label>
                    <input type="text" id="username" name="username" required  
                           value="<?php echo e($username); ?>"
                           placeholder="<?= et('johndoe') ?>" pattern="[A-Za-z0-9_.@\-]{3,64}"
                           autocomplete="off">
                    <small style="color:var(--text-muted); font-size:0.75rem;"><?= et('3-64 chars: letters, numbers, . _ - @') ?></small>
                </div>

                <div class="form-group">
                    <label for="email"><?= et('Email Address') ?></label>
                    <input type="email" id="email" name="email"  
                           value="<?php echo e($email); ?>"
                           placeholder="john@example.com">
                </div>

                <div class="form-group">
                    <label for="full_name"><?= et('Full Name') ?></label>
                    <input type="text" id="full_name" name="full_name"  
                           value="<?php echo e($full_name); ?>"
                           placeholder="<?= et('John Doe') ?>">
                </div>

                <div class="form-group password-group">
                    <label for="password"><?= et('Password') ?></label>
                    <i class="fas fa-eye toggle-password" onclick="togglePass('password')"></i>
                    <input type="password" id="password" name="password" required  
                           placeholder="<?= et('Min. 8 chars') ?>" oninput="checkStrength(this.value)"
                           autocomplete="new-password">
                    
                    <div class="strength-meter">
                        <div class="strength-fill" id="strengthBar"></div>
                    </div>
                    <div class="strength-text" id="strengthText"><?= et('Enter password') ?></div>
                </div>

                <div class="form-group password-group">
                    <label for="confirm_password"><?= et('Confirm Password') ?></label>
                    <i class="fas fa-eye toggle-password" onclick="togglePass('confirm_password')"></i>
                    <input type="password" id="confirm_password" name="confirm_password" required  
                           placeholder="<?= et('Repeat password') ?>">
                </div>

                <div class="form-actions" style="margin-top: 2rem;">
                    <button type="submit" class="btn btn-primary" style="width:100%;">
                        <?= $admin_create ? et('Create User') : et('Register Account') ?>
                    </button>
                </div>

                <?php if (!$admin_create): ?>
                    <div class="auth-footer">
                        <?= eth('Already have an account? {link}', ['link' => '<a href="index.php">' . et('Log In') . '</a>']) ?>
                    </div>
                <?php endif; ?>
            </form>
        <?php endif; ?>  
    </div>

    <?php if ($admin_create): ?>
        </main>
    <?php endif; ?>

    <script>
    function togglePass(id) {
        const input = document.getElementById(id);
        const type = input.type === 'password' ? 'text' : 'password';
        input.type = type;
        const icon = input.parentElement.querySelector('.toggle-password');
        if (icon) {
            if (type === 'text') { icon.classList.remove('fa-eye'); icon.classList.add('fa-eye-slash'); } 
            else { icon.classList.remove('fa-eye-slash'); icon.classList.add('fa-eye'); }
        }
    }

    function checkStrength(password) {
        const bar = document.getElementById('strengthBar');
        const text = document.getElementById('strengthText');
        let strength = 0;
        
        if (password.length >= 8) strength += 1;
        if (password.match(/[a-z]/) && password.match(/[A-Z]/)) strength += 1;
        if (password.match(/\d/)) strength += 1;
        if (password.match(/[^a-zA-Z\d]/)) strength += 1;

        switch(strength) {
            case 0: case 1: bar.style.width = '25%'; bar.style.backgroundColor = '#ef4444'; text.textContent = 'Weak'; text.style.color = '#ef4444'; break;
            case 2: bar.style.width = '50%'; bar.style.backgroundColor = '#f59e0b'; text.textContent = 'Fair'; text.style.color = '#f59e0b'; break;
            case 3: bar.style.width = '75%'; bar.style.backgroundColor = 'var(--primary)'; text.textContent = 'Good'; text.style.color = 'var(--primary)'; break;
            case 4: bar.style.width = '100%'; bar.style.backgroundColor = '#10b981'; text.textContent = 'Strong'; text.style.color = '#10b981'; break;
        }
    }

    const form = document.getElementById('regForm');
    if (form) {
        form.addEventListener('submit', function(e) {
            const p1 = document.getElementById('password').value;
            const p2 = document.getElementById('confirm_password').value;
            if (p1 !== p2) { e.preventDefault(); SubSigAlert.show('error', <?= tj('Passwords do not match!') ?>); }
        });
    }
    </script>
</body>
</html>
