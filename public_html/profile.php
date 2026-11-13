<?php
// profile.php

// 1. Include Configuration & Security
require_once 'includes/config.php';
requireLogin();

// ---------------------------------------------------------
// 3. DETERMINE TARGET USER (Security Critical)
// ---------------------------------------------------------
$current_user_id = (int)$_SESSION['user_id']; // The person logged in
$target_user_id = $current_user_id;       // Default: Edit self

$is_admin_editing_others = false;

// Check if an ID is requested via URL (e.g., profile.php?user_id=5)
if (isset($_GET['user_id'])) {
    $requested_id = (int)$_GET['user_id'];
    
    // SECURITY CHECK: Only administrators can edit other users (technicians cannot)
    if (isAdmin() && $requested_id !== $current_user_id) {
        $target_user_id = $requested_id;
        $is_admin_editing_others = true;
    } elseif ($requested_id !== $current_user_id) {
        // Non-admin trying to access another profile -> Security Log & Redirect
        logSecurityEventToDB($db, 'UNAUTHORIZED_ACCESS', $current_user_id, "Tried to access profile ID: $requested_id");
        header('Location: profile.php'); // Redirect to own profile
        exit;
    }
}
// ---------------------------------------------------------

$error = '';
$success = '';

// 4. Update Profile Logic
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_profile'])) {
    
    requireCsrf();

    $full_name = cleanText($_POST['full_name'] ?? '', 100);
    $email = cleanText($_POST['email'] ?? '', 254);

    if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = t('Invalid email address!');
    } else {
        // The email address must stay unique (it is also checked at registration).
        $dup = 0;
        if ($email !== '') {
            $chk = $db->prepare('SELECT COUNT(*) FROM users WHERE email = ? AND id != ?');
            $chk->bindValue(1, $email, SQLITE3_TEXT);
            $chk->bindValue(2, $target_user_id, SQLITE3_INTEGER);
            $dup = (int)$chk->execute()->fetchArray(SQLITE3_NUM)[0];
        }

        if ($dup > 0) {
            $error = t('This email address is already used by another account.');
        } else {
            $stmt = $db->prepare('UPDATE users SET full_name = ?, email = ? WHERE id = ?');
            $stmt->bindValue(1, $full_name, SQLITE3_TEXT);
            $stmt->bindValue(2, $email, SQLITE3_TEXT);
            $stmt->bindValue(3, $target_user_id, SQLITE3_INTEGER);
            $stmt->execute();

            if (!$is_admin_editing_others) {
                $_SESSION['full_name'] = $full_name;
                $_SESSION['email'] = $email;
                $success = t('Profile updated successfully!');
            } else {
                logSecurityEventToDB($db, 'ADMIN_PROFILE_EDIT', $current_user_id, "Target ID: $target_user_id");
                $success = t('User profile updated successfully (Admin Mode).');
            }
        }
    }
}

// 5. Load User Data (Target User)
$stmt = $db->prepare("SELECT username, email, full_name, role, created_at, last_login 
                     FROM users WHERE id = ?");
$stmt->bindValue(1, $target_user_id, SQLITE3_INTEGER);
$result = $stmt->execute();
$user = $result->fetchArray(SQLITE3_ASSOC);

if (!$user) {
    if ($is_admin_editing_others) {
        setFlash('error', t('User not found.'));
        header('Location: admin_users.php'); // Admin fallback
    } else {
        header('Location: logout.php'); // Self fallback
    }
    exit;
}

// 6. User Statistics
$sig_stmt = $db->prepare("SELECT COUNT(*) as count FROM user_signatures WHERE user_id = ?");
$sig_stmt->bindValue(1, $target_user_id, SQLITE3_INTEGER);
$sig_result = $sig_stmt->execute();
$sig_count = $sig_result->fetchArray(SQLITE3_ASSOC)['count'];
?>
<!DOCTYPE html>
<html lang="<?= e(currentLang()) ?>" dir="<?= e(langDir()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= $is_admin_editing_others ? et('Edit User') : et('My Profile') ?> - SubSignature</title>
    
    <?= i18nHead() ?>
    
    <script src="<?= assetUrl('js/theme.js') ?>"></script>
    <link rel="stylesheet" href="<?= assetUrl('css/theme.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/style.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/all.min.css') ?>">
    
    <style>
        /* Profile Specific Styles */
        .profile-layout { display: grid; grid-template-columns: 2fr 1fr; gap: 2rem; }
        .profile-card { background: var(--bg-white); border-radius: 12px; border: 1px solid var(--border); overflow: hidden; display: flex; flex-direction: column; }
        .profile-header { background: linear-gradient(135deg, var(--bg-subtle) 0%, var(--bg-white) 100%); padding: 2rem; text-align: center; border-bottom: 1px solid var(--border); }
        .profile-avatar { width: 80px; height: 80px; background: var(--bg-white); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 2.5rem; color: var(--primary); margin: 0 auto 1rem; box-shadow: 0 4px 12px rgba(0,0,0,0.08); border: 2px solid var(--bg-white); }
        .profile-name { font-size: 1.4rem; font-weight: 700; color: var(--text-main); margin-bottom: 0.25rem; }
        .profile-role { color: var(--text-muted); font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; }
        .stats-list { padding: 1.5rem; }
        .stat-row { display: flex; justify-content: space-between; padding: 0.75rem 0; border-bottom: 1px solid var(--border); font-size: 0.95rem; }
        .stat-row:last-child { border-bottom: none; }
        .stat-key { color: var(--text-muted); display: flex; align-items: center; gap: 0.5rem; }
        .stat-val { font-weight: 600; color: var(--text-main); }
        .action-list { display: flex; flex-direction: column; gap: 0.75rem; padding: 1.5rem; background: var(--bg-subtle); border-top: 1px solid var(--border); }
        .action-btn { display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem 1rem; background: var(--bg-white); border: 1px solid var(--border); border-radius: 8px; color: var(--text-main); text-decoration: none; font-weight: 500; transition: all 0.2s; }
        .action-btn:hover { border-color: var(--primary); color: var(--primary); transform: translateX(4px); }
        .action-btn i { width: 20px; text-align: center; color: var(--text-muted); }
        .action-btn:hover i { color: var(--primary); }
        .settings-card { background: var(--bg-white); border-radius: 12px; border: 1px solid var(--border); padding: 2rem; }
        
        .admin-banner {
            grid-column: 1 / -1;
            background: var(--warning-bg); border: 1px solid var(--warning-border); color: var(--warning-text);
            padding: 1rem; border-radius: 8px; margin-bottom: 1rem;
            display: flex; align-items: center; gap: 0.75rem;
        }

        @media (max-width: 900px) {
            .profile-layout { grid-template-columns: 1fr; }
            .profile-card { order: -1; }
        }
    </style>
</head>
<body>

    <aside class="sidebar">
        <?php if (file_exists('includes/navbar.php')) include 'includes/navbar.php'; ?>
        <div class="sidebar-footer">
        <?= langSwitcher() ?>
            <div class="user-profile">
                <div class="avatar"><?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?></div>
                <div class="user-info">
                    <div><?php echo e($_SESSION['username']); ?></div>
                    <span><?= eRoleLabel() ?></span>
                </div>
            </div>
            <a href="logout.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> <span><?= et('Sign Out') ?></span></a>
        </div>
    </aside>

    <main class="main-content">
        
        <header class="page-header">
            <?php if ($is_admin_editing_others): ?>
                <h2><?= et('Edit User: {user}', ['user' => $user['username']]) ?></h2>
                <p><?= et('Administrator Mode: Editing another user\'s profile.') ?></p>
            <?php else: ?>
                <h2><?= et('My Profile') ?></h2>
                <p><?= et('Manage your account settings and personal information.') ?></p>
            <?php endif; ?>
        </header>

        <div class="profile-layout">
            
            <?php if ($is_admin_editing_others): ?>
            <div class="admin-banner">
                <i class="fas fa-exclamation-triangle"></i>
                <div>
                    <strong><?= et('Admin Mode Active:') ?></strong>
                    <?= eth('You are editing the profile of {user} (ID: {id}).', ['user' => '<u>' . e($user['username']) . '</u>', 'id' => (int)$target_user_id]) ?>
                    <a href="admin_users.php" style="color:inherit; font-weight:700; margin-left:10px;"><?= et('Back to List') ?></a>
                </div>
            </div>
            <?php endif; ?>

            <div class="settings-card">
                <h3 style="margin-bottom: 1.5rem; display: flex; align-items: center; gap: 0.5rem;">
                    <i class="fas fa-user-edit"></i> <?= et('Edit Details') ?>
                </h3>

                <?= flashAlerts($success, $error) ?>

                <form method="POST">
                    <?php echo csrfField(); ?>

                    <div class="form-group">
                        <label for="username"><?= et('Username') ?></label>
                        <input type="text" id="username" 
                               value="<?php echo e($user['username']); ?>" 
                               disabled style="background: var(--bg-subtle); color: var(--text-muted);">
                        <small style="color: var(--text-muted);"><?= et('Username cannot be changed.') ?></small>
                    </div>

                    <div class="form-group">
                        <label for="full_name"><?= et('Full Name') ?></label>
                        <input type="text" id="full_name" name="full_name" 
                               value="<?php echo e($user['full_name'] ?? ''); ?>"
                               placeholder="<?= et('e.g. John Doe') ?>">
                    </div>

                    <div class="form-group">
                        <label for="email"><?= et('Email Address') ?></label>
                        <input type="email" id="email" name="email" 
                               value="<?php echo e($user['email'] ?? ''); ?>"
                               placeholder="john@example.com">
                    </div>

                    <div class="form-group">
                        <label><?= et('Role') ?></label>
                        <input type="text" value="<?= eRoleLabel($user['role']) ?>" 
                               disabled style="background: var(--bg-subtle); color: var(--text-muted);">
                    </div>

                    <div class="form-actions">
                        <button type="submit" name="update_profile" class="btn btn-primary">
                            <i class="fas fa-save"></i> <?= et('Save Changes') ?>
                        </button>
                    </div>
                </form>
            </div>

            <div class="profile-card">
                <div class="profile-header">
                    <div class="profile-avatar"><?php echo strtoupper(substr($user['username'], 0, 1)); ?></div>
                    <div class="profile-name"><?php echo e($user['full_name'] ?: $user['username']); ?></div>
                    <div class="profile-role"><?= eRoleLabel($user['role']) ?></div>
                </div>

                <div class="stats-list">
                    <div class="stat-row">
                        <span class="stat-key"><i class="fas fa-calendar-alt"></i> <?= et('Joined') ?></span>
                        <span class="stat-val"><?php echo e(date('M Y', strtotime($user['created_at']) ?: time())); ?></span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-key"><i class="fas fa-clock"></i> <?= et('Last Login') ?></span>
                        <span class="stat-val"><?php echo $user['last_login'] ? e(date('d.m.Y', strtotime($user['last_login']) ?: time())) : 'Never'; ?></span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-key"><i class="fas fa-signature"></i> <?= et('Signatures') ?></span>
                        <span class="stat-val"><?php echo $sig_count; ?></span>
                    </div>
                </div>

                <div class="action-list">
                    <?php if (!$is_admin_editing_others): ?>
                        <a href="change_password.php" class="action-btn"><i class="fas fa-key"></i> <?= et('Change Password') ?></a>
                        <a href="csv_import.php" class="action-btn"><i class="fas fa-file-import"></i> <?= et('Import Data') ?></a>
                    <?php else: ?>
                        <div style="text-align:center; padding:0.5rem; color:var(--text-muted); font-size:0.85rem;">
                            <?= et('To reset password, use the Admin User List.') ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </main>
</body>
</html>
