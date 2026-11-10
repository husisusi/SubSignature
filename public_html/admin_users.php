<?php
// admin_users.php - user management. Administrators only: a technician must never be able to
// create users, change roles or passwords, or (de)activate and delete accounts.

require_once 'includes/config.php';
requireAdmin();

// 1. Messages (flash messages survive exactly one redirect)
$message = popFlash('success');
$error = popFlash('error');

// 2. HANDLE POST REQUESTS (all state-changing actions: POST + CSRF)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    requireCsrf();

    $action = $_POST['action'] ?? '';
    $target_user_id = (int)($_POST['user_id'] ?? 0);
    $self_id = (int)$_SESSION['user_id'];

    // Name of the target for the audit log (also verifies that it exists).
    $stmt = $db->prepare('SELECT username, role FROM users WHERE id = ?');
    $stmt->bindValue(1, $target_user_id, SQLITE3_INTEGER);
    $target = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if (!$target) {
        setFlash('error', t('User not found.'));
    } elseif ($action === 'reset_password') {
        $new_password = is_string($_POST['new_password'] ?? null) ? $_POST['new_password'] : '';
        $policyErrors = validatePasswordPolicy($new_password);
        if ($policyErrors) {
            setFlash('error', t('Password too weak: {details}.', ['details' => implode('; ', $policyErrors)]));
        } else {
            $stmt = $db->prepare('UPDATE users SET password_hash = ?, failed_login_attempts = 0, account_locked_until = NULL WHERE id = ?');
            $stmt->bindValue(1, password_hash($new_password, PASSWORD_DEFAULT), SQLITE3_TEXT);
            $stmt->bindValue(2, $target_user_id, SQLITE3_INTEGER);
            $stmt->execute();
            // Existing sessions of that user end automatically (password fingerprint changes).
            logSecurityEventToDB($db, 'ADMIN_PASSWORD_RESET', $self_id, 'Target: ' . $target['username']);
            setFlash('success', t('Password successfully reset for user {user}.', ['user' => $target['username']]));
        }
    } elseif ($target_user_id === $self_id) {
        // Admins cannot lock themselves out (deactivate / demote / delete themselves).
        setFlash('error', t('You cannot change your own account here.'));
    } else {
        // Removing administrator power from an admin (demote, deactivate, delete) is only allowed while
        // ANOTHER active administrator remains. The check is part of the SQL statement, so it is atomic
        // even when two administrators act at the same moment.
        $keepAdmin = "(role != 'admin' OR (SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1 AND id != :id) > 0)";
        $newRole = null;
        $sql = null;

        switch ($action) {
            case 'activate':
                $sql = 'UPDATE users SET is_active = 1 WHERE id = :id';
                break;
            case 'deactivate':
                $sql = 'UPDATE users SET is_active = 0 WHERE id = :id AND ' . $keepAdmin;
                break;
            case 'set_role':
                $newRole = $_POST['role'] ?? '';
                if (!isValidRole($newRole)) {
                    setFlash('error', t('Invalid role.'));
                    break;
                }
                if ($newRole === $target['role']) {
                    setFlash('success', t('Action completed for user {user}.', ['user' => $target['username']]));
                    break; // nothing to change, nothing to log
                }
                $sql = $newRole === ROLE_ADMIN
                    ? 'UPDATE users SET role = :role WHERE id = :id'
                    : 'UPDATE users SET role = :role WHERE id = :id AND ' . $keepAdmin;
                break;
            case 'delete':
                $sql = 'DELETE FROM users WHERE id = :id AND ' . $keepAdmin;
                break;
        }

        if ($sql !== null) {
            $stmt = $db->prepare($sql);
            $stmt->bindValue(':id', $target_user_id, SQLITE3_INTEGER);
            if ($newRole !== null) {
                $stmt->bindValue(':role', $newRole, SQLITE3_TEXT);
            }
            $stmt->execute();

            if ($db->changes() < 1) {
                setFlash('error', t('At least one active administrator must remain.'));
            } else {
                if ($action === 'set_role') {
                    logSecurityEventToDB($db, 'ADMIN_ROLE_CHANGED', $self_id, 'Target: ' . $target['username'] . ' (' . $target['role'] . ' -> ' . $newRole . ')');
                } else {
                    logSecurityEventToDB($db, 'ADMIN_USER_' . strtoupper($action), $self_id, 'Target: ' . $target['username']);
                }
                setFlash('success', t('Action completed for user {user}.', ['user' => $target['username']]));
            }
        }
    }
    header('Location: admin_users.php');
    exit;
}

// 4. LOAD DATA
$stmt = $db->prepare("SELECT id, username, email, full_name, role, is_active, 
                     created_at, last_login, auth_source FROM users ORDER BY created_at DESC, id DESC");
$result = $stmt->execute();
$users = [];
while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
    $users[] = $row;
}

// Statistics
$total_users = count($users);
$active_users = array_filter($users, function ($u) { return $u['is_active'] == 1; });
$admin_users = array_filter($users, function ($u) { return $u['role'] === ROLE_ADMIN; });
$technician_users = array_filter($users, function ($u) { return $u['role'] === ROLE_TECHNICIAN; });
?>
<!DOCTYPE html>
<html lang="<?= e(currentLang()) ?>" dir="<?= e(langDir()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= et('User Management') ?> - SubSignature</title>
    <?= i18nHead() ?>
    <script src="<?= assetUrl('js/theme.js') ?>"></script>
    <link rel="stylesheet" href="<?= assetUrl('css/theme.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/style.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/all.min.css') ?>">
    <?php echo csrfMeta(); ?>
    <style>
        /* --- Layout Fixes --- */
        .page-header-actions { 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            margin-bottom: 2rem; 
            flex-wrap: wrap; /* Prevent breaking on very small screens */
            gap: 1rem;
        }
        .page-header-title h2 { margin: 0; font-size: 1.8rem; font-weight: 700; color: var(--text-main); }
        .page-header-title p { margin: 0; color: var(--text-muted); }

        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
        .stat-card { background: var(--bg-white); padding: 1.5rem; border-radius: 12px; border: 1px solid var(--border); box-shadow: 0 1px 3px rgba(0,0,0,0.05); display: flex; flex-direction: column; }
        .stat-label { color: var(--text-muted); font-size: 0.85rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem; }
        .stat-value { font-size: 2rem; font-weight: 700; color: var(--text-main); }
        .stat-icon { float: right; color: var(--primary); opacity: 0.2; font-size: 2rem; margin-top: -2.5rem; }
        
        .users-table { width: 100%; border-collapse: collapse; font-size: 0.95rem; }
        .users-table th { text-align: left; padding: 1rem; background: var(--bg-subtle); border-bottom: 1px solid var(--border); color: var(--text-muted); font-weight: 600; font-size: 0.85rem; text-transform: uppercase; }
        .users-table td { padding: 1rem; border-bottom: 1px solid var(--border); vertical-align: middle; }
        .users-table tr:hover { background: var(--bg-subtle); }
        
        .badge { padding: 0.25rem 0.6rem; border-radius: 99px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
        .badge-admin { background: var(--danger-bg); color: var(--danger-text); border: 1px solid var(--danger-border); }
        .badge-user { background: var(--bg-hover); color: var(--primary); border: 1px solid var(--info-border); }
        .badge-tech { background: var(--warning-bg); color: var(--warning-text); border: 1px solid var(--warning-border); }
        .role-select { width: 100%; padding: 0.75rem; border: 1px solid var(--border); border-radius: 6px; font-size: 1rem; background: var(--bg-white); color: var(--text-main); }
        .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
        .status-active { color: var(--success-text); } .dot-active { background: #16a34a; }
        .status-inactive { color: var(--danger-text); } .dot-inactive { background: #dc2626; }
        
        .badge-self { background: var(--bg-subtle); color: var(--text-muted); font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; margin-left: 0.5rem; border: 1px solid var(--border); }
        
        .btn-icon { width: 32px; height: 32px; display: inline-flex; align-items: center; justify-content: center; border-radius: 6px; border: 1px solid transparent; color: var(--text-muted); transition: all 0.2s; text-decoration: none; cursor: pointer; }
        .btn-icon:hover { background: var(--bg-subtle); color: var(--primary); }
        .btn-icon.danger:hover { background: var(--danger-bg); color: var(--danger-text); border-color: var(--danger-border); }
        .btn-icon.warning:hover { background: var(--warning-bg); color: var(--warning-text); border-color: var(--warning-border); }
        .btn-icon.success:hover { background: var(--success-bg); color: var(--success-text); border-color: var(--success-border); }
        
        .username-link { color: var(--text-main); font-weight: 600; text-decoration: none; display: inline-flex; align-items: center; }
        .username-link:hover { color: var(--primary); text-decoration: underline; }
        .username-link i { font-size: 0.75rem; margin-left: 0.5rem; opacity: 0.5; }

        /* Modal Styles */
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.5); display: none; justify-content: center; align-items: center; z-index: 1000; backdrop-filter: blur(2px); }
        .modal-box { background: var(--bg-white); width: 90%; max-width: 400px; padding: 2rem; border-radius: 12px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1); position: relative; }
        .modal-header h3 { margin: 0; color: var(--text-main); font-size: 1.25rem; }
        .modal-close { position: absolute; top: 1rem; right: 1rem; cursor: pointer; color: var(--text-muted); font-size: 1.2rem; }
        
        @media (max-width: 768px) { 
            .page-header-actions { flex-direction: column; align-items: flex-start; } 
            .page-header-actions .btn { width: 100%; justify-content: center; }
        }
    </style>
</head>
<body>
    <aside class="sidebar">
        <?php include 'includes/navbar.php'; ?>
        <div class="sidebar-footer">
        <?= langSwitcher() ?>
            <div class="user-profile">
                <div class="avatar"><?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?></div>
                <div class="user-info">
                    <div><?php echo e($_SESSION['username']); ?></div>
                    <span><?= et('Administrator') ?></span>
                </div>
            </div>
            <a href="logout.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> <span><?= et('Sign Out') ?></span></a>
        </div>
    </aside>

    <main class="main-content">
        <div class="page-header-actions">
            <div class="page-header-title">
                <h2><?= et('User Management') ?></h2>
                <p><?= et('Manage system access and roles.') ?></p>
            </div>
            
            <a href="register.php?admin=1" class="btn btn-primary">
                <i class="fas fa-user-plus"></i> <?= et('Create New User') ?>
            </a>
        </div>

        <?php if ($message): ?>
            <div class="alert alert-success" style="padding: 1rem; background: var(--success-bg); color: var(--success-text); border-radius: 8px; margin-bottom: 1.5rem;"><i class="fas fa-check-circle"></i> <?php echo e($message); ?></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="alert alert-error" style="padding: 1rem; background: var(--danger-bg); color: var(--danger-text); border-radius: 8px; margin-bottom: 1.5rem;"><i class="fas fa-exclamation-circle"></i> <?php echo e($error); ?></div>
        <?php endif; ?>

        <div class="stats-grid">
            <div class="stat-card">
                <span class="stat-label"><?= et('Total Users') ?></span>
                <span class="stat-value"><?php echo $total_users; ?></span>
                <i class="fas fa-users stat-icon"></i>
            </div>
            <div class="stat-card">
                <span class="stat-label"><?= et('Active Users') ?></span>
                <span class="stat-value" style="color:var(--success);"><?php echo count($active_users); ?></span>
                <i class="fas fa-check-circle stat-icon" style="color:var(--success);"></i>
            </div>
            <div class="stat-card">
                <span class="stat-label"><?= et('Administrators') ?></span>
                <span class="stat-value" style="color:var(--primary);"><?php echo count($admin_users); ?></span>
                <i class="fas fa-crown stat-icon"></i>
            </div>
            <div class="stat-card">
                <span class="stat-label"><?= et('Technicians') ?></span>
                <span class="stat-value" style="color:var(--warning-text);"><?php echo count($technician_users); ?></span>
                <i class="fas fa-screwdriver-wrench stat-icon"></i>
            </div>
            <div class="stat-card">
                <span class="stat-label"><?= et('Inactive') ?></span>
                <span class="stat-value" style="color:var(--text-muted);"><?php echo $total_users - count($active_users); ?></span>
                <i class="fas fa-user-slash stat-icon" style="color:var(--text-muted);"></i>
            </div>
        </div>
        
        <section class="card" style="padding:0; overflow:hidden;">
            <div class="table-responsive">
                <table class="users-table">
                    <thead>
                        <tr>
                            <th style="width: 50px;">ID</th>
                            <th><?= et('Username') ?></th>
                            <th><?= et('Full Name') ?></th>
                            <th><?= et('Role') ?></th>
                            <th><?= et('Status') ?></th>
                            <th><?= et('Created At') ?></th>
                            <th><?= et('Last Login') ?></th>
                            <th style="text-align:right;"><?= et('Actions') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $user): ?>
                        <tr>
                            <td>#<?php echo $user['id']; ?></td>
                            <td>
                                <a href="profile.php?user_id=<?php echo (int)$user['id']; ?>" class="username-link" title="<?= et('Edit Profile') ?>">
                                    <?php echo e($user['username']); ?>
                                    <i class="fas fa-pen"></i>
                                </a>
                                <?php if ($user['id'] == $_SESSION['user_id']): ?>
                                    <span class="badge-self">YOU</span>
                                <?php endif; ?>
                                <?php if (($user['auth_source'] ?? 'local') === 'ldap'): ?>
                                    <span class="badge badge-user" title="<?= et('Imported from LDAP / Active Directory') ?>">LDAP</span>
                                <?php endif; ?>
                                <div style="font-size:0.85rem; color:var(--text-muted); margin-top:2px;">
                                    <?php echo e($user['email'] ?: t('No email')); ?>
                                </div>
                            </td>
                            <td>
                                <?php echo e($user['full_name'] ?: '-'); ?>
                            </td>
                            <td>
                                <?php if ($user['role'] === ROLE_ADMIN): ?>
                                    <span class="badge badge-admin"><i class="fas fa-crown"></i> <?= et('Admin') ?></span>
                                <?php elseif ($user['role'] === ROLE_TECHNICIAN): ?>
                                    <span class="badge badge-tech"><i class="fas fa-screwdriver-wrench"></i> <?= et('Technician') ?></span>
                                <?php else: ?>
                                    <span class="badge badge-user"><?= et('User') ?></span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if ($user['is_active']): ?>
                                    <div class="status-active"><span class="status-dot dot-active"></span> <?= et('Active') ?></div>
                                <?php else: ?>
                                    <div class="status-inactive"><span class="status-dot dot-inactive"></span> <?= et('Inactive') ?></div>
                                <?php endif; ?>
                            </td>
                            <td style="color:var(--text-muted); font-size:0.9rem;">
                                <?php echo e(date('M d, Y', strtotime($user['created_at']) ?: time())); ?>
                            </td>
                            <td style="color:var(--text-muted); font-size:0.9rem;">
                                <?php echo $user['last_login'] ? e(date('M d, H:i', strtotime($user['last_login']) ?: time())) : 'Never'; ?>
                            </td>
                            <td style="text-align:right;">
                                <div style="display:inline-flex; gap:0.25rem;">
                                    <?php if ($user['id'] != $_SESSION['user_id']): ?>
                                        <button type="button" class="btn-icon warning" 
                                                data-reset-id="<?php echo (int)$user['id']; ?>" data-reset-name="<?php echo e($user['username']); ?>"
                                                title="<?= et('Reset Password') ?>">
                                            <i class="fas fa-key"></i>
                                        </button>

                                        <?php if ($user['is_active']): ?>
                                            <button type="button" data-post="admin_users.php" data-params='{"action":"deactivate","user_id":"<?php echo (int)$user['id']; ?>"}' class="btn-icon warning" data-confirm="<?= et('Deactivate this user?') ?>" title="<?= et('Deactivate') ?>"><i class="fas fa-user-slash"></i></button>
                                        <?php else: ?>
                                            <button type="button" data-post="admin_users.php" data-params='{"action":"activate","user_id":"<?php echo (int)$user['id']; ?>"}' class="btn-icon success" data-confirm="<?= et('Activate this user?') ?>" title="<?= et('Activate') ?>"><i class="fas fa-user-check"></i></button>
                                        <?php endif; ?>
                                        
                                        <button type="button" class="btn-icon" data-role-id="<?php echo (int)$user['id']; ?>" data-role-name="<?php echo e($user['username']); ?>" data-role-current="<?php echo e(isValidRole($user['role']) ? $user['role'] : ROLE_USER); ?>" title="<?= et('Change role') ?>"><i class="fas fa-user-shield"></i></button>

                                        <button type="button" data-post="admin_users.php" data-params='{"action":"delete","user_id":"<?php echo (int)$user['id']; ?>"}' class="btn-icon danger" data-confirm="<?= et('Permanently delete?') ?>" title="<?= et('Delete') ?>"><i class="fas fa-trash"></i></button>
                                    <?php else: ?>
                                        <a href="profile.php" class="btn-icon" title="<?= et('Edit My Profile') ?>"><i class="fas fa-user-edit"></i></a>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </section>
    </main>

    <div id="resetModal" class="modal-overlay">
        <div class="modal-box">
            <span class="modal-close" id="resetModalClose">&times;</span>
            <div class="modal-header">
                <h3><i class="fas fa-key warning" style="color:var(--warning-text);"></i> <?= et('Reset Password') ?></h3>
                <p style="color:var(--text-muted); font-size:0.9rem; margin-top:0.5rem;">
                    <?= eth('Set a new password for user: {user}', ['user' => '<strong id="modalUsername"></strong>']) ?>
                </p>
            </div>
            
            <form method="POST" action="admin_users.php">
                <?php echo csrfField(); ?>
                <input type="hidden" name="action" value="reset_password">
                <input type="hidden" name="user_id" id="modalUserId">
                
                <div class="form-group" style="margin-bottom:1.5rem;">
                    <label for="new_password" style="display:block; margin-bottom:0.5rem; font-weight:500;"><?= et('New Password') ?></label>
                    <input type="text" id="new_password" name="new_password" required autocomplete="off" maxlength="200" placeholder="<?= et('Enter new password...') ?>" style="width:100%; padding:0.75rem; border:1px solid var(--border); border-radius:6px; font-size:1rem;">
                    <small style="color:var(--text-muted); display:block; margin-top:0.25rem;"><?= et('Min. 8 characters, upper and lower case letters and a number') ?></small>
                </div>
                
                <div style="display:flex; justify-content:flex-end; gap:0.5rem;">
                    <button type="button" class="btn btn-danger" style="background:var(--bg-white); color:var(--text-main); border:1px solid var(--border);" id="resetModalCancel"><?= et('Cancel') ?></button>
                    <button type="submit" class="btn btn-primary"><?= et('Set Password') ?></button>
                </div>
            </form>
        </div>
    </div>

    <div id="roleModal" class="modal-overlay">
        <div class="modal-box">
            <span class="modal-close" id="roleModalClose">&times;</span>
            <div class="modal-header">
                <h3><i class="fas fa-user-shield" style="color:var(--primary);"></i> <?= et('Change role') ?></h3>
                <p style="color:var(--text-muted); font-size:0.9rem; margin-top:0.5rem;">
                    <?= eth('Set the role for user: {user}', ['user' => '<strong id="roleModalUsername"></strong>']) ?>
                </p>
            </div>

            <form method="POST" action="admin_users.php">
                <?php echo csrfField(); ?>
                <input type="hidden" name="action" value="set_role">
                <input type="hidden" name="user_id" id="roleModalUserId">

                <div class="form-group" style="margin-bottom:1.5rem;">
                    <label for="role_select" style="display:block; margin-bottom:0.5rem; font-weight:500;"><?= et('Role') ?></label>
                    <select id="role_select" name="role" class="role-select">
                        <option value="user"><?= et('User') ?></option>
                        <option value="technician"><?= et('Technician') ?></option>
                        <option value="admin"><?= et('Administrator') ?></option>
                    </select>
                    <small style="color:var(--text-muted); display:block; margin-top:0.5rem;"><?= et('Technicians can use all tools and work with all signatures, but have no access to Users, System Configuration and System Logs.') ?></small>
                </div>

                <div style="display:flex; justify-content:flex-end; gap:0.5rem;">
                    <button type="button" class="btn btn-danger" style="background:var(--bg-white); color:var(--text-main); border:1px solid var(--border);" id="roleModalCancel"><?= et('Cancel') ?></button>
                    <button type="submit" class="btn btn-primary"><?= et('Save') ?></button>
                </div>
            </form>
        </div>
    </div>

    <script src="<?= assetUrl('js/post-action.js') ?>"></script>
    <script>
        const modal = document.getElementById('resetModal');
        const modalUserSpan = document.getElementById('modalUsername');
        const modalUserIdInput = document.getElementById('modalUserId');

        function openResetModal(id, username) {
            modalUserIdInput.value = id;
            modalUserSpan.textContent = username;
            modal.style.display = 'flex';
        }
        function closeResetModal() { modal.style.display = 'none'; }
        const roleModal = document.getElementById('roleModal');
        function closeRoleModal() { roleModal.style.display = 'none'; }
        window.onclick = function(event) {
            if (event.target == modal) closeResetModal();
            if (event.target == roleModal) closeRoleModal();
        }
        document.querySelectorAll('[data-role-id]').forEach(function (btn) {
            btn.addEventListener('click', function () {
                document.getElementById('roleModalUserId').value = btn.getAttribute('data-role-id');
                document.getElementById('roleModalUsername').textContent = btn.getAttribute('data-role-name');
                document.getElementById('role_select').value = btn.getAttribute('data-role-current');
                roleModal.style.display = 'flex';
            });
        });
        document.getElementById('roleModalClose').addEventListener('click', closeRoleModal);
        document.getElementById('roleModalCancel').addEventListener('click', closeRoleModal);
        document.querySelectorAll('[data-reset-id]').forEach(function (btn) {
            btn.addEventListener('click', function () {
                openResetModal(btn.getAttribute('data-reset-id'), btn.getAttribute('data-reset-name'));
            });
        });
        document.getElementById('resetModalClose').addEventListener('click', closeResetModal);
        document.getElementById('resetModalCancel').addEventListener('click', closeResetModal);
    </script>
</body>
</html>
