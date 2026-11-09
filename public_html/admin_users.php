<?php
// admin_users.php

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
    $stmt = $db->prepare('SELECT username FROM users WHERE id = ?');
    $stmt->bindValue(1, $target_user_id, SQLITE3_INTEGER);
    $target = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if (!$target) {
        setFlash('error', 'User not found.');
    } elseif ($action === 'reset_password') {
        $new_password = is_string($_POST['new_password'] ?? null) ? $_POST['new_password'] : '';
        $policyErrors = validatePasswordPolicy($new_password);
        if ($policyErrors) {
            setFlash('error', 'Password too weak: ' . implode('; ', $policyErrors) . '.');
        } else {
            $stmt = $db->prepare('UPDATE users SET password_hash = ?, failed_login_attempts = 0, account_locked_until = NULL WHERE id = ?');
            $stmt->bindValue(1, password_hash($new_password, PASSWORD_DEFAULT), SQLITE3_TEXT);
            $stmt->bindValue(2, $target_user_id, SQLITE3_INTEGER);
            $stmt->execute();
            // Existing sessions of that user end automatically (password fingerprint changes).
            logSecurityEventToDB($db, 'ADMIN_PASSWORD_RESET', $self_id, 'Target: ' . $target['username']);
            setFlash('success', 'Password successfully reset for user ' . $target['username'] . '.');
        }
    } elseif ($target_user_id === $self_id) {
        // Admins cannot lock themselves out (deactivate / demote / delete themselves).
        setFlash('error', 'You cannot change your own account here.');
    } else {
        $done = true;
        switch ($action) {
            case 'activate':
                $sql = 'UPDATE users SET is_active = 1 WHERE id = ?';
                break;
            case 'deactivate':
                $sql = 'UPDATE users SET is_active = 0 WHERE id = ?';
                break;
            case 'make_admin':
                $sql = "UPDATE users SET role = 'admin' WHERE id = ?";
                break;
            case 'make_user':
                $sql = "UPDATE users SET role = 'user' WHERE id = ?";
                break;
            case 'delete':
                $sql = 'DELETE FROM users WHERE id = ?';
                break;
            default:
                $done = false;
        }
        if ($done) {
            $stmt = $db->prepare($sql);
            $stmt->bindValue(1, $target_user_id, SQLITE3_INTEGER);
            $stmt->execute();
            logSecurityEventToDB($db, 'ADMIN_USER_' . strtoupper($action), $self_id, 'Target: ' . $target['username']);
            setFlash('success', 'Action completed for user ' . $target['username'] . '.');
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
$admin_users = array_filter($users, function ($u) { return $u['role'] == 'admin'; });
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management - SubSignature</title>
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
        <div class="page-header-actions">
            <div class="page-header-title">
                <h2>User Management</h2>
                <p>Manage system access and roles.</p>
            </div>
            
            <a href="register.php?admin=1" class="btn btn-primary">
                <i class="fas fa-user-plus"></i> Create New User
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
                <span class="stat-label">Total Users</span>
                <span class="stat-value"><?php echo $total_users; ?></span>
                <i class="fas fa-users stat-icon"></i>
            </div>
            <div class="stat-card">
                <span class="stat-label">Active Users</span>
                <span class="stat-value" style="color:var(--success);"><?php echo count($active_users); ?></span>
                <i class="fas fa-check-circle stat-icon" style="color:var(--success);"></i>
            </div>
            <div class="stat-card">
                <span class="stat-label">Administrators</span>
                <span class="stat-value" style="color:var(--primary);"><?php echo count($admin_users); ?></span>
                <i class="fas fa-crown stat-icon"></i>
            </div>
            <div class="stat-card">
                <span class="stat-label">Inactive</span>
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
                            <th>Username</th>
                            <th>Full Name</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Created At</th>
                            <th>Last Login</th>
                            <th style="text-align:right;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $user): ?>
                        <tr>
                            <td>#<?php echo $user['id']; ?></td>
                            <td>
                                <a href="profile.php?user_id=<?php echo (int)$user['id']; ?>" class="username-link" title="Edit Profile">
                                    <?php echo e($user['username']); ?>
                                    <i class="fas fa-pen"></i>
                                </a>
                                <?php if ($user['id'] == $_SESSION['user_id']): ?>
                                    <span class="badge-self">YOU</span>
                                <?php endif; ?>
                                <?php if (($user['auth_source'] ?? 'local') === 'ldap'): ?>
                                    <span class="badge badge-user" title="Imported from LDAP / Active Directory">LDAP</span>
                                <?php endif; ?>
                                <div style="font-size:0.85rem; color:var(--text-muted); margin-top:2px;">
                                    <?php echo e($user['email'] ?: 'No email'); ?>
                                </div>
                            </td>
                            <td>
                                <?php echo e($user['full_name'] ?: '-'); ?>
                            </td>
                            <td>
                                <?php if ($user['role'] == 'admin'): ?>
                                    <span class="badge badge-admin"><i class="fas fa-crown"></i> Admin</span>
                                <?php else: ?>
                                    <span class="badge badge-user">User</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if ($user['is_active']): ?>
                                    <div class="status-active"><span class="status-dot dot-active"></span> Active</div>
                                <?php else: ?>
                                    <div class="status-inactive"><span class="status-dot dot-inactive"></span> Inactive</div>
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
                                                title="Reset Password">
                                            <i class="fas fa-key"></i>
                                        </button>

                                        <?php if ($user['is_active']): ?>
                                            <button type="button" data-post="admin_users.php" data-params='{"action":"deactivate","user_id":"<?php echo (int)$user['id']; ?>"}' class="btn-icon warning" data-confirm="Deactivate this user?" title="Deactivate"><i class="fas fa-user-slash"></i></button>
                                        <?php else: ?>
                                            <button type="button" data-post="admin_users.php" data-params='{"action":"activate","user_id":"<?php echo (int)$user['id']; ?>"}' class="btn-icon success" data-confirm="Activate this user?" title="Activate"><i class="fas fa-user-check"></i></button>
                                        <?php endif; ?>
                                        
                                        <?php if ($user['role'] == 'user'): ?>
                                            <button type="button" data-post="admin_users.php" data-params='{"action":"make_admin","user_id":"<?php echo (int)$user['id']; ?>"}' class="btn-icon" data-confirm="Promote to Admin?" title="Promote"><i class="fas fa-arrow-up"></i></button>
                                        <?php else: ?>
                                            <button type="button" data-post="admin_users.php" data-params='{"action":"make_user","user_id":"<?php echo (int)$user['id']; ?>"}' class="btn-icon" data-confirm="Demote to User?" title="Demote"><i class="fas fa-arrow-down"></i></button>
                                        <?php endif; ?>
                                        
                                        <button type="button" data-post="admin_users.php" data-params='{"action":"delete","user_id":"<?php echo (int)$user['id']; ?>"}' class="btn-icon danger" data-confirm="Permanently delete?" title="Delete"><i class="fas fa-trash"></i></button>
                                    <?php else: ?>
                                        <a href="profile.php" class="btn-icon" title="Edit My Profile"><i class="fas fa-user-edit"></i></a>
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
                <h3><i class="fas fa-key warning" style="color:var(--warning-text);"></i> Reset Password</h3>
                <p style="color:var(--text-muted); font-size:0.9rem; margin-top:0.5rem;">
                    Set a new password for user: <strong id="modalUsername"></strong>
                </p>
            </div>
            
            <form method="POST" action="admin_users.php">
                <?php echo csrfField(); ?>
                <input type="hidden" name="action" value="reset_password">
                <input type="hidden" name="user_id" id="modalUserId">
                
                <div class="form-group" style="margin-bottom:1.5rem;">
                    <label for="new_password" style="display:block; margin-bottom:0.5rem; font-weight:500;">New Password</label>
                    <input type="text" id="new_password" name="new_password" required autocomplete="off" maxlength="200" placeholder="Enter new password..." style="width:100%; padding:0.75rem; border:1px solid var(--border); border-radius:6px; font-size:1rem;">
                    <small style="color:var(--text-muted); display:block; margin-top:0.25rem;">Min. 8 characters, upper and lower case letters and a number</small>
                </div>
                
                <div style="display:flex; justify-content:flex-end; gap:0.5rem;">
                    <button type="button" class="btn btn-danger" style="background:var(--bg-white); color:var(--text-main); border:1px solid var(--border);" id="resetModalCancel">Cancel</button>
                    <button type="submit" class="btn btn-primary">Set Password</button>
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
        window.onclick = function(event) { if (event.target == modal) closeResetModal(); }
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
