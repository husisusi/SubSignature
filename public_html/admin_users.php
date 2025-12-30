<?php
// admin_users.php

require_once 'includes/config.php';
requireAdmin();

// 1. Initialize Variables & CSRF
$message = '';
$error = '';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// 2. HANDLE POST REQUESTS (Secure Password Reset)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Security: Verify CSRF Token
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Security Error: Invalid CSRF Token.");
    }

    if (isset($_POST['action']) && $_POST['action'] === 'reset_password') {
        $target_user_id = (int)$_POST['user_id'];
        $new_password = $_POST['new_password'];
        
        if (empty($new_password) || strlen($new_password) < 8) {
            $error = "Password must be at least 8 characters long.";
        } else {
            $new_hash = password_hash($new_password, PASSWORD_DEFAULT);
            $stmt = $db->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
            $stmt->bindValue(1, $new_hash, SQLITE3_TEXT);
            $stmt->bindValue(2, $target_user_id, SQLITE3_INTEGER);
            
            if ($stmt->execute()) {
                $message = "Password successfully reset for user ID #$target_user_id.";
            } else {
                $error = "Database error while resetting password.";
            }
        }
    }
}

// 3. HANDLE GET ACTIONS
if (isset($_GET['action'])) {
    $user_id = (int)$_GET['user_id'];
    $action = $_GET['action'];
    
    switch ($action) {
        case 'activate':
            $stmt = $db->prepare("UPDATE users SET is_active = 1 WHERE id = ? AND id != ?");
            $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
            $stmt->bindValue(2, $_SESSION['user_id'], SQLITE3_INTEGER); 
            $stmt->execute();
            break;
            
        case 'deactivate':
            $stmt = $db->prepare("UPDATE users SET is_active = 0 WHERE id = ? AND id != ?");
            $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
            $stmt->bindValue(2, $_SESSION['user_id'], SQLITE3_INTEGER);
            $stmt->execute();
            break;
            
        case 'make_admin':
            $stmt = $db->prepare("UPDATE users SET role = 'admin' WHERE id = ? AND id != ?");
            $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
            $stmt->bindValue(2, $_SESSION['user_id'], SQLITE3_INTEGER);
            $stmt->execute();
            break;
            
        case 'make_user':
            $stmt = $db->prepare("UPDATE users SET role = 'user' WHERE id = ? AND id != ?");
            $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
            $stmt->bindValue(2, $_SESSION['user_id'], SQLITE3_INTEGER);
            $stmt->execute();
            break;
            
        case 'delete':
            if ($user_id != $_SESSION['user_id']) {
                $stmt = $db->prepare("DELETE FROM users WHERE id = ?");
                $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
                $stmt->execute();
            }
            break;
    }
    header('Location: admin_users.php');
    exit;
}

// 4. LOAD DATA
$stmt = $db->prepare("SELECT id, username, email, full_name, role, is_active, 
                     created_at, last_login FROM users ORDER BY created_at DESC");
$result = $stmt->execute();
$users = [];
while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
    $users[] = $row;
}

// Statistics
$total_users = count($users);
$active_users = array_filter($users, fn($u) => $u['is_active'] == 1);
$admin_users = array_filter($users, fn($u) => $u['role'] == 'admin');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management - SubSignature</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/all.min.css">    
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
        .stat-card { background: white; padding: 1.5rem; border-radius: 12px; border: 1px solid var(--border); box-shadow: 0 1px 3px rgba(0,0,0,0.05); display: flex; flex-direction: column; }
        .stat-label { color: var(--text-muted); font-size: 0.85rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem; }
        .stat-value { font-size: 2rem; font-weight: 700; color: var(--text-main); }
        .stat-icon { float: right; color: var(--primary); opacity: 0.2; font-size: 2rem; margin-top: -2.5rem; }
        
        .users-table { width: 100%; border-collapse: collapse; font-size: 0.95rem; }
        .users-table th { text-align: left; padding: 1rem; background: #f8fafc; border-bottom: 1px solid var(--border); color: var(--text-muted); font-weight: 600; font-size: 0.85rem; text-transform: uppercase; }
        .users-table td { padding: 1rem; border-bottom: 1px solid var(--border); vertical-align: middle; }
        .users-table tr:hover { background: #f8fafc; }
        
        .badge { padding: 0.25rem 0.6rem; border-radius: 99px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
        .badge-admin { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
        .badge-user { background: #eff6ff; color: #2563eb; border: 1px solid #dbeafe; }
        .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
        .status-active { color: #166534; } .dot-active { background: #16a34a; }
        .status-inactive { color: #991b1b; } .dot-inactive { background: #dc2626; }
        
        .badge-self { background: #f3f4f6; color: #4b5563; font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; margin-left: 0.5rem; border: 1px solid #e5e7eb; }
        
        .btn-icon { width: 32px; height: 32px; display: inline-flex; align-items: center; justify-content: center; border-radius: 6px; border: 1px solid transparent; color: var(--text-muted); transition: all 0.2s; text-decoration: none; cursor: pointer; }
        .btn-icon:hover { background: #f1f5f9; color: var(--primary); }
        .btn-icon.danger:hover { background: #fef2f2; color: #dc2626; border-color: #fecaca; }
        .btn-icon.warning:hover { background: #fffbeb; color: #d97706; border-color: #fde68a; }
        .btn-icon.success:hover { background: #dcfce7; color: #166534; border-color: #bbf7d0; }
        
        .username-link { color: var(--text-main); font-weight: 600; text-decoration: none; display: inline-flex; align-items: center; }
        .username-link:hover { color: var(--primary); text-decoration: underline; }
        .username-link i { font-size: 0.75rem; margin-left: 0.5rem; opacity: 0.5; }

        /* Modal Styles */
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.5); display: none; justify-content: center; align-items: center; z-index: 1000; backdrop-filter: blur(2px); }
        .modal-box { background: white; width: 90%; max-width: 400px; padding: 2rem; border-radius: 12px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1); position: relative; }
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
                    <div><?php echo htmlspecialchars($_SESSION['username']); ?></div>
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
            <div class="alert alert-success" style="padding: 1rem; background: #dcfce7; color: #166534; border-radius: 8px; margin-bottom: 1.5rem;"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="alert alert-error" style="padding: 1rem; background: #fee2e2; color: #991b1b; border-radius: 8px; margin-bottom: 1.5rem;"><i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error); ?></div>
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
                                <a href="profile.php?user_id=<?php echo $user['id']; ?>" class="username-link" title="Edit Profile">
                                    <?php echo htmlspecialchars($user['username']); ?>
                                    <i class="fas fa-pen"></i>
                                </a>
                                <?php if ($user['id'] == $_SESSION['user_id']): ?>
                                    <span class="badge-self">YOU</span>
                                <?php endif; ?>
                                <div style="font-size:0.85rem; color:var(--text-muted); margin-top:2px;">
                                    <?php echo htmlspecialchars($user['email'] ?: 'No email'); ?>
                                </div>
                            </td>
                            <td>
                                <?php echo htmlspecialchars($user['full_name'] ?: '-'); ?>
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
                                <?php echo date('M d, Y', strtotime($user['created_at'])); ?>
                            </td>
                            <td style="color:var(--text-muted); font-size:0.9rem;">
                                <?php echo $user['last_login'] ? date('M d, H:i', strtotime($user['last_login'])) : 'Never'; ?>
                            </td>
                            <td style="text-align:right;">
                                <div style="display:inline-flex; gap:0.25rem;">
                                    <?php if ($user['id'] != $_SESSION['user_id']): ?>
                                        <button type="button" class="btn-icon warning" 
                                                onclick="openResetModal(<?php echo $user['id']; ?>, '<?php echo htmlspecialchars($user['username'], ENT_QUOTES); ?>')"
                                                title="Reset Password">
                                            <i class="fas fa-key"></i>
                                        </button>

                                        <?php if ($user['is_active']): ?>
                                            <a href="admin_users.php?action=deactivate&user_id=<?php echo $user['id']; ?>" class="btn-icon warning" onclick="return confirm('Deactivate this user?')" title="Deactivate"><i class="fas fa-user-slash"></i></a>
                                        <?php else: ?>
                                            <a href="admin_users.php?action=activate&user_id=<?php echo $user['id']; ?>" class="btn-icon success" onclick="return confirm('Activate this user?')" title="Activate"><i class="fas fa-user-check"></i></a>
                                        <?php endif; ?>
                                        
                                        <?php if ($user['role'] == 'user'): ?>
                                            <a href="admin_users.php?action=make_admin&user_id=<?php echo $user['id']; ?>" class="btn-icon" onclick="return confirm('Promote to Admin?')" title="Promote"><i class="fas fa-arrow-up"></i></a>
                                        <?php else: ?>
                                            <a href="admin_users.php?action=make_user&user_id=<?php echo $user['id']; ?>" class="btn-icon" onclick="return confirm('Demote to User?')" title="Demote"><i class="fas fa-arrow-down"></i></a>
                                        <?php endif; ?>
                                        
                                        <a href="admin_users.php?action=delete&user_id=<?php echo $user['id']; ?>" class="btn-icon danger" onclick="return confirm('Permanently delete?')" title="Delete"><i class="fas fa-trash"></i></a>
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
            <span class="modal-close" onclick="closeResetModal()">&times;</span>
            <div class="modal-header">
                <h3><i class="fas fa-key warning" style="color:#d97706;"></i> Reset Password</h3>
                <p style="color:var(--text-muted); font-size:0.9rem; margin-top:0.5rem;">
                    Set a new password for user: <strong id="modalUsername"></strong>
                </p>
            </div>
            
            <form method="POST" action="admin_users.php">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <input type="hidden" name="action" value="reset_password">
                <input type="hidden" name="user_id" id="modalUserId">
                
                <div class="form-group" style="margin-bottom:1.5rem;">
                    <label for="new_password" style="display:block; margin-bottom:0.5rem; font-weight:500;">New Password</label>
                    <input type="text" id="new_password" name="new_password" required placeholder="Enter new password..." style="width:100%; padding:0.75rem; border:1px solid var(--border); border-radius:6px; font-size:1rem;">
                    <small style="color:var(--text-muted); display:block; margin-top:0.25rem;">Min. 8 characters</small>
                </div>
                
                <div style="display:flex; justify-content:flex-end; gap:0.5rem;">
                    <button type="button" class="btn btn-danger" style="background:white; color:var(--text-main); border:1px solid var(--border);" onclick="closeResetModal()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Set Password</button>
                </div>
            </form>
        </div>
    </div>

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
    </script>
</body>
</html>
