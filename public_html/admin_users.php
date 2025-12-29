<?php
require_once 'includes/config.php';
requireAdmin();

// Actions: activate/deactivate/delete user
if (isset($_GET['action'])) {
    $user_id = (int)$_GET['user_id'];
    $action = $_GET['action'];
    
    switch ($action) {
        case 'activate':
            $stmt = $db->prepare("UPDATE users SET is_active = 1 WHERE id = ? AND id != ?");
            $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
            $stmt->bindValue(2, $_SESSION['user_id'], SQLITE3_INTEGER); // Cannot deactivate self
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
            // Cannot delete self
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

// Load all users
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
        /* Stats Grid for Dashboard */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: white;
            padding: 1.5rem;
            border-radius: 12px;
            border: 1px solid var(--border);
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            display: flex;
            flex-direction: column;
        }

        .stat-label { color: var(--text-muted); font-size: 0.85rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem; }
        .stat-value { font-size: 2rem; font-weight: 700; color: var(--text-main); }
        .stat-icon { float: right; color: var(--primary); opacity: 0.2; font-size: 2rem; margin-top: -2.5rem; }

        /* Table Specifics */
        .table-responsive {
            width: 100%;
            overflow-x: auto;
        }

        .users-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.95rem;
        }

        .users-table th {
            text-align: left;
            padding: 1rem;
            background: #f8fafc;
            border-bottom: 1px solid var(--border);
            color: var(--text-muted);
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
        }

        .users-table td {
            padding: 1rem;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
        }

        .users-table tr:last-child td { border-bottom: none; }
        .users-table tr:hover { background: #f8fafc; }

        /* Badges */
        .badge {
            padding: 0.25rem 0.6rem;
            border-radius: 99px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-admin { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
        .badge-user { background: #eff6ff; color: #2563eb; border: 1px solid #dbeafe; }
        
        .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
        .status-active { color: #166534; } .dot-active { background: #16a34a; }
        .status-inactive { color: #991b1b; } .dot-inactive { background: #dc2626; }

        .badge-self {
            background: #f3f4f6; color: #4b5563; 
            font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; 
            margin-left: 0.5rem; border: 1px solid #e5e7eb;
        }

        /* Action Buttons in Table */
        .btn-icon {
            width: 32px;
            height: 32px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            border-radius: 6px;
            border: 1px solid transparent;
            color: var(--text-muted);
            transition: all 0.2s;
            text-decoration: none;
        }
        .btn-icon:hover { background: #f1f5f9; color: var(--primary); }
        .btn-icon.danger:hover { background: #fef2f2; color: #dc2626; border-color: #fecaca; }
        .btn-icon.warning:hover { background: #fffbeb; color: #d97706; border-color: #fde68a; }
        .btn-icon.success:hover { background: #dcfce7; color: #166534; border-color: #bbf7d0; }

        /* Header Actions */
        .page-header-actions {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
        }
        
        @media (max-width: 768px) {
            .page-header-actions { flex-direction: column; align-items: flex-start; gap: 1rem; }
        }
    </style>
</head>
<body>

    <aside class="sidebar">

<?php include 'includes/navbar.php'; ?>

        <div class="sidebar-footer">
            <div class="user-profile">
                <div class="avatar">
                    <?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?>
                </div>
                <div class="user-info">
                    <div><?php echo htmlspecialchars($_SESSION['username']); ?></div>
                    <span>Administrator</span>
                </div>
            </div>
            <a href="logout.php" class="btn-logout">
                <i class="fas fa-sign-out-alt"></i> <span>Sign Out</span>
            </a>
        </div>
    </aside>

    <main class="main-content">
        
        <div class="page-header-actions">
            <header>
                <h2 style="font-size:1.8rem; font-weight:700; color:var(--text-main);">User Management</h2>
                <p style="color:var(--text-muted);">Manage system access and roles.</p>
            </header>
            
            <a href="register.php?admin=1" class="btn btn-primary">
                <i class="fas fa-user-plus"></i> Create New User
            </a>
        </div>

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
                            <th>User</th>
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
                                <div style="font-weight:600; color:var(--text-main);">
                                    <?php echo htmlspecialchars($user['username']); ?>
                                    <?php if ($user['id'] == $_SESSION['user_id']): ?>
                                        <span class="badge-self">YOU</span>
                                    <?php endif; ?>
                                </div>
                                <div style="font-size:0.85rem; color:var(--text-muted);">
                                    <?php echo htmlspecialchars($user['email'] ?: 'No email'); ?>
                                </div>
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
                                    <div class="status-active">
                                        <span class="status-dot dot-active"></span> Active
                                    </div>
                                <?php else: ?>
                                    <div class="status-inactive">
                                        <span class="status-dot dot-inactive"></span> Inactive
                                    </div>
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
                                        <?php if ($user['is_active']): ?>
                                            <a href="admin_users.php?action=deactivate&user_id=<?php echo $user['id']; ?>" 
                                               class="btn-icon warning" 
                                               onclick="return confirm('Deactivate this user?')"
                                               title="Deactivate User">
                                                <i class="fas fa-user-slash"></i>
                                            </a>
                                        <?php else: ?>
                                            <a href="admin_users.php?action=activate&user_id=<?php echo $user['id']; ?>" 
                                               class="btn-icon success"
                                               onclick="return confirm('Activate this user?')"
                                               title="Activate User">
                                                <i class="fas fa-user-check"></i>
                                            </a>
                                        <?php endif; ?>
                                        
                                        <?php if ($user['role'] == 'user'): ?>
                                            <a href="admin_users.php?action=make_admin&user_id=<?php echo $user['id']; ?>" 
                                               class="btn-icon"
                                               onclick="return confirm('Make this user an administrator?')"
                                               title="Promote to Admin">
                                                <i class="fas fa-arrow-up"></i>
                                            </a>
                                        <?php else: ?>
                                            <a href="admin_users.php?action=make_user&user_id=<?php echo $user['id']; ?>" 
                                               class="btn-icon"
                                               onclick="return confirm('Remove admin privileges?')"
                                               title="Demote to User">
                                                <i class="fas fa-arrow-down"></i>
                                            </a>
                                        <?php endif; ?>
                                        
                                        <a href="admin_users.php?action=delete&user_id=<?php echo $user['id']; ?>" 
                                           class="btn-icon danger"
                                           onclick="return confirm('Permanently delete this user and all their signatures?')"
                                           title="Delete User">
                                            <i class="fas fa-trash"></i>
                                        </a>
                                    <?php else: ?>
                                        <span style="font-size:0.85rem; color:var(--text-muted); padding:0 0.5rem;">Current User</span>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </section>
        
        <div class="card" style="background:#f8fafc; border:1px dashed var(--border); box-shadow:none;">
            <h3 style="font-size:1rem; margin-bottom:0.5rem;"><i class="fas fa-info-circle"></i> Notes</h3>
            <ul style="margin:0; padding-left:1.5rem; color:var(--text-muted); font-size:0.9rem;">
                <li>Administrators have full access to templates and user management.</li>
                <li>Deactivated users cannot log in, but their signatures remain in the database.</li>
                <li>You cannot delete or deactivate your own account.</li>
            </ul>
        </div>

    </main>

</body>
</html>
