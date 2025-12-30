<?php
// profile.php

// 1. Include Configuration & Security
require_once 'includes/config.php';
requireLogin();

// 2. CSRF Protection
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ---------------------------------------------------------
// 3. DETERMINE TARGET USER (Security Critical)
// ---------------------------------------------------------
$current_user_id = $_SESSION['user_id']; // The person logged in
$target_user_id = $current_user_id;       // Default: Edit self

$is_admin_editing_others = false;

// Check if an ID is requested via URL (e.g., profile.php?user_id=5)
if (isset($_GET['user_id'])) {
    $requested_id = (int)$_GET['user_id'];
    
    // SECURITY CHECK: Only Admins can edit other users
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
    
    // CSRF Check
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('Error: Invalid CSRF token. Please refresh the page and try again.');
    }

    $full_name = trim($_POST['full_name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    
    // Basic Validation
    if (!empty($email) && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Invalid email address!";
    } else {
        // Secure Update
        $stmt = $db->prepare("UPDATE users SET full_name = ?, email = ? WHERE id = ?");
        $stmt->bindValue(1, $full_name, SQLITE3_TEXT);
        $stmt->bindValue(2, $email, SQLITE3_TEXT);
        $stmt->bindValue(3, $target_user_id, SQLITE3_INTEGER); // Use target_user_id
        
        if ($stmt->execute()) {
            // Only update SESSION vars if editing SELF
            if (!$is_admin_editing_others) {
                $_SESSION['full_name'] = $full_name;
                $_SESSION['email'] = $email;
                $success = "✅ Profile updated successfully!";
            } else {
                $success = "✅ User profile updated successfully (Admin Mode).";
            }
        } else {
            $error = "❌ Failed to update profile!";
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
        header('Location: admin_users.php?error=UserNotFound'); // Admin fallback
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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $is_admin_editing_others ? 'Edit User' : 'My Profile'; ?> - SubSignature</title>
    
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/all.min.css">
    
    <style>
        /* Profile Specific Styles */
        .profile-layout { display: grid; grid-template-columns: 2fr 1fr; gap: 2rem; }
        .profile-card { background: white; border-radius: 12px; border: 1px solid var(--border); overflow: hidden; display: flex; flex-direction: column; }
        .profile-header { background: linear-gradient(135deg, #f3f4f6 0%, #ffffff 100%); padding: 2rem; text-align: center; border-bottom: 1px solid var(--border); }
        .profile-avatar { width: 80px; height: 80px; background: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 2.5rem; color: var(--primary); margin: 0 auto 1rem; box-shadow: 0 4px 12px rgba(0,0,0,0.08); border: 2px solid white; }
        .profile-name { font-size: 1.4rem; font-weight: 700; color: var(--text-main); margin-bottom: 0.25rem; }
        .profile-role { color: var(--text-muted); font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; }
        .stats-list { padding: 1.5rem; }
        .stat-row { display: flex; justify-content: space-between; padding: 0.75rem 0; border-bottom: 1px solid var(--border); font-size: 0.95rem; }
        .stat-row:last-child { border-bottom: none; }
        .stat-key { color: var(--text-muted); display: flex; align-items: center; gap: 0.5rem; }
        .stat-val { font-weight: 600; color: var(--text-main); }
        .action-list { display: flex; flex-direction: column; gap: 0.75rem; padding: 1.5rem; background: #f8fafc; border-top: 1px solid var(--border); }
        .action-btn { display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem 1rem; background: white; border: 1px solid var(--border); border-radius: 8px; color: var(--text-main); text-decoration: none; font-weight: 500; transition: all 0.2s; }
        .action-btn:hover { border-color: var(--primary); color: var(--primary); transform: translateX(4px); }
        .action-btn i { width: 20px; text-align: center; color: var(--text-muted); }
        .action-btn:hover i { color: var(--primary); }
        .settings-card { background: white; border-radius: 12px; border: 1px solid var(--border); padding: 2rem; }
        
        .admin-banner {
            grid-column: 1 / -1;
            background: #fff7ed; border: 1px solid #fed7aa; color: #c2410c;
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
            <div class="user-profile">
                <div class="avatar"><?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?></div>
                <div class="user-info">
                    <div><?php echo htmlspecialchars($_SESSION['username'], ENT_QUOTES, 'UTF-8'); ?></div>
                    <span><?php echo isAdmin() ? 'Administrator' : 'User'; ?></span>
                </div>
            </div>
            <a href="logout.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> <span>Sign Out</span></a>
        </div>
    </aside>

    <main class="main-content">
        
        <header class="page-header">
            <?php if ($is_admin_editing_others): ?>
                <h2>Edit User: <?php echo htmlspecialchars($user['username']); ?></h2>
                <p>Administrator Mode: Editing another user's profile.</p>
            <?php else: ?>
                <h2>My Profile</h2>
                <p>Manage your account settings and personal information.</p>
            <?php endif; ?>
        </header>

        <div class="profile-layout">
            
            <?php if ($is_admin_editing_others): ?>
            <div class="admin-banner">
                <i class="fas fa-exclamation-triangle"></i>
                <div>
                    <strong>Admin Mode Active:</strong> You are editing the profile of 
                    <u><?php echo htmlspecialchars($user['username']); ?></u> (ID: <?php echo $target_user_id; ?>).
                    <a href="admin_users.php" style="color:inherit; font-weight:700; margin-left:10px;">Back to List</a>
                </div>
            </div>
            <?php endif; ?>

            <div class="settings-card">
                <h3 style="margin-bottom: 1.5rem; display: flex; align-items: center; gap: 0.5rem;">
                    <i class="fas fa-user-edit"></i> Edit Details
                </h3>

                <?php if ($success): ?>
                    <div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?></div>
                <?php endif; ?>
                <?php if ($error): ?>
                    <div class="alert alert-error"><i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error); ?></div>
                <?php endif; ?>

                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" 
                               value="<?php echo htmlspecialchars($user['username'], ENT_QUOTES, 'UTF-8'); ?>" 
                               disabled style="background: #f3f4f6; color: var(--text-muted);">
                        <small style="color: var(--text-muted);">Username cannot be changed.</small>
                    </div>

                    <div class="form-group">
                        <label for="full_name">Full Name</label>
                        <input type="text" id="full_name" name="full_name" 
                               value="<?php echo htmlspecialchars($user['full_name'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                               placeholder="e.g. John Doe">
                    </div>

                    <div class="form-group">
                        <label for="email">Email Address</label>
                        <input type="email" id="email" name="email" 
                               value="<?php echo htmlspecialchars($user['email'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                               placeholder="john@example.com">
                    </div>

                    <div class="form-group">
                        <label>Role</label>
                        <input type="text" value="<?php echo htmlspecialchars(ucfirst($user['role']), ENT_QUOTES, 'UTF-8'); ?>" 
                               disabled style="background: #f3f4f6; color: var(--text-muted);">
                    </div>

                    <div class="form-actions">
                        <button type="submit" name="update_profile" class="btn btn-primary">
                            <i class="fas fa-save"></i> Save Changes
                        </button>
                    </div>
                </form>
            </div>

            <div class="profile-card">
                <div class="profile-header">
                    <div class="profile-avatar"><?php echo strtoupper(substr($user['username'], 0, 1)); ?></div>
                    <div class="profile-name"><?php echo htmlspecialchars($user['full_name'] ?: $user['username']); ?></div>
                    <div class="profile-role"><?php echo htmlspecialchars($user['role']); ?></div>
                </div>

                <div class="stats-list">
                    <div class="stat-row">
                        <span class="stat-key"><i class="fas fa-calendar-alt"></i> Joined</span>
                        <span class="stat-val"><?php echo date('M Y', strtotime($user['created_at'])); ?></span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-key"><i class="fas fa-clock"></i> Last Login</span>
                        <span class="stat-val"><?php echo $user['last_login'] ? date('d.m.Y', strtotime($user['last_login'])) : 'Never'; ?></span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-key"><i class="fas fa-signature"></i> Signatures</span>
                        <span class="stat-val"><?php echo $sig_count; ?></span>
                    </div>
                </div>

                <div class="action-list">
                    <?php if (!$is_admin_editing_others): ?>
                        <a href="change_password.php" class="action-btn"><i class="fas fa-key"></i> Change Password</a>
                        <a href="csv_import.php" class="action-btn"><i class="fas fa-file-import"></i> Import Data</a>
                    <?php else: ?>
                        <div style="text-align:center; padding:0.5rem; color:var(--text-muted); font-size:0.85rem;">
                            To reset password, use the Admin User List.
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </main>
</body>
</html>
