<?php
// change_password.php

// 1. Include Configuration & Security
require_once 'includes/config.php';
requireLogin();

// 2. Security Headers
// Prevent this page from being loaded in an iframe (Clickjacking protection)
header('X-Frame-Options: DENY');

$message = '';
$error = '';

// 3. CSRF Protection Initialization
// Ensure a token exists for the session
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 4. Verify CSRF Token
    // This prevents attackers from forging a password change request from another site.
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Security Error: Invalid CSRF Token. Please refresh the page.");
    }

    // Get inputs (do not trim passwords as spaces can be valid characters in phrases)
    $current_password = $_POST['current_password'] ?? '';
    $new_password = $_POST['new_password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    
    // 5. Enforce Password Complexity Policies
    if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
        $error = "All fields are required!";
    } elseif ($new_password !== $confirm_password) {
        $error = "New passwords do not match!";
    } elseif (strlen($new_password) < 8) {
        $error = "Password must be at least 8 characters long!";
    } elseif (!preg_match("/[A-Z]/", $new_password) || !preg_match("/[a-z]/", $new_password) || !preg_match("/[0-9]/", $new_password)) {
        $error = "Password must contain uppercase, lowercase letters, and numbers!";
    } else {
        // 6. Verify Current Password
        $stmt = $db->prepare("SELECT id, password_hash FROM users WHERE id = ?");
        $stmt->bindValue(1, $_SESSION['user_id'], SQLITE3_INTEGER);
        $result = $stmt->execute();
        $user = $result->fetchArray(SQLITE3_ASSOC);
        
        if ($user && password_verify($current_password, $user['password_hash'])) {
            // Hash new password securely
            $new_hash = password_hash($new_password, PASSWORD_DEFAULT);
            
            // Update database
            $update_stmt = $db->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
            $update_stmt->bindValue(1, $new_hash, SQLITE3_TEXT);
            $update_stmt->bindValue(2, $_SESSION['user_id'], SQLITE3_INTEGER);
            
            if ($update_stmt->execute()) {
                $message = "✅ Password successfully changed!";
                
                // 7. CRITICAL: Prevent Session Fixation
                // Regenerate session ID after privilege level change.
                session_regenerate_id(true);
            } else {
                $error = "❌ Database error! Could not update password.";
            }
        } else {
            // 8. Rate Limiting (Anti-Brute-Force)
            // If the current password was wrong, sleep for ~1 second.
            // This prevents automated tools from guessing the current password rapidly.
            usleep(rand(500000, 1500000));
            
            $error = "❌ Current password is incorrect!";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Change Password - SubSignature</title>
    
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/all.min.css">    
    
    <style>
        /* CSS remains exactly as original */
        .password-strength-container {
            margin-top: 0.5rem;
            background: #f1f5f9;
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
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            border-radius: 8px;
            padding: 1.5rem;
            margin-top: 2rem;
        }
        .security-tips h4 {
            color: #166534;
            margin-bottom: 0.75rem;
            font-size: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .security-tips ul {
            padding-left: 1.25rem;
            margin: 0;
            color: #15803d;
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
            <div class="user-profile">
                <div class="avatar">
                    <?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?>
                </div>
                <div class="user-info">
                    <div><?php echo htmlspecialchars($_SESSION['username'], ENT_QUOTES, 'UTF-8'); ?></div>
                    <span><?php echo isAdmin() ? 'Administrator' : 'User'; ?></span>
                </div>
            </div>
            <a href="logout.php" class="btn-logout">
                <i class="fas fa-sign-out-alt"></i> <span>Sign Out</span>
            </a>
        </div>
    </aside>

    <main class="main-content">
        
        <header class="page-header">
            <h2>Change Password</h2>
            <p>Update your credentials to keep your account secure.</p>
        </header>

        <?php if ($message): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="alert alert-error">
                <i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>

        <div class="form-grid" style="grid-template-columns: 2fr 1fr; gap: 2rem;">
            
            <section class="card">
                <div class="card-header">
                    <h3><i class="fas fa-lock"></i> Security Credentials</h3>
                </div>

                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

                    <div class="form-group">
                        <label for="current_password">Current Password</label>
                        <input type="password" id="current_password" name="current_password" required>
                    </div>

                    <div style="margin: 1.5rem 0; border-bottom: 1px solid var(--border);"></div>

                    <div class="form-group">
                        <label for="new_password">New Password</label>
                        <div class="input-with-icon">
                            <input type="password" id="new_password" name="new_password" required 
                                   oninput="checkStrength(this.value)">
                            <i class="fas fa-eye toggle-password" onclick="togglePass('new_password')"></i>
                        </div>
                        
                        <div class="password-strength-container">
                            <div id="strengthBar" class="strength-bar"></div>
                        </div>
                        <span id="strengthText" class="strength-label">Enter new password</span>
                    </div>

                    <div class="form-group">
                        <label for="confirm_password">Confirm New Password</label>
                        <div class="input-with-icon">
                            <input type="password" id="confirm_password" name="confirm_password" required oninput="checkMatch()">
                             <i class="fas fa-eye toggle-password" onclick="togglePass('confirm_password')"></i>
                        </div>
                        <span id="matchText" class="strength-label" style="text-align:left;"></span>
                    </div>

                    <div class="form-actions">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save"></i> Update Password
                        </button>
                        <a href="profile.php" class="btn btn-danger" style="background:white; color:var(--text-main); border:1px solid var(--border)">
                            Cancel
                        </a>
                    </div>
                </form>
            </section>

            <div>
                <div class="security-tips">
                    <h4><i class="fas fa-shield-alt"></i> Password Guidelines</h4>
                    <ul>
                        <li>At least 8 characters long</li>
                        <li>Include uppercase & lowercase letters</li>
                        <li>Include at least one number</li>
                        <li>Avoid using your name or email</li>
                    </ul>
                </div>
                
                <div class="card" style="margin-top: 1.5rem; text-align: center; padding: 1.5rem;">
                    <i class="fas fa-key" style="font-size: 2.5rem; color: #cbd5e1; margin-bottom: 1rem;"></i>
                    <p style="color: var(--text-muted); font-size: 0.9rem;">
                        Changing your password will not affect existing signatures, but you will need to use the new password for your next login.
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
            text.textContent = 'Weak';
            text.style.color = '#ef4444';
        } else if (strength < 75) {
            bar.style.backgroundColor = '#f59e0b';
            text.textContent = 'Medium';
            text.style.color = '#f59e0b';
        } else {
            bar.style.backgroundColor = '#10b981';
            text.textContent = 'Strong';
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
            text.textContent = '✓ Passwords match';
            text.style.color = '#10b981';
        } else {
            text.textContent = 'Passwords do not match';
            text.style.color = '#ef4444';
        }
    }
    </script>
</body>
</html>
