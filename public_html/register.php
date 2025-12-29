<?php
// register.php

// 1. Include Configuration
require_once 'includes/config.php';

// 2. Determine Context: Is this an Admin creating a user?
// We strictly check the session role to prevent privilege escalation.
$is_admin_session = (isset($_SESSION['role']) && $_SESSION['role'] === 'admin');
$admin_create_mode = (isset($_GET['admin']) && $_GET['admin'] == 1);

// Only allow admin mode if the user is actually an admin
$admin_create = $is_admin_session && $admin_create_mode;

// 3. Security: Access Control
// If a user is logged in but NOT an admin, they should not see the public registration page
// (redirect to dashboard) nor the admin creation page.
if (isLoggedIn() && !$is_admin_session) {
    header('Location: generator.php');
    exit;
}

// 4. Rate Limiting (Public Registration Only)
// Protects against bot spam and brute-force account creation.
if (!$is_admin_session) {
    // Ensure the function exists, otherwise deny access for security default
    if (function_exists('checkRateLimit')) {
        if (!checkRateLimit('registration', 5, 900)) {  
            // 429 Too Many Requests
            http_response_code(429);  
            die("Security Warning: Too many registration attempts. Please try again later.");
        }
    }
}

// Security Headers
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');

$error = '';
$success = '';
$username = '';
$email = '';
$full_name = '';

// 5. Form Processing
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF Protection
    if (empty($_POST['csrf_token']) || empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Security Error: Invalid CSRF token. Please refresh the page.");
    }

    // Input Sanitization
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? ''; // Don't trim passwords
    $confirm_password = $_POST['confirm_password'] ?? '';
    $email = trim($_POST['email'] ?? '');
    $full_name = trim($_POST['full_name'] ?? '');
    
    // Validation
    if (empty($username) || empty($password) || empty($confirm_password)) {
        $error = "All mandatory fields are required.";
    } elseif (!preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username)) {
        $error = "Username must be 3-20 characters (letters, numbers, underscores only).";
    } elseif ($password !== $confirm_password) {
        $error = "Passwords do not match.";
    } elseif (strlen($password) < 8) {
        $error = "Password must be at least 8 characters long.";
    } elseif (!preg_match("/[A-Z]/", $password) || !preg_match("/[a-z]/", $password) || !preg_match("/[0-9]/", $password)) {
        $error = "Password must contain uppercase, lowercase letters and numbers.";
    } elseif (!empty($email) && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Invalid email address format.";
    }
    
    // Database Interaction
    if (empty($error)) {
        try {
            // Check availability using Prepared Statement
            $stmt = $db->prepare("SELECT count(*) as count FROM users WHERE username = ? OR (email = ? AND email != '')");
            $stmt->bindValue(1, $username, SQLITE3_TEXT);
            $stmt->bindValue(2, $email, SQLITE3_TEXT);
            $result = $stmt->execute();
            $row = $result->fetchArray(SQLITE3_ASSOC);
            
            if ($row['count'] > 0) {
                // Delay response slightly to mitigate timing attacks (User Enumeration)
                usleep(rand(100000, 300000));  
                $error = "Username or Email already exists.";
            } else {
                // Hash Password Securely
                $password_hash = password_hash($password, PASSWORD_DEFAULT);
                
                // Determine Account Status
                // Default: Inactive (0) for public registration
                $is_active = 0;  
                
                // If Admin creates user: Default to Active (1), or use selection
                if ($admin_create) {
                    $is_active = isset($_POST['user_status']) ? (int)$_POST['user_status'] : 1;
                }
                
                // Transaction for Data Integrity
                $db->exec('BEGIN');

                // 1. Insert User
                $stmt = $db->prepare("INSERT INTO users (username, password_hash, email, full_name, role, is_active, created_at)  
                                      VALUES (?, ?, ?, ?, 'user', ?, datetime('now'))");
                $stmt->bindValue(1, $username, SQLITE3_TEXT);
                $stmt->bindValue(2, $password_hash, SQLITE3_TEXT);
                $stmt->bindValue(3, $email, SQLITE3_TEXT);
                $stmt->bindValue(4, $full_name, SQLITE3_TEXT);
                $stmt->bindValue(5, $is_active, SQLITE3_INTEGER);
                
                if ($stmt->execute()) {
                    $user_id = $db->lastInsertRowID();
                    
                    // 2. Create default settings entry (Now using Prepared Statement for consistency)
                    $stmtSettings = $db->prepare("INSERT INTO user_settings (user_id) VALUES (?)");
                    $stmtSettings->bindValue(1, $user_id, SQLITE3_INTEGER);
                    $stmtSettings->execute();
                    
                    $db->exec('COMMIT'); // Commit changes
                    
                    if ($admin_create) {
                        $success = "User " . htmlspecialchars($username, ENT_QUOTES, 'UTF-8') . " created successfully.";
                    } else {
                        // Public message: Must wait for approval
                        $success = "Account created! Please wait for administrator approval.";
                    }
                    
                    // Clear fields on success
                    $username = $email = $full_name = '';
                    
                } else {
                    $db->exec('ROLLBACK');
                    $error = "Database error during registration.";
                }
            }
        } catch (Exception $e) {
            // Rollback if transaction is active
            $db->exec('ROLLBACK');
            // Log the actual error internally, show generic error to user
            error_log("Registration error: " . $e->getMessage());
            $error = "System error occurred. Please try again.";
        }
    }
}

// Generate new CSRF Token if none exists
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $admin_create ? 'Create User' : 'Register'; ?> - SubSignature</title>
    
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/all.min.css">    
    
    <style>
        /* Styles remain exactly as in original */
        .register-body {
            background: linear-gradient(135deg, #f5f7fa 0%, #e4edf5 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
        }
        
        .register-card {
            background: white;
            padding: 2.5rem;
            border-radius: 16px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.08);
            width: 100%;
            max-width: 480px;
            border: 1px solid var(--border);
        }

        .strength-meter {
            height: 4px;
            background: #e2e8f0;
            border-radius: 2px;
            margin-top: 0.5rem;
            overflow: hidden;
        }
        .strength-fill {
            height: 100%;
            width: 0%;
            transition: all 0.3s;
        }
        .strength-text {
            font-size: 0.75rem;
            margin-top: 0.25rem;
            text-align: right;
        }

        .password-group { position: relative; }
        .toggle-password {
            position: absolute;
            right: 12px;
            top: 42px;
            color: #94a3b8;
            cursor: pointer;
            z-index: 10;
        }
        .toggle-password:hover { color: var(--primary); }

        .auth-footer { margin-top: 1.5rem; text-align: center; font-size: 0.9rem; color: var(--text-muted); }
        .auth-footer a { color: var(--primary); text-decoration: none; font-weight: 600; }
        
        .status-toggle-wrapper {
            background: #f8fafc;
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
                <div class="user-profile">
                    <div class="avatar">
                        <?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?>
                    </div>
                    <div class="user-info">
                        <div><?php echo htmlspecialchars($_SESSION['username'], ENT_QUOTES, 'UTF-8'); ?></div>
                        <span>Administrator</span>
                    </div>
                </div>
                <a href="logout.php" class="btn-logout">
                    <i class="fas fa-sign-out-alt"></i> <span>Sign Out</span>
                </a>
            </div>
        </aside>

        <main class="main-content">
            <header class="page-header">
                <h2>Create User</h2>
                <p>Manually register a new user account.</p>
            </header>
    <?php endif; ?>

    <div class="<?php echo $admin_create ? 'card' : 'register-card'; ?>">
        
        <?php if (!$admin_create): ?>
            <div style="text-align: center; margin-bottom: 2rem;">
                <div style="margin-bottom: 1rem;">
                    <img src="img/subsig.svg" alt="SubSignature Logo" style="height: 100px; width: auto; object-fit: contain;">
                </div>
                <h2 style="font-size:1.5rem;">Create Account</h2>
                <p style="color:var(--text-muted);">Join SubSignature today</p>
            </div>
        <?php endif; ?>

        <?php if ($success): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success, ENT_QUOTES, 'UTF-8'); ?>
            </div>
            
            <div style="margin-top: 1.5rem; text-align: center;">
                <?php if ($admin_create): ?>
                    <a href="admin_users.php" class="btn btn-secondary">Back to User List</a>
                    <a href="register.php?admin=1" class="btn btn-primary">Create Another</a>
                <?php else: ?>
                    <a href="index.php" class="btn btn-primary" style="width:100%">Go to Login</a>
                <?php endif; ?>
            </div>
        <?php else: ?>  
            
            <?php if ($error): ?>
                <div class="alert alert-error">
                    <i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?>
                </div>
            <?php endif; ?>

            <form method="POST" id="regForm" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                
                <?php if ($admin_create): ?>
                <div class="status-toggle-wrapper">
                    <div class="form-group" style="margin-bottom:0;">
                        <label for="user_status">Initial Account Status</label>
                        <select name="user_status" id="user_status" style="width:100%; padding:0.6rem; border:1px solid var(--border); border-radius:6px;">
                            <option value="1" selected>Active (Can login immediately)</option>
                            <option value="0">Inactive (Requires activation)</option>
                        </select>
                    </div>
                </div>
                <?php endif; ?>

                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required  
                           value="<?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?>"
                           placeholder="johndoe" pattern="[a-zA-Z0-9_]{3,20}"
                           autocomplete="off">
                    <small style="color:var(--text-muted); font-size:0.75rem;">3-20 chars, letters/numbers only.</small>
                </div>

                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="email" id="email" name="email"  
                           value="<?php echo htmlspecialchars($email, ENT_QUOTES, 'UTF-8'); ?>"
                           placeholder="john@example.com">
                </div>

                <div class="form-group">
                    <label for="full_name">Full Name</label>
                    <input type="text" id="full_name" name="full_name"  
                           value="<?php echo htmlspecialchars($full_name, ENT_QUOTES, 'UTF-8'); ?>"
                           placeholder="John Doe">
                </div>

                <div class="form-group password-group">
                    <label for="password">Password</label>
                    <i class="fas fa-eye toggle-password" onclick="togglePass('password')"></i>
                    <input type="password" id="password" name="password" required  
                           placeholder="Min. 8 chars" oninput="checkStrength(this.value)"
                           autocomplete="new-password">
                    
                    <div class="strength-meter">
                        <div class="strength-fill" id="strengthBar"></div>
                    </div>
                    <div class="strength-text" id="strengthText">Enter password</div>
                </div>

                <div class="form-group password-group">
                    <label for="confirm_password">Confirm Password</label>
                    <i class="fas fa-eye toggle-password" onclick="togglePass('confirm_password')"></i>
                    <input type="password" id="confirm_password" name="confirm_password" required  
                           placeholder="Repeat password">
                </div>

                <div class="form-actions" style="margin-top: 2rem;">
                    <button type="submit" class="btn btn-primary" style="width:100%;">
                        <?php echo $admin_create ? 'Create User' : 'Register Account'; ?>
                    </button>
                </div>

                <?php if (!$admin_create): ?>
                    <div class="auth-footer">
                        Already have an account? <a href="index.php">Log In</a>
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
            if (type === 'text') {
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
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
            case 0:
            case 1:
                bar.style.width = '25%'; bar.style.backgroundColor = '#ef4444';
                text.textContent = 'Weak'; text.style.color = '#ef4444';
                break;
            case 2:
                bar.style.width = '50%'; bar.style.backgroundColor = '#f59e0b';
                text.textContent = 'Fair'; text.style.color = '#f59e0b';
                break;
            case 3:
                bar.style.width = '75%'; bar.style.backgroundColor = '#3b82f6';
                text.textContent = 'Good'; text.style.color = '#3b82f6';
                break;
            case 4:
                bar.style.width = '100%'; bar.style.backgroundColor = '#10b981';
                text.textContent = 'Strong'; text.style.color = '#10b981';
                break;
        }
    }

    const form = document.getElementById('regForm');
    if (form) {
        form.addEventListener('submit', function(e) {
            const p1 = document.getElementById('password').value;
            const p2 = document.getElementById('confirm_password').value;
            if (p1 !== p2) {
                e.preventDefault();
                alert('Passwords do not match!');
            }
        });
    }
    </script>
</body>
</html>
