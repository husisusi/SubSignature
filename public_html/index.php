<?php
// index.php
require_once 'includes/config.php';

// ---------------------------------------------------------
// 1. SECURITY HEADERS (Defense in Depth)
// ---------------------------------------------------------
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("X-XSS-Protection: 1; mode=block");

// ---------------------------------------------------------
// 2. CHECK LOGIN STATE
// ---------------------------------------------------------
if (isLoggedIn()) {
    header('Location: generator.php');
    exit;
}

$error = '';

// Generate CSRF Token if missing
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

// ---------------------------------------------------------
// 3. HANDLE LOGIN REQUEST
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    
    // Sanitize input for DB lookup (matches registration logic)
    $username_clean = sanitizeInput($username);
    
    // A. CSRF Check
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $error = "Security violation: Invalid session.";
        // Log explicit security event for CSRF
        logSecurityEventToDB($db, 'CSRF_FAILED', null, "Login attempt - IP: " . $_SERVER['REMOTE_ADDR']);
    }
    
    // B. Rate Limiting (IP-based)
    // Note: checkRateLimit() automatically logs 'RATE_LIMIT_EXCEEDED' to DB if limit is reached.
    elseif (!checkRateLimit('login_attempt', 5, 300)) { // 5 attempts per 5 mins
        $error = "Too many login attempts. Please try again in 5 minutes.";
    }
    
    // C. Account Lock Check (User-based)
    // Note: isAccountLocked() automatically logs 'ACCOUNT_LOCKED' to DB if triggered.
    elseif (isAccountLocked($db, $username_clean)) {
        $error = "Account temporarily locked due to too many failed attempts. Try again in 15 minutes.";
    }
    
    else {
        // D. Verify Credentials
        $stmt = $db->prepare("SELECT id, username, password_hash, role, full_name, email, is_active 
                             FROM users WHERE username = ?");
        $stmt->bindValue(1, $username_clean, SQLITE3_TEXT);
        $result = $stmt->execute();
        $user = $result->fetchArray(SQLITE3_ASSOC);
        
        if ($user) {
            // Check active status
            if ($user['is_active'] == 0) {
                $error = "Your account is deactivated. Please contact the administrator.";
                // Log failed attempt (reason: inactive) -> writes to DB logs
                logLoginAttempt($db, $username_clean, false);
            }
            // Verify Password
            elseif (password_verify($password, $user['password_hash'])) {
                
                // SECURITY: Regenerate Session ID to prevent Session Fixation
                session_regenerate_id(true);
                
                // Set Session Variables
                $_SESSION['loggedin'] = true;
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['role'] = $user['role'];
                $_SESSION['full_name'] = $user['full_name'];
                $_SESSION['email'] = $user['email'];
                $_SESSION['last_activity'] = time();
                
                // Refresh CSRF Token
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                
                // Log Success -> writes to DB logs (login_attempts + security_events)
                logLoginAttempt($db, $username_clean, true);
                
                header('Location: generator.php');
                exit;
                
            } else {
                // Invalid Password
                // SECURITY: Prevent Timing Attacks
                usleep(rand(100000, 300000)); 
                
                $error = 'Invalid username or password!';
                // Log Failure -> writes to DB logs
                logLoginAttempt($db, $username_clean, false);
            }
        } else {
            // User does not exist
            // SECURITY: Generic error message (Prevent User Enumeration)
            usleep(rand(100000, 300000)); 
            
            $error = 'Invalid username or password!';
            // Log Failure -> writes to DB logs
            logLoginAttempt($db, $username_clean, false);
        }
    }
    
    // Track failed attempts for frontend display (session only)
    if ($error) {
        if (!isset($_SESSION['failed_logins'])) {
            $_SESSION['failed_logins'] = 0;
        }
        $_SESSION['failed_logins']++;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - SubSignature</title>
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';">
    <link rel="stylesheet" href="css/all.min.css">
    <style>
        /* Styles kept identical for consistency */
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #e4edf5 100%);
            min-height: 100vh;
            display: flex; align-items: center; justify-content: center; padding: 20px;
        }
        .login-box {
            background: white; border-radius: 16px; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.08);
            width: 100%; max-width: 400px; padding: 40px; text-align: center; border: 1px solid #eaeaea;
        }
        .logo { font-size: 2.8rem; color: #4a6cf7; margin-bottom: 10px; }
        .logo-text { font-size: 1.8rem; font-weight: 700; color: #2c3e50; margin-bottom: 5px; letter-spacing: -0.5px; }
        .tagline { color: #718096; font-size: 0.95rem; margin-bottom: 30px; font-weight: 500; }
        .error-alert {
            background: #fff5f5; color: #c53030; padding: 12px 16px; border-radius: 10px;
            border-left: 4px solid #f56565; margin-bottom: 25px; font-size: 0.9rem;
            display: flex; align-items: center; justify-content: center; gap: 8px; text-align: left; animation: shake 0.5s;
        }
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            10%, 30%, 50%, 70%, 90% { transform: translateX(-5px); }
            20%, 40%, 60%, 80% { transform: translateX(5px); }
        }
        .success-alert {
            background: #f0fff4; color: #276749; padding: 12px 16px; border-radius: 10px;
            border-left: 4px solid #48bb78; margin-bottom: 25px; font-size: 0.9rem;
            display: flex; align-items: center; justify-content: center; gap: 8px; text-align: left;
        }
        .input-group { margin-bottom: 20px; text-align: left; }
        .input-label { display: block; color: #4a5568; font-size: 0.9rem; font-weight: 600; margin-bottom: 8px; display: flex; align-items: center; gap: 6px; }
        .input-field {
            width: 100%; padding: 14px 16px; border: 2px solid #e2e8f0; border-radius: 10px;
            font-size: 1rem; transition: all 0.2s; background: #f8fafc;
        }
        .input-field:focus { outline: none; border-color: #4a6cf7; background: white; box-shadow: 0 0 0 3px rgba(74, 108, 247, 0.1); }
        .input-field.error { border-color: #f44336; background: #fff5f5; }
        .password-wrapper { position: relative; }
        .toggle-password {
            position: absolute; right: 12px; top: 50%; transform: translateY(-50%);
            background: none; border: none; color: #a0aec0; cursor: pointer; padding: 5px;
        }
        .login-btn {
            width: 100%; background: linear-gradient(135deg, #4a6cf7 0%, #3a0ca3 100%);
            color: white; border: none; padding: 15px; border-radius: 10px; font-size: 1rem;
            font-weight: 600; cursor: pointer; transition: all 0.2s; margin-top: 10px;
            display: flex; align-items: center; justify-content: center; gap: 8px;
        }
        .login-btn:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 5px 15px rgba(74, 108, 247, 0.3); }
        .login-btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .register-link { margin-top: 20px; font-size: 0.9rem; color: #4a5568; }
        .register-link a { color: #4a6cf7; text-decoration: none; font-weight: 600; }
        .register-link a:hover { text-decoration: underline; }
        .features { margin-top: 30px; padding-top: 25px; border-top: 2px solid #f1f5f9; text-align: left; }
        .features h4 { color: #2c3e50; font-size: 1rem; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }
        .feature-list { list-style: none; }
        .feature-list li { color: #4a5568; font-size: 0.85rem; padding: 6px 0; padding-left: 24px; position: relative; }
        .feature-list li:before { content: "✓"; color: #10b981; position: absolute; left: 0; font-weight: bold; }
        .failed-attempts {
            margin-top: 10px; font-size: 0.8rem; color: #f44336; background: #ffebee;
            padding: 8px 12px; border-radius: 6px; border-left: 3px solid #f44336; display: none;
        }
        @media (max-width: 480px) { .login-box { padding: 30px 25px; } .logo { font-size: 2.4rem; } .logo-text { font-size: 1.6rem; } }
    </style>
</head>
<body>
    <div class="login-box">
        <img src="img/subsig.svg" alt="SubSignature Logo" style="height: 100px; width: auto; object-fit: contain;">
        <div class="logo-text">SubSignature</div>
        <div class="tagline">Professional Email Signatures</div>
        
        <?php if (isset($_GET['error']) && $_GET['error'] == 'Account+deactivated'): ?>
            <div class="error-alert">
                <i class="fas fa-ban"></i>
                <div><strong>Account Deactivated</strong><br>Contact administrator.</div>
            </div>
        <?php endif; ?>
        
        <?php if (isset($_GET['success']) && $_GET['success'] == 'registered'): ?>
            <div class="success-alert">
                <i class="fas fa-check-circle"></i>
                <div><strong>Registration Successful!</strong><br>Wait for activation.</div>
            </div>
        <?php endif; ?>
        
        <?php if (isset($_GET['msg']) && $_GET['msg'] == 'loggedout'): ?>
            <div class="success-alert">
                <i class="fas fa-sign-out-alt"></i>
                <div><strong>Logged Out</strong><br>See you soon.</div>
            </div>
        <?php endif; ?>
        
        <?php if (isset($_SESSION['failed_logins']) && $_SESSION['failed_logins'] > 0): ?>
            <div class="failed-attempts" id="failedAttempts">
                <i class="fas fa-exclamation-triangle"></i>
                Failed attempts: <?php echo $_SESSION['failed_logins']; ?>
            </div>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="error-alert">
                <i class="fas fa-exclamation-circle"></i>
                <div><?php echo htmlspecialchars($error); ?></div>
            </div>
        <?php endif; ?>
        
        <form method="POST" id="loginForm" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
            
            <div class="input-group">
                <label class="input-label"><i class="fas fa-user"></i> Username</label>
                <input type="text" name="username" class="input-field" placeholder="Enter username" 
                       required autofocus autocomplete="username"
                       value="<?php echo isset($_POST['username']) ? htmlspecialchars($_POST['username']) : ''; ?>"
                       id="usernameInput">
            </div>
            
            <div class="input-group">
                <label class="input-label"><i class="fas fa-lock"></i> Password</label>
                <div class="password-wrapper">
                    <input type="password" name="password" id="password" class="input-field" 
                           placeholder="Enter password" required autocomplete="current-password">
                    <button type="button" class="toggle-password" onclick="togglePassword()">
                        <i class="fas fa-eye"></i>
                    </button>
                </div>
            </div>
            
            <button type="submit" class="login-btn" id="loginBtn">
                <i class="fas fa-sign-in-alt"></i> Sign In
            </button>
        </form>
        
        <div class="register-link">
            New user? <a href="register.php">Create account</a>
        </div>
        
        <div class="features">
            <h4><i class="fas fa-star"></i> Features</h4>
            <ul class="feature-list">
                <li>Create professional signatures</li>
                <li>Multiple design templates</li>
                <li>Import/Export via CSV</li>
                <li>Secure user management</li>
                <li>Account activation system</li>
            </ul>
        </div>
    </div>
    
    <script>
    function togglePassword() {
        const password = document.getElementById('password');
        const icon = document.querySelector('.toggle-password i');
        if (password.type === 'password') {
            password.type = 'text';
            icon.className = 'fas fa-eye-slash';
        } else {
            password.type = 'password';
            icon.className = 'fas fa-eye';
        }
    }
    
    document.getElementById('loginForm').addEventListener('submit', function(e) {
        const btn = document.getElementById('loginBtn');
        const username = document.getElementById('usernameInput').value;
        const password = document.getElementById('password').value;
        
        if (!username.trim() || !password.trim()) {
            e.preventDefault();
            if(!username.trim()) document.getElementById('usernameInput').classList.add('error');
            if(!password.trim()) document.getElementById('password').classList.add('error');
            return false;
        }
        
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Signing in...';
        btn.disabled = true;
        // Re-enable button after 5 seconds to prevent spam if server is slow
        setTimeout(() => {
            btn.innerHTML = '<i class="fas fa-sign-in-alt"></i> Sign In';
            btn.disabled = false;
        }, 5000);
        return true;
    });
    
    document.getElementById('usernameInput')?.addEventListener('input', function() { this.classList.remove('error'); });
    document.getElementById('password')?.addEventListener('input', function() { this.classList.remove('error'); });
    
    document.addEventListener('DOMContentLoaded', function() {
        const usernameInput = document.getElementById('usernameInput');
        if (usernameInput) usernameInput.focus();
        
        const failedAttempts = document.getElementById('failedAttempts');
        if (failedAttempts) failedAttempts.style.display = 'block';
        
        // Simple animation for elements
        const elements = document.querySelectorAll('.input-group, .login-btn, .register-link, .features');
        elements.forEach((el, i) => {
            el.style.opacity = '0';
            el.style.transform = 'translateY(10px)';
            setTimeout(() => {
                el.style.transition = 'opacity 0.3s, transform 0.3s';
                el.style.opacity = '1';
                el.style.transform = 'translateY(0)';
            }, i * 100);
        });
        
        // Prevent double submission
        let lastSubmitTime = 0;
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            const now = Date.now();
            if (now - lastSubmitTime < 1000) {
                e.preventDefault();
                return false;
            }
            lastSubmitTime = now;
        });
    });
    
    // Auto-hide failed attempts message after 5 seconds
    setTimeout(() => {
        const failedAttempts = document.getElementById('failedAttempts');
        if (failedAttempts) {
            failedAttempts.style.transition = 'opacity 0.5s';
            failedAttempts.style.opacity = '0';
            setTimeout(() => { failedAttempts.style.display = 'none'; }, 500);
        }
    }, 5000);
    </script>
</body>
</html>
