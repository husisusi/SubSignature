<?php
// login.php
require_once 'includes/config.php';

// SICHERHEIT: CSRF Token generieren, falls nicht vorhanden
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// 1. Session Hijacking Protection
if (isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true) {
    header('Location: generator.php');
    exit;
}

$error = '';

// 2. Login Handling
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // SICHERHEIT: CSRF Prüfung
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('Ungültiger Sicherheits-Token. Bitte Seite neu laden.');
    }

    $password = $_POST['password'] ?? '';
    
    // 3. Database Query
    $stmt = $db->prepare("SELECT id, password_hash FROM users WHERE username = 'admin'");
    $result = $stmt->execute();
    $user = $result->fetchArray(SQLITE3_ASSOC);
    
    // 4. Verify Password
    if ($user && password_verify($password, $user['password_hash'])) {
        
        // CRITICAL SECURITY STEP: Prevent Session Fixation
        session_regenerate_id(true);
        
        // Set Session Variables
        $_SESSION['loggedin'] = true;
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = 'admin';
        
        // Token erneuern nach Login (Best Practice)
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        
        // Redirect
        header('Location: generator.php');
        exit;
    } else {
        // 5. Anti-Brute-Force Delay
        usleep(rand(500000, 1500000));
        $error = 'Invalid password!';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Signature Generator - Login</title>
    <?php header('X-Frame-Options: DENY'); ?>
    <link rel="stylesheet" href="css/style.css">
</head>
<body class="login-page">
    <div class="login-container">
        <h1>🔐 Signature Generator</h1>
        
        <?php if ($error): ?>
            <div class="alert alert-error">
                <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>
        
        <form method="POST" class="login-form">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required 
                       placeholder="Enter your password">
            </div>
            
            <button type="submit" class="btn btn-primary">Login</button>
            
            <div class="login-hints" style="display:none;">
                </div>
        </form>
        
        <div class="login-info">
            <h4>📝 Need help?</h4>
            <ul>
                <li>Please contact the system administrator.</li>
            </ul>
        </div>
    </div>
    
    <style>
    /* CSS bleibt exakt gleich */
    .login-page {
        display: flex;
        align-items: center;
        justify-content: center;
        min-height: 100vh;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    .login-container {
        background: white;
        padding: 3rem;
        border-radius: 20px;
        box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        width: 100%;
        max-width: 400px;
    }
    .login-form { margin: 2rem 0; }
    .form-group { margin-bottom: 1.5rem; }
    .form-group label { display: block; margin-bottom: 0.5rem; font-weight: 600; color: #333; }
    .form-group input {
        width: 100%; padding: 0.75rem; border: 2px solid #dee2e6; border-radius: 8px; font-size: 1rem; transition: border-color 0.3s;
    }
    .form-group input:focus { outline: none; border-color: #4361ee; box-shadow: 0 0 0 3px rgba(67, 97, 238, 0.2); }
    .btn {
        width: 100%; padding: 0.75rem; background: #4361ee; color: white; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: background 0.3s;
    }
    .btn:hover { background: #3a0ca3; }
    .alert { padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; }
    .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
    .login-info { margin-top: 2rem; padding: 1rem; background: #e9f7fe; border-radius: 8px; border-left: 4px solid #17a2b8; }
    .login-info ul { margin: 0.5rem 0 0 1.5rem; font-size: 0.9rem; }
    .login-info li { margin-bottom: 0.25rem; }
    @media (max-width: 480px) { .login-container { margin: 1rem; padding: 2rem; } }
    </style>
</body>
</html>
