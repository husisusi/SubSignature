<?php
// generate.php

// 1. Load Configuration & Security Context
require_once 'includes/config.php';
requireLogin();

// 2. Handle Deletion
// Note: Ideally, state-changing actions like DELETE should use POST/DELETE methods to prevent CSRF.
// However, to maintain UI compatibility with existing links, we keep GET but ensure strict ownership checks.
if (isset($_GET['delete'])) {
    $signature_id = (int)$_GET['delete'];
    $user_id = $_SESSION['user_id'];
    
    // Security Optimization: 
    // Instead of SELECT then DELETE, we execute a single DELETE statement with the user_id condition.
    // This ensures atomic execution and that users can ONLY delete their own signatures.
    $stmt = $db->prepare("DELETE FROM user_signatures WHERE id = ? AND user_id = ?");
    $stmt->bindValue(1, $signature_id, SQLITE3_INTEGER);
    $stmt->bindValue(2, $user_id, SQLITE3_INTEGER);
    $stmt->execute();
    
    header('Location: generator.php');
    exit;
}

// 3. Handle Generation & Saving
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitize and trim inputs
    $name = trim($_POST['name'] ?? '');
    $role = trim($_POST['role'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $phone = trim($_POST['phone'] ?? '');
    $template = $_POST['template'] ?? 'signature_default.html';
    $action = $_POST['action'] ?? 'preview';
    $user_id = $_SESSION['user_id'];
    
    // 4. Input Validation
    
    // Validate Phone (Required)
    if (empty($phone)) {
        $_SESSION['error'] = "Phone number is required!";
        header('Location: generator.php');
        exit;
    }
    
    // Validate Phone Format (Regex)
    if (!preg_match('/^[\+\d\s\-\(\)]{8,20}$/', $phone)) {
        $_SESSION['error'] = "Invalid phone number format!";
        header('Location: generator.php');
        exit;
    }

    // Validate Email (New Security Check)
    // Even if not strictly required by the logic, validating email format prevents garbage data.
    if (!empty($email) && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
         $_SESSION['error'] = "Invalid email format!";
         header('Location: generator.php');
         exit;
    }
    
    // 5. Secure Template Loading
    // Prevent Directory Traversal attacks using realpath and strpos checks.
    $templates_dir = __DIR__ . '/templates';
    $real_templates_dir = realpath($templates_dir);
    
    // Sanitize template filename
    $template_file = basename($template); 
    $template_path = realpath($templates_dir . '/' . $template_file);
    
    // Verify file is strictly inside the templates directory
    if ($template_path && $real_templates_dir && 
        strpos($template_path, $real_templates_dir) === 0 && 
        file_exists($template_path)) {
        
        $template_content = file_get_contents($template_path);
    } else {
        // Fallback to default if malicious path or missing file
        $fallback = $templates_dir . '/signature_default.html';
        if (file_exists($fallback)) {
            $template_content = file_get_contents($fallback);
        } else {
            die('Error: Default template missing.');
        }
    }
    
    // 6. XSS Prevention
    // htmlspecialchars() converts characters like <, >, &, " to HTML entities.
    // This prevents users from injecting JavaScript into the signature (XSS).
    $signature = str_replace(
        ['{{NAME}}', '{{ROLE}}', '{{EMAIL}}', '{{PHONE}}'],
        [
            htmlspecialchars($name, ENT_QUOTES, 'UTF-8'), 
            htmlspecialchars($role, ENT_QUOTES, 'UTF-8'), 
            htmlspecialchars($email, ENT_QUOTES, 'UTF-8'), 
            htmlspecialchars($phone, ENT_QUOTES, 'UTF-8')
        ],
        $template_content
    );
    
    // 7. Update Session State
    $_SESSION['preview'] = $signature;
    $_SESSION['form_data'] = [
        'name' => $name,
        'role' => $role,
        'email' => $email,
        'phone' => $phone,
        'template' => $template
    ];
    
    // 8. Save to Database
    if ($action === 'save') {
        // Use Prepared Statements for SQL Injection protection
        $stmt = $db->prepare("INSERT INTO user_signatures (user_id, name, role, email, phone, template) 
                             VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
        $stmt->bindValue(2, $name, SQLITE3_TEXT);
        $stmt->bindValue(3, $role, SQLITE3_TEXT);
        $stmt->bindValue(4, $email, SQLITE3_TEXT);
        $stmt->bindValue(5, $phone, SQLITE3_TEXT);
        $stmt->bindValue(6, $template, SQLITE3_TEXT);
        
        if ($stmt->execute()) {
            $_SESSION['last_generated_id'] = $db->lastInsertRowID();
            $_SESSION['success'] = "Signature saved successfully.";
        } else {
            $_SESSION['error'] = "Database error: Could not save signature.";
        }
    }
    
    header('Location: generator.php');
    exit;
} else {
    // If accessed directly via GET (without ?delete), redirect to generator
    header('Location: generator.php');
    exit;
}
?>
