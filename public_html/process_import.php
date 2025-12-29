<?php
// process_import.php

// 1. Include Configuration & Security
require_once 'includes/config.php';
requireLogin();

// 2. Session Data Check
// Ensure import data exists. If not, redirect (prevents direct access).
if (!isset($_SESSION['import_data'])) {
    header('Location: csv_import.php');
    exit;
}

// Retrieve data
$import_data = $_SESSION['import_data'];

// 3. Prevent Double Submission
// CRITICAL: Unset the session data immediately.
// This prevents the user from refreshing the page and importing the same duplicates again.
unset($_SESSION['import_data']);

$user_id = (int)$import_data['user_id'];
$template = $import_data['template'];
$rows = $import_data['rows'];

// 4. Authorization Check
// Ensure the user has permission to import for the target user ID.
// Admin can import for anyone; Users can only import for themselves.
if (!isAdmin() && $user_id !== $_SESSION['user_id']) {
    // Log this security event if you have a logger
    header('Location: csv_import.php?error=Access+Denied');
    exit;
}

$success_count = 0;
$error_count = 0;
$errors = [];

// 5. Processing Loop with Validation
foreach ($rows as $index => $row) {
    // Sanitize inputs (trim whitespace)
    $name = trim($row['name'] ?? '');
    $role = trim($row['role'] ?? '');
    $email = trim($row['email'] ?? '');
    $phone = trim($row['phone'] ?? '');
    $row_num = $row['row'] ?? ($index + 1);

    // Validation: Check required fields
    if (empty($name)) {
        $error_count++;
        $errors[] = "Row {$row_num}: Name is required.";
        continue;
    }

    // Validation: Check Email Format
    // This prevents garbage data from polluting the database.
    if (!empty($email) && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error_count++;
        $errors[] = "Row {$row_num}: Invalid email format '{$email}'.";
        continue;
    }

    try {
        // Secure Insert
        $stmt = $db->prepare("INSERT INTO user_signatures (user_id, name, role, email, phone, template) 
                             VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
        $stmt->bindValue(2, $name, SQLITE3_TEXT);
        $stmt->bindValue(3, $role, SQLITE3_TEXT);
        $stmt->bindValue(4, $email, SQLITE3_TEXT);
        $stmt->bindValue(5, $phone, SQLITE3_TEXT);
        // Ensure template filename is safe (basename check was done in previous step, but good to be sure)
        $stmt->bindValue(6, basename($template), SQLITE3_TEXT);
        
        if ($stmt->execute()) {
            $success_count++;
        } else {
            $error_count++;
            $errors[] = "Row {$row_num}: Database insertion failed.";
        }
    } catch (Exception $e) {
        $error_count++;
        // Do not output raw SQL errors to UI, mostly for security, but kept generic here.
        $errors[] = "Row {$row_num}: System error during save.";
    }
}

// 6. Fetch User Info for Display
// Use prepared statement to prevent injection if $user_id was manipulated
$stmt = $db->prepare("SELECT username, full_name FROM users WHERE id = ?");
$stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
$result = $stmt->execute();
$user_info = $result->fetchArray(SQLITE3_ASSOC);

if (!$user_info) {
    // Fallback if user was deleted during process
    $user_info = ['username' => 'Unknown', 'full_name' => 'Unknown'];
}

// Prepare template name for display (Sanitized later in HTML)
$template_display = ucfirst(str_replace(['signature_', '.html', '_'], ['', '', ' '], $template));
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Import Results - SubSignature</title>
    
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/all.min.css">    
    
    <style>
        /* Import Result Specific Styles */
        .result-stats-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .result-card {
            background: white;
            padding: 2rem;
            border-radius: 12px;
            border: 1px solid var(--border);
            text-align: center;
        }

        .result-card.success { border-bottom: 4px solid #16a34a; }
        .result-card.error { border-bottom: 4px solid #dc2626; }
        .result-card.total { border-bottom: 4px solid var(--primary); }

        .result-number { font-size: 2.5rem; font-weight: 700; display: block; margin: 0.5rem 0; }
        .result-label { color: var(--text-muted); font-size: 0.9rem; font-weight: 600; text-transform: uppercase; }

        .details-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }
        .details-list li {
            padding: 1rem 0;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
        }
        .details-list li:last-child { border-bottom: none; }
        
        .error-log {
            background: #fef2f2;
            border: 1px solid #fecaca;
            border-radius: 8px;
            padding: 1.5rem;
            margin-top: 1.5rem;
            max-height: 250px;
            overflow-y: auto;
        }
        .error-item { 
            padding: 0.5rem 0; 
            border-bottom: 1px solid #fee2e2; 
            color: #b91c1c; 
            font-size: 0.9rem;
        }

        .action-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 2rem;
        }
        
        .action-card {
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            border: 1px solid var(--border);
            text-align: center;
            text-decoration: none;
            color: var(--text-main);
            transition: all 0.2s;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 0.5rem;
        }
        .action-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            border-color: var(--primary);
        }
        
        .action-icon { font-size: 2rem; color: var(--primary); margin-bottom: 0.5rem; }

        @media (max-width: 768px) {
            .result-stats-grid { grid-template-columns: 1fr; }
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
            <h2>Import Results</h2>
            <p>Processing complete for <?php echo count($rows); ?> records.</p>
        </header>

        <div class="result-stats-grid">
            <div class="result-card success">
                <span class="result-label">Success</span>
                <span class="result-number" style="color: #16a34a;"><?php echo $success_count; ?></span>
                <i class="fas fa-check-circle" style="color: #16a34a;"></i>
            </div>
            
            <div class="result-card error">
                <span class="result-label">Failed</span>
                <span class="result-number" style="color: #dc2626;"><?php echo $error_count; ?></span>
                <i class="fas fa-times-circle" style="color: #dc2626;"></i>
            </div>
            
            <div class="result-card total">
                <span class="result-label">Total Processed</span>
                <span class="result-number" style="color: var(--primary);"><?php echo count($rows); ?></span>
                <i class="fas fa-file-csv" style="color: var(--primary);"></i>
            </div>
        </div>

        <section class="card">
            <div class="card-header">
                <h3><i class="fas fa-info-circle"></i> Import Summary</h3>
            </div>
            
            <div style="padding: 1rem 0;">
                <ul class="details-list">
                    <li>
                        <span><strong>Assigned User:</strong></span>
                        <span>
                            <?php echo htmlspecialchars($user_info['full_name'] ?: $user_info['username'], ENT_QUOTES, 'UTF-8'); ?>
                        </span>
                    </li>
                    <li>
                        <span><strong>Template Used:</strong></span>
                        <span><?php echo htmlspecialchars($template_display, ENT_QUOTES, 'UTF-8'); ?></span>
                    </li>
                    <li>
                        <span><strong>Timestamp:</strong></span>
                        <span><?php echo date('d.m.Y H:i:s'); ?></span>
                    </li>
                </ul>
            </div>

            <?php if (!empty($errors)): ?>
                <div class="error-log">
                    <h4 style="color:#991b1b; margin-bottom:1rem;"><i class="fas fa-exclamation-triangle"></i> Import Errors</h4>
                    <?php foreach ($errors as $error): ?>
                        <div class="error-item">
                            <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </section>

        <section>
            <h3 style="margin-top:2rem; margin-bottom:1rem; font-size:1.2rem;">What would you like to do next?</h3>
            <div class="action-cards">
                <a href="generator.php" class="action-card">
                    <i class="fas fa-list-ul action-icon"></i>
                    <strong>View Signatures</strong>
                    <span style="font-size:0.85rem; color:var(--text-muted);">See all created signatures</span>
                </a>
                
                <a href="csv_import.php" class="action-card">
                    <i class="fas fa-file-upload action-icon"></i>
                    <strong>Import More</strong>
                    <span style="font-size:0.85rem; color:var(--text-muted);">Upload another CSV file</span>
                </a>
                
                <a href="download_all.php" class="action-card">
                    <i class="fas fa-download action-icon"></i>
                    <strong>Download All</strong>
                    <span style="font-size:0.85rem; color:var(--text-muted);">Get ZIP of all signatures</span>
                </a>
            </div>
        </section>

    </main>

</body>
</html>
