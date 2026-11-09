<?php
/**
 * process_import.php - writes the previewed CSV rows to the database.
 * The data comes from the session (set by csv_import.php) and is validated again here.
 */
require_once 'includes/config.php';
requireLogin();

// Direct access without a prepared import: back to the upload page.
if (!isset($_SESSION['import_data'])) {
    header('Location: csv_import.php');
    exit;
}

$import_data = $_SESSION['import_data'];
// Remove immediately so a page refresh cannot import the same rows twice.
unset($_SESSION['import_data']);

$user_id  = (int)$import_data['user_id'];
$template = resolveTemplateName($import_data['template'] ?? '');
$rows     = array_slice((array)($import_data['rows'] ?? []), 0, 2000);

// Authorization: admins may import for any user, everybody else only for themselves.
if (!isAdmin() && $user_id !== (int)$_SESSION['user_id']) {
    logSecurityEventToDB($db, 'IMPORT_DENIED', (int)$_SESSION['user_id'], 'Target user: ' . $user_id);
    setFlash('error', t('Access denied.'));
    header('Location: csv_import.php');
    exit;
}

// The target must still exist (it may have been deleted since the preview).
$stmt = $db->prepare('SELECT username, full_name FROM users WHERE id = ?');
$stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
$user_info = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
if (!$user_info) {
    header('Location: csv_import.php');
    exit;
}

$success_count = 0;
$error_count = 0;
$errors = [];

// All rows or none: a failure in the middle must not leave a half import behind.
$db->exec('BEGIN IMMEDIATE');
try {
    $insert = $db->prepare("INSERT INTO user_signatures (user_id, name, role, email, phone, template, source) VALUES (?, ?, ?, ?, ?, ?, 'csv')");
    foreach ($rows as $index => $row) {
        $row_num = (int)($row['row'] ?? ($index + 1));
        [$clean, $rowErrors] = validateSignatureFields((array)$row, true);
        if ($rowErrors) {
            $error_count++;
            $errors[] = t('Row {row}: {details}', ['row' => $row_num, 'details' => implode(' ', $rowErrors)]);
            continue;
        }
        $insert->reset();
        $insert->bindValue(1, $user_id, SQLITE3_INTEGER);
        $insert->bindValue(2, $clean['name'], SQLITE3_TEXT);
        $insert->bindValue(3, $clean['role'], SQLITE3_TEXT);
        $insert->bindValue(4, $clean['email'], SQLITE3_TEXT);
        $insert->bindValue(5, $clean['phone'], SQLITE3_TEXT);
        $insert->bindValue(6, $template, SQLITE3_TEXT);
        $insert->execute();
        $success_count++;
    }
    $db->exec('COMMIT');
} catch (Exception $e) {
    $db->exec('ROLLBACK');
    error_log('CSV import failed: ' . $e->getMessage());
    $errors[] = t('The import failed and was rolled back. No rows were saved.');
    $error_count += $success_count;
    $success_count = 0;
}

logSecurityEventToDB($db, 'CSV_IMPORT', (int)$_SESSION['user_id'], "Target user: $user_id, imported: $success_count, failed: $error_count");

$template_display = templateDisplayName($template);
?>
<!DOCTYPE html>
<html lang="<?= e(currentLang()) ?>" dir="<?= e(langDir()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= et('Import Results') ?> - SubSignature</title>
    
    <?= i18nHead() ?>
    
    <script src="<?= assetUrl('js/theme.js') ?>"></script>
    <link rel="stylesheet" href="<?= assetUrl('css/theme.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/style.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/all.min.css') ?>">    
    
    <style>
        /* Import Result Specific Styles */
        .result-stats-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .result-card {
            background: var(--bg-white);
            padding: 2rem;
            border-radius: 12px;
            border: 1px solid var(--border);
            text-align: center;
        }

        .result-card.success { border-bottom: 4px solid #16a34a; }
        .result-card.error { border-bottom: 4px solid var(--danger); }
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
            background: var(--danger-bg);
            border: 1px solid var(--danger-border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-top: 1.5rem;
            max-height: 250px;
            overflow-y: auto;
        }
        .error-item { 
            padding: 0.5rem 0; 
            border-bottom: 1px solid var(--danger-border); 
            color: var(--danger-text); 
            font-size: 0.9rem;
        }

        .action-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 2rem;
        }
        
        .action-card {
            background: var(--bg-white);
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
        <?= langSwitcher() ?>
            <div class="user-profile">
                <div class="avatar">
                    <?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?>
                </div>
                <div class="user-info">
                    <div><?php echo e($_SESSION['username']); ?></div>
                    <span><?= isAdmin() ? et('Administrator') : et('User') ?></span>
                </div>
            </div>
            <a href="logout.php" class="btn-logout">
                <i class="fas fa-sign-out-alt"></i> <span><?= et('Sign Out') ?></span>
            </a>
        </div>
    </aside>

    <main class="main-content">
        
        <header class="page-header">
            <h2><?= et('Import Results') ?></h2>
            <p><?= et('Processing complete for {count} records.', ['count' => count($rows)]) ?></p>
        </header>

        <div class="result-stats-grid">
            <div class="result-card success">
                <span class="result-label"><?= et('Success') ?></span>
                <span class="result-number" style="color: var(--success-text);"><?php echo $success_count; ?></span>
                <i class="fas fa-check-circle" style="color: var(--success-text);"></i>
            </div>
            
            <div class="result-card error">
                <span class="result-label"><?= et('Failed') ?></span>
                <span class="result-number" style="color: var(--danger-text);"><?php echo $error_count; ?></span>
                <i class="fas fa-times-circle" style="color: var(--danger-text);"></i>
            </div>
            
            <div class="result-card total">
                <span class="result-label"><?= et('Total Processed') ?></span>
                <span class="result-number" style="color: var(--primary);"><?php echo count($rows); ?></span>
                <i class="fas fa-file-csv" style="color: var(--primary);"></i>
            </div>
        </div>

        <section class="card">
            <div class="card-header">
                <h3><i class="fas fa-info-circle"></i> <?= et('Import Summary') ?></h3>
            </div>
            
            <div style="padding: 1rem 0;">
                <ul class="details-list">
                    <li>
                        <span><strong><?= et('Assigned User:') ?></strong></span>
                        <span>
                            <?php echo e($user_info['full_name'] ?: $user_info['username']); ?>
                        </span>
                    </li>
                    <li>
                        <span><strong><?= et('Template Used:') ?></strong></span>
                        <span><?php echo e($template_display); ?></span>
                    </li>
                    <li>
                        <span><strong><?= et('Timestamp:') ?></strong></span>
                        <span><?php echo date('d.m.Y H:i:s'); ?></span>
                    </li>
                </ul>
            </div>

            <?php if (!empty($errors)): ?>
                <div class="error-log">
                    <h4 style="color:var(--danger-text); margin-bottom:1rem;"><i class="fas fa-exclamation-triangle"></i> <?= et('Import Errors') ?></h4>
                    <?php foreach ($errors as $error): ?>
                        <div class="error-item">
                            <?php echo e($error); ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </section>

        <section>
            <h3 style="margin-top:2rem; margin-bottom:1rem; font-size:1.2rem;"><?= et('What would you like to do next?') ?></h3>
            <div class="action-cards">
                <a href="all_signatures.php" class="action-card">
                    <i class="fas fa-list-ul action-icon"></i>
                    <strong><?= et('View Signatures') ?></strong>
                    <span style="font-size:0.85rem; color:var(--text-muted);"><?= et('See all created signatures') ?></span>
                </a>
                
                <a href="csv_import.php" class="action-card">
                    <i class="fas fa-file-upload action-icon"></i>
                    <strong><?= et('Import More') ?></strong>
                    <span style="font-size:0.85rem; color:var(--text-muted);"><?= et('Upload another CSV file') ?></span>
                </a>
                
                <a href="download_all.php" class="action-card">
                    <i class="fas fa-download action-icon"></i>
                    <strong><?= et('Download All') ?></strong>
                    <span style="font-size:0.85rem; color:var(--text-muted);"><?= et('Get ZIP of all signatures') ?></span>
                </a>
            </div>
        </section>

    </main>

</body>
</html>
