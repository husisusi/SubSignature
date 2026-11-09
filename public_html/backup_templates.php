<?php
/**
 * backup_templates.php - ZIP download of all templates (and the default marker).
 */

require_once 'includes/config.php';
requireAdmin();

// ---------------------------------------------------------
// 1. HANDLE POST REQUEST (generate download)
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    requireCsrf();

    ignore_user_abort(true);
    set_time_limit(300);

    if (!is_dir(TEMPLATES_DIR)) die('Error: Templates directory not found.');

    $zip_path = tempnam(TMP_DIR, 'tpl_backup_');
    if ($zip_path === false) die('Error: Could not create temporary file.');

    $download_filename = 'subsignature_backup_' . date('Y-m-d_H-i-s') . '.zip';

    $zip = new ZipArchive();
    if ($zip->open($zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        unlink($zip_path);
        die('Error: Could not open ZIP file.');
    }

    // Signature templates, the mail wrapper and the default marker file.
    $names = listSignatureTemplates();
    if (is_file(TEMPLATES_DIR . '/email_notification.html')) $names[] = 'email_notification.html';
    if (is_file(TEMPLATES_DIR . '/default_config.txt')) $names[] = 'default_config.txt';

    $count = 0;
    foreach ($names as $name) {
        $file = TEMPLATES_DIR . '/' . $name;
        if (is_file($file) && is_readable($file) && isPathInside($file, TEMPLATES_DIR)) {
            $zip->addFile(realpath($file), $name);
            $count++;
        }
    }
    $zip->close();

    if ($count > 0 && is_file($zip_path)) {
        while (ob_get_level()) ob_end_clean();
        logSecurityEventToDB($db, 'TEMPLATE_BACKUP', (int)$_SESSION['user_id'], "Files: $count");
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="' . $download_filename . '"');
        header('Content-Length: ' . filesize($zip_path));
        readfile($zip_path);
        unlink($zip_path);
        exit;
    }
    if (is_file($zip_path)) unlink($zip_path);
    die('Error: No templates found to backup.');
}

// ---------------------------------------------------------
// 2. HANDLE GET REQUEST (Show UI)
// ---------------------------------------------------------

$csrf_token = generateCSRFToken();

// Count templates for display
$count = count(listSignatureTemplates());
?>
<!DOCTYPE html>
<html lang="<?= e(currentLang()) ?>" dir="<?= e(langDir()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= et('Backup') ?> - SubSignature</title>
    <?= i18nHead() ?>
    <script src="<?= assetUrl('js/theme.js') ?>"></script>
    <link rel="stylesheet" href="<?= assetUrl('css/theme.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/style.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/all.min.css') ?>">
    <style>
        /* Modern Backup Card Styling */
        .backup-hero {
            text-align: center;
            padding: 3rem 1rem;
            background: linear-gradient(to bottom, var(--bg-subtle), var(--bg-white));
            border-bottom: 1px solid var(--border);
        }
        .backup-icon-circle {
            width: 80px; height: 80px;
            background: var(--accent-bg); color: var(--primary);
            border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            font-size: 2.5rem; margin: 0 auto 1.5rem auto;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        .stat-badge {
            background: var(--bg-subtle); color: var(--text-muted);
            padding: 4px 12px; border-radius: 20px;
            font-size: 0.85rem; font-weight: 600;
            display: inline-flex; align-items: center; gap: 6px;
            margin-bottom: 1.5rem;
        }

        /* Custom Modal Styling */
        .modal-overlay {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(4px);
            z-index: 1000;
            display: none; /* Hidden by default */
            align-items: center; justify-content: center;
            opacity: 0; transition: opacity 0.3s ease;
        }
        .modal-overlay.active { display: flex; opacity: 1; }
        
        .modal-box {
            background: var(--bg-white); width: 90%; max-width: 450px;
            border-radius: 12px; padding: 2rem;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
            transform: translateY(20px); transition: transform 0.3s ease;
            text-align: center;
        }
        .modal-overlay.active .modal-box { transform: translateY(0); }
        
        .modal-icon {
            font-size: 3rem; color: var(--primary); margin-bottom: 1rem;
        }
        .modal-actions {
            display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;
            margin-top: 2rem;
        }
    </style>
</head>
<body>

<aside class="sidebar">
    <?php include 'includes/navbar.php'; ?>
    <div class="sidebar-footer">
        <?= langSwitcher() ?>
        <div class="user-profile">
            <div class="avatar"><?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?></div>
            <div class="user-info">
                <div><?php echo e($_SESSION['username']); ?></div>
                <span><?= isAdmin() ? et('Administrator') : et('User') ?></span>
            </div>
        </div>
        <a href="logout.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> <span><?= et('Sign Out') ?></span></a>
        <div style="text-align: center; margin-top: 0.75rem; font-size: 0.7rem; color: var(--text-faint);">
            SubSignature <a href="about.php" style="color: inherit; text-decoration: none; font-weight: 600;">v1.0.1</a>
        </div>
    </div>
</aside>

<main class="main-content">
    <header class="page-header">
        <h2><?= et('Backup System') ?></h2>
        <p><?= et('Manage and secure your template data.') ?></p>
    </header>

    <div class="card" style="max-width: 700px; margin: 0 auto; overflow: hidden; padding: 0;">
        
        <div class="backup-hero">
            <div class="backup-icon-circle">
                <i class="fas fa-cube"></i>
            </div>
            <h3 style="font-size: 1.5rem; margin-bottom: 0.5rem;"><?= et('Export Templates') ?></h3>
            <p style="color: var(--text-muted); margin-bottom: 1.5rem;">
                <?= et('Create a secure ZIP archive of all HTML signature templates.') ?>
            </p>
            
            <div class="stat-badge">
                <i class="fas fa-file-code"></i> <?= et('{count} Templates found', ['count' => $count]) ?>
            </div>
            
            <br>
            
            <button onclick="openModal()" class="btn btn-primary" style="padding: 0.8rem 2rem; font-size: 1rem;">
                <i class="fas fa-download"></i> <?= et('Create Backup') ?>
            </button>
        </div>

        <div style="padding: 1.5rem; background: var(--bg-white); font-size: 0.9rem; color: var(--text-muted);">
            <strong><i class="fas fa-info-circle"></i> <?= et('Note:') ?></strong> 
            <?= et('The backup includes all `.html` template files currently active in the system. User data or database entries are not included in this specific archive.') ?>
        </div>
    </div>
</main>

<div class="modal-overlay" id="backupModal">
    <div class="modal-box">
        <div class="modal-icon"><i class="fas fa-file-zipper"></i></div>
        <h3 style="font-size: 1.4rem; margin-bottom: 0.5rem; color: var(--text-main);"><?= et('Ready to download?') ?></h3>
        <p style="color: var(--text-muted);">
            <?= eth('We are about to generate a ZIP file containing {count}.', ['count' => '<strong>' . e(t('{count} templates', ['count' => $count])) . '</strong>']) ?>
        </p>
        
        <form method="POST" action="backup_templates.php" id="downloadForm">
            <?php echo csrfField(); ?>
            
            <div class="modal-actions">
                <button type="button" class="btn btn-danger" onclick="closeModal()">
                    <?= et('Cancel') ?>
                </button>
                <button type="submit" class="btn btn-primary" onclick="startDownload(this)">
                    <i class="fas fa-check"></i> <?= et('Download') ?>
                </button>
            </div>
        </form>
    </div>
</div>

<script>
    const modal = document.getElementById('backupModal');

    function openModal() {
        modal.classList.add('active');
    }

    function closeModal() {
        modal.classList.remove('active');
    }

    // Close modal if clicking outside the box
    modal.addEventListener('click', function(e) {
        if (e.target === modal) closeModal();
    });

    // Handle Button Loading State
    function startDownload(btn) {
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ' + <?= tj('Processing...') ?>;
        btn.style.opacity = '0.8';
        // Note: We don't disable the button because form submission might be blocked in some browsers if disabled immediately
        
        // Close modal after a short delay (UI feel)
        setTimeout(() => {
            closeModal();
            // Reset button
            setTimeout(() => {
                btn.innerHTML = '<i class="fas fa-check"></i> ' + <?= tj('Download') ?>;
                btn.style.opacity = '1';
            }, 1000);
        }, 1500);
    }
</script>

</body>
</html>
