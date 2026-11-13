<?php
// admin_templates.php - manage signature templates (default, import, rename, delete).

require_once 'includes/config.php';
requireStaff();

$message = popFlash('success');
$error = popFlash('error');
$csrf_token = generateCSRFToken();

const TEMPLATE_MAX_BYTES = 524288; // 512 KB per template

$default_config_file = TEMPLATES_DIR . '/default_config.txt';
$current_default = getDefaultTemplateName();

/**
 * Stores the redirect message and returns to the list (Post/Redirect/Get).
 */
function templatesRedirect(string $type, string $text): void
{
    setFlash($type, $text);
    header('Location: admin_templates.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    requireCsrf();

    // ---------------------------------------------------------
    // 1. ACTION: SET DEFAULT TEMPLATE
    // ---------------------------------------------------------
    if (isset($_POST['set_default'])) {
        $new_default = basename((string)($_POST['template_name'] ?? ''));
        if (!isValidTemplateName($new_default) || !is_file(TEMPLATES_DIR . '/' . $new_default)) {
            templatesRedirect('error', 'Template file not found.');
        }
        if (file_put_contents($default_config_file, $new_default, LOCK_EX) === false) {
            templatesRedirect('error', 'Could not save setting. Check file permissions.');
        }
        templatesRedirect('success', 'Default template updated to: ' . $new_default);
    }

    // ---------------------------------------------------------
    // 2. ACTION: IMPORT TEMPLATES
    // ---------------------------------------------------------
    if (isset($_POST['import_templates'])) {
        $success_count = 0;
        $error_details = [];
        $uploaded_files = $_FILES['html_files'] ?? null;

        if ($uploaded_files && is_array($uploaded_files['name'])) {
            for ($i = 0; $i < min(count($uploaded_files['name']), 20); $i++) {
                $filename = cleanText(basename((string)$uploaded_files['name'][$i]), 120);
                $tmp_name = $uploaded_files['tmp_name'][$i];

                if ($uploaded_files['error'][$i] !== UPLOAD_ERR_OK) {
                    if ($uploaded_files['error'][$i] !== UPLOAD_ERR_NO_FILE) {
                        $error_details[] = "$filename: Upload failed.";
                    }
                    continue;
                }
                if (!is_uploaded_file($tmp_name)) {
                    $error_details[] = "$filename: invalid upload source.";
                    continue;
                }
                if (strtolower(pathinfo($filename, PATHINFO_EXTENSION)) !== 'html') {
                    $error_details[] = t('{file}: Only .html files allowed.', ['file' => $filename]);
                    continue;
                }
                if (filesize($tmp_name) > TEMPLATE_MAX_BYTES) {
                    $error_details[] = "$filename: File is too large (max 512 KB).";
                    continue;
                }

                $content = (string)file_get_contents($tmp_name);
                if (strpos($content, '<?') !== false) {
                    $error_details[] = "$filename: Contains PHP/XML processing instructions (not allowed).";
                    continue;
                }
                if (!mb_check_encoding($content, 'UTF-8')) {
                    $error_details[] = "$filename: File must be UTF-8 encoded.";
                    continue;
                }
                // Active content (scripts, handlers, javascript: URLs) is removed on import.
                $content = sanitizeTemplateHtml($content);

                $safe_name = substr(preg_replace('/[^a-z0-9_\-]/', '', strtolower(pathinfo($filename, PATHINFO_FILENAME))), 0, 70);
                if (strpos($safe_name, 'signature_') !== 0) {
                    $safe_name = 'signature_' . $safe_name;
                }
                $final_name = $safe_name . '.html';
                if (file_exists(TEMPLATES_DIR . '/' . $final_name)) {
                    $final_name = $safe_name . '_' . bin2hex(random_bytes(3)) . '.html'; // never overwrite silently
                }
                if (!isValidTemplateName($final_name)) {
                    $error_details[] = "$filename: Invalid template name.";
                    continue;
                }

                if (file_put_contents(TEMPLATES_DIR . '/' . $final_name, $content, LOCK_EX) !== false) {
                    $success_count++;
                } else {
                    $error_details[] = "$filename: Failed to save file.";
                }
            }
        }

        if ($success_count > 0) {
            logSecurityEventToDB($db, 'TEMPLATES_IMPORTED', (int)$_SESSION['user_id'], "Count: $success_count");
        }
        if ($error_details) {
            setFlash('error', implode("\n", $error_details));
        }
        if ($success_count > 0) {
            setFlash('success', t('Successfully imported {count} template(s).', ['count' => $success_count]));
        }
        header('Location: admin_templates.php');
        exit;
    }

    // ---------------------------------------------------------
    // 3. ACTION: RENAME TEMPLATE
    // ---------------------------------------------------------
    if (isset($_POST['rename_template'])) {
        $old_name = basename((string)($_POST['old_name'] ?? ''));
        $new_name = trim((string)($_POST['new_name'] ?? ''));

        if ($new_name === '') {
            templatesRedirect('error', 'New name is required!');
        }
        if (!isValidTemplateName($new_name)) {
            templatesRedirect('error', 'Format must be: signature_name.html (letters, digits, underscore, hyphen)');
        }
        $old_path = TEMPLATES_DIR . '/' . $old_name;
        $new_path = TEMPLATES_DIR . '/' . $new_name;

        if (!isValidTemplateName($old_name) || !is_file($old_path)) {
            templatesRedirect('error', 'Original file not found!');
        }
        if (file_exists($new_path)) {
            templatesRedirect('error', 'Name already exists!');
        }
        if (!rename($old_path, $new_path)) {
            templatesRedirect('error', 'Error renaming file.');
        }

        if ($old_name === $current_default) {
            file_put_contents($default_config_file, $new_name, LOCK_EX);
        }
        // Keep database references consistent.
        $stmt = $db->prepare("UPDATE user_signatures SET template = ?, updated_at = datetime('now') WHERE template = ?");
        $stmt->bindValue(1, $new_name, SQLITE3_TEXT);
        $stmt->bindValue(2, $old_name, SQLITE3_TEXT);
        $stmt->execute();
        templatesRedirect('success', 'Template renamed successfully.');
    }

    // ---------------------------------------------------------
    // 4. ACTION: DELETE TEMPLATE
    // ---------------------------------------------------------
    if (($_POST['action'] ?? '') === 'delete_template') {
        $template = basename((string)($_POST['template'] ?? ''));
        $template_path = TEMPLATES_DIR . '/' . $template;

        if (!isValidTemplateName($template) || !is_file($template_path)) {
            templatesRedirect('error', 'Template not found!');
        }
        if ($template === $current_default) {
            templatesRedirect('error', 'Cannot delete the active default template! Please set another default first.');
        }
        if (!unlink($template_path)) {
            templatesRedirect('error', 'Error deleting file.');
        }
        logSecurityEventToDB($db, 'TEMPLATE_DELETED', (int)$_SESSION['user_id'], $template);
        templatesRedirect('success', 'Template deleted successfully.');
    }

    header('Location: admin_templates.php');
    exit;
}

// ---------------------------------------------------------
// 5. DATA LOADING & SORTING
// ---------------------------------------------------------
$templates = [];
$template_files = listSignatureTemplates();

if ($template_files) {
    foreach ($template_files as $filename) {
        
        // Count usage in DB
        $stmt = $db->prepare("SELECT COUNT(*) as count FROM user_signatures WHERE template = ?");
        $stmt->bindValue(1, $filename, SQLITE3_TEXT);
        $result = $stmt->execute();
        $usage = $result->fetchArray(SQLITE3_ASSOC)['count'];
        
        $templates[] = [
            'filename' => $filename,
            'display_name' => templateDisplayName($filename),
            'usage' => $usage,
            'is_default' => ($filename === $current_default)
        ];
    }
}

// Sort: Active Default first, then by Usage desc, then Name asc
usort($templates, function($a, $b) { 
    if ($a['is_default']) return -1;
    if ($b['is_default']) return 1;
    if ($a['usage'] != $b['usage']) return $b['usage'] - $a['usage'];
    return strcmp($a['filename'], $b['filename']); 
});

?>
<!DOCTYPE html>
<html lang="<?= e(currentLang()) ?>" dir="<?= e(langDir()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= et('Template Management') ?> - SubSignature</title>
    <?= i18nHead() ?>
    <script src="<?= assetUrl('js/theme.js') ?>"></script>
    <link rel="stylesheet" href="<?= assetUrl('css/theme.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/style.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/all.min.css') ?>">
    <?php echo csrfMeta(); ?>
    
    <style>
        .rename-row { display: none; background: var(--bg-subtle); }
        .inline-form { display: flex; align-items: center; justify-content: flex-end; gap: 10px; padding: 10px; }
        
        .template-badge { padding: 4px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; display: inline-block; margin-right: 5px; }
        .badge-default { background: var(--success-bg); color: var(--success-text); border: 1px solid var(--success-border); } /* Green for Active Default */
        .badge-active { background: var(--info-bg); color: var(--info-text); } /* Blue for used templates */
        .badge-unused { background: var(--bg-subtle); color: var(--text-muted); }
        
        /* Star Button Styles */
        .btn-star { background: transparent; border: 1px solid var(--border-strong); color: var(--border-strong); cursor: pointer; border-radius: 4px; padding: 4px 8px;}
        .btn-star:hover { border-color: #eab308; color: #eab308; }
        .btn-star.active { background: var(--warning-bg); border-color: #eab308; color: var(--warning-text); pointer-events: none; }
        
        /* Modal Styles */
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.5); display: none; justify-content: center; align-items: center; z-index: 1000; backdrop-filter: blur(2px); }
        .modal-box { background: var(--bg-white); width: 90%; max-width: 500px; padding: 2rem; border-radius: 12px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1); position: relative; }
        .modal-header h3 { margin: 0; color: var(--text-main); font-size: 1.25rem; }
        .modal-close { position: absolute; top: 1rem; right: 1rem; cursor: pointer; color: var(--text-muted); font-size: 1.2rem; }
        
        /* Upload Area */
        .upload-area { border: 2px dashed var(--border-strong); border-radius: 8px; padding: 2rem; text-align: center; cursor: pointer; transition: all 0.2s; background: var(--bg-subtle); position: relative; margin-top: 1rem; }
        .upload-area:hover { border-color: var(--primary); background: var(--bg-hover); }
        .upload-input { position: absolute; width: 100%; height: 100%; top: 0; left: 0; opacity: 0; cursor: pointer; }
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
                    <span><?= eRoleLabel() ?></span>
                </div>
            </div>
            <a href="logout.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> <span><?= et('Sign Out') ?></span></a>
        </div>
    </aside>

    <main class="main-content">
        
        <header class="page-header">
            <h2><?= et('Template Management') ?></h2>
            <p><?= et('Manage, rename, import, and set default signature templates.') ?></p>
        </header>

        <?= flashAlerts($message, $error) ?>

        <div class="form-grid" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); margin-bottom: 2rem;">
            <div class="card" style="padding: 1.5rem; text-align:center;">
                <div style="color: var(--text-muted); margin-bottom: 0.5rem;"><?= et('Total Templates') ?></div>
                <div style="font-size: 2rem; font-weight: 700; color: var(--text-main);"><?php echo count($templates); ?></div>
            </div>
            <div class="card" style="padding: 1.5rem; text-align:center;">
                <div style="color: var(--text-muted); margin-bottom: 0.5rem;"><?= et('Total Usage') ?></div>
                <div style="font-size: 2rem; font-weight: 700; color: var(--text-main);"><?php echo array_sum(array_column($templates, 'usage')); ?></div>
            </div>
        </div>

        <section class="card">
            <div class="card-header">
                <h3><i class="fas fa-list"></i> <?= et('Installed Templates') ?></h3>
                <div style="display:flex; gap: 0.5rem;">
                    <button onclick="openImportModal()" class="btn btn-sm btn-success">
                        <i class="fas fa-file-import"></i> <?= et('Import HTML') ?>
                    </button>
                    
                    <a href="template_editor.php" class="btn btn-sm btn-primary">
                        <i class="fas fa-plus"></i> <?= et('New') ?>
                    </a>
                </div>
            </div>
            
            <div style="overflow-x: auto;">
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="background: var(--bg-subtle); text-align: left; border-bottom: 1px solid var(--border);">
                            <th style="padding: 1rem; width: 50px;"><?= et('Def.') ?></th>
                            <th style="padding: 1rem;"><?= et('Name') ?></th>
                            <th style="padding: 1rem;"><?= et('Filename') ?></th>
                            <th style="padding: 1rem;"><?= et('Usage') ?></th>
                            <th style="padding: 1rem; text-align: right;"><?= et('Actions') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($templates as $t): ?>
                        <tr style="border-bottom: 1px solid var(--border);">
                            
                            <td style="padding: 1rem; text-align: center;">
                                <form method="POST" style="margin:0;">
                                    <?php echo csrfField(); ?>
                                    <input type="hidden" name="set_default" value="1">
                                    <input type="hidden" name="template_name" value="<?php echo e($t['filename']); ?>">
                                    
                                    <?php if ($t['is_default']): ?>
                                        <button type="button" class="btn-star active" title="<?= et('Current Default') ?>">
                                            <i class="fas fa-star"></i>
                                        </button>
                                    <?php else: ?>
                                        <button type="submit" class="btn-star" title="<?= et('Set as Default') ?>">
                                            <i class="far fa-star"></i>
                                        </button>
                                    <?php endif; ?>
                                </form>
                            </td>

                            <td style="padding: 1rem;">
                                <strong><?php echo e($t['display_name']); ?></strong>
                                <?php if ($t['is_default']): ?>
                                    <span class="template-badge badge-default" style="margin-left:5px;"><?= et('Default') ?></span>
                                <?php endif; ?>
                            </td>
                            
                            <td style="padding: 1rem; color: var(--text-muted);"><code><?php echo e($t['filename']); ?></code></td>
                            
                            <td style="padding: 1rem;">
                                <?php 
                                    if ($t['usage'] > 0) {
                                        echo '<span class="template-badge badge-active">' . $t['usage'] . ' Users</span>';
                                    } else {
                                        echo '<span class="template-badge badge-unused">Unused</span>';
                                    }
                                ?>
                            </td>
                            
                            <td style="padding: 1rem; text-align: right;">
                                <div style="display: inline-flex; gap: 0.5rem;">
                                    <a href="template_editor.php?edit=<?php echo rawurlencode($t['filename']); ?>" class="btn btn-sm btn-primary" title="<?= et('Edit') ?>"><i class="fas fa-pen"></i></a>
                                    
                                    <a href="preview_template.php?template=<?php echo rawurlencode($t['filename']); ?>" target="_blank" class="btn btn-sm btn-secondary" title="<?= et('Preview') ?>"><i class="fas fa-eye"></i></a>
                                    
                                    <button type="button" onclick="toggleRename('<?php echo md5($t['filename']); ?>')" class="btn btn-sm btn-secondary" title="<?= et('Rename') ?>"><i class="fas fa-i-cursor"></i></button>
                                    
                                    <?php if (!$t['is_default']): ?>
                                        <button type="button" data-post="admin_templates.php" data-params='{"action":"delete_template","template":"<?php echo e($t['filename']); ?>"}' data-confirm="<?= et('Really delete?') ?>" class="btn btn-sm btn-danger" title="<?= et('Delete') ?>"><i class="fas fa-trash"></i></button>
                                    <?php else: ?>
                                        <button class="btn btn-sm btn-secondary" disabled style="opacity:0.5; cursor:not-allowed;"><i class="fas fa-trash"></i></button>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                        
                        <tr id="rename-<?php echo md5($t['filename']); ?>" class="rename-row">
                            <td colspan="5">
                                <form method="POST" class="inline-form">
                                    <?php echo csrfField(); ?>
                                    <input type="hidden" name="rename_template" value="1">
                                    <input type="hidden" name="old_name" value="<?php echo e($t['filename']); ?>">
                                    
                                    <span><?= et('Rename to:') ?></span>
                                    <input type="text" name="new_name" value="<?php echo e($t['filename']); ?>" required style="padding: 5px; border: 1px solid var(--border); border-radius: 4px; width: 250px;">
                                    
                                    <button type="submit" class="btn btn-sm btn-primary"><?= et('Save') ?></button>
                                    <button type="button" onclick="toggleRename('<?php echo md5($t['filename']); ?>')" class="btn btn-sm btn-secondary"><?= et('Cancel') ?></button>
                                </form>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </section>

    </main>

    <div id="importModal" class="modal-overlay">
        <div class="modal-box">
            <span class="modal-close" onclick="closeImportModal()">&times;</span>
            <div class="modal-header">
                <h3><i class="fas fa-cloud-upload-alt" style="color:var(--primary);"></i> <?= et('Import Templates') ?></h3>
                <p style="color:var(--text-muted); font-size:0.9rem; margin-top:0.5rem;">
                    <?= eth('Upload new HTML templates. Only {ext} files allowed.', ['ext' => '<code>.html</code>']) ?>
                </p>
            </div>
            
            <form method="POST" enctype="multipart/form-data">
                <?php echo csrfField(); ?>
                <input type="hidden" name="import_templates" value="1">
                
                <div class="upload-area" id="dropZone">
                    <input type="file" name="html_files[]" class="upload-input" accept=".html" multiple required onchange="showFileCount(this)">
                    <i class="fas fa-file-code" style="font-size: 2.5rem; color: var(--border-strong); margin-bottom: 1rem;"></i>
                    <div id="uploadText" style="font-weight: 500; color: var(--text-main);">
                        <?= et('Click to select or drag & drop files') ?>
                    </div>
                    <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.5rem;">
                        <?= eth('Files will be renamed to {pattern}', ['pattern' => '<code>signature_*.html</code>']) ?>
                    </div>
                </div>
                
                <div style="display:flex; justify-content:flex-end; gap:0.5rem; margin-top: 1.5rem;">
                    <button type="button" class="btn btn-danger" style="background:var(--bg-white); color:var(--text-main); border:1px solid var(--border);" onclick="closeImportModal()"><?= et('Cancel') ?></button>
                    <button type="submit" class="btn btn-primary"><?= et('Start Import') ?></button>
                </div>
            </form>
        </div>
    </div>

    <script src="<?= assetUrl('js/post-action.js') ?>"></script>
    <script>
    // --- JS: Toggle Rename Row ---
    function toggleRename(id) {
        document.querySelectorAll('.rename-row').forEach(el => el.style.display = 'none');
        const row = document.getElementById('rename-' + id);
        row.style.display = (row.style.display === 'none' || row.style.display === '') ? 'table-row' : 'none';
    }
    
    // --- JS: Modal Logic ---
    const modal = document.getElementById('importModal');
    function openImportModal() { modal.style.display = 'flex'; }
    function closeImportModal() { modal.style.display = 'none'; }
    window.onclick = function(event) { if (event.target == modal) closeImportModal(); }

    // --- JS: File Input Visuals ---
    function showFileCount(input) {
        const text = document.getElementById('uploadText');
        if (input.files && input.files.length > 0) {
            text.innerHTML = `<strong>${input.files.length}</strong> ` + <?= tj('file(s) selected') ?>;
            text.style.color = 'var(--success-text)';
        } else {
            text.innerHTML = <?= tj('Click to select or drag & drop files') ?>;
            text.style.color = 'var(--text-main)';
        }
    }
    
    // --- JS: Drag & Drop Visuals ---
    const dropZone = document.getElementById('dropZone');
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = 'var(--primary)';
        dropZone.style.background = 'var(--bg-hover)';
    });
    dropZone.addEventListener('dragleave', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = 'var(--border-strong)';
        dropZone.style.background = 'var(--bg-subtle)';
    });
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = 'var(--success-text)'; // Success green
        dropZone.style.background = 'var(--success-bg)';
        
        // Pass dropped files to input
        const input = dropZone.querySelector('input');
        input.files = e.dataTransfer.files;
        showFileCount(input);
    });

    </script>
</body>
</html>
