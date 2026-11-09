<?php
/**
 * CSV import: upload + preview. The confirmed rows are written by process_import.php.
 * Protections: login, CSRF, target user check, upload size/type/row limits, per-row validation.
 */

require_once 'includes/config.php';
require_once 'includes/tag_picker.php';
requireLogin();

// --- CANCEL LOGIC (Reset Session) ---
if (isset($_GET['cancel'])) {
    unset($_SESSION['preview_data']);
    unset($_SESSION['import_params']);
    header('Location: csv_import.php');
    exit;
}

// Access Control
$is_admin = isAdmin();
$user_id = (int)$_SESSION['user_id'];

// Load Users (Admin only)
$users = [];
if ($is_admin) {
    $stmt = $db->prepare("SELECT id, username, full_name FROM users WHERE is_active = 1 ORDER BY username");
    $result = $stmt->execute();
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $users[] = $row;
    }
}

// Signature templates (only signature_*.html, never the mail wrapper)
$templates = [];
foreach (listSignatureTemplates() as $file) {
    $templates[$file] = templateDisplayName($file);
}

// Initialize Variables
$error = popFlash('error');
$success = '';
$preview_data = [];
$total_rows = 0;
$valid_rows = 0;
$form_user_id = $user_id;
$form_template = getDefaultTemplateName();
$form_tag = ['id' => 0, 'new' => '', 'color' => 'blue', 'error' => ''];

const CSV_MAX_FILE_BYTES = 2097152;  // 2 MB
const CSV_MAX_ROWS       = 2000;

/**
 * True if the user id exists and is active.
 */
function importTargetExists($db, int $id): bool
{
    $st = $db->prepare('SELECT COUNT(*) FROM users WHERE id = ? AND is_active = 1');
    $st->bindValue(1, $id, SQLITE3_INTEGER);
    return (int)$st->execute()->fetchArray(SQLITE3_NUM)[0] > 0;
}

// ---------------------------------------------------------
// PROCESS POST REQUEST
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    requireCsrf();

    $target_user_id = (int)($_POST['user_id'] ?? $user_id);
    $template = resolveTemplateName($_POST['template'] ?? '');
    $action = $_POST['action'] ?? 'preview';

    $form_user_id = $target_user_id;
    $form_template = $template;
    // Optional tag (administrators only). On "import" the choice made at upload time is used.
    $tagChoice = ($action === 'import' && isset($_SESSION['import_params']['tag']))
        ? $_SESSION['import_params']['tag']
        : resolveImportTagChoice($db, $_POST);
    $form_tag = $tagChoice;

    if (!$is_admin && $target_user_id !== (int)$user_id) {
        // Permission check: users can only import for themselves.
        $error = t('Access Denied: You can only import for yourself.');
    } elseif (!importTargetExists($db, $target_user_id)) {
        $error = t('The selected user does not exist or is not active.');
    }
    // Action: confirm the import of the previewed rows
    elseif ($tagChoice['error'] !== '') {
        $error = $tagChoice['error'];
    }
    elseif ($action === 'import' && isset($_SESSION['preview_data'])) {
        $preview_data = $_SESSION['preview_data'];
        $valid_data = array_filter($preview_data, function ($row) { return !empty($row['is_valid']); });

        if (count($valid_data) > 0) {
            $_SESSION['import_data'] = [
                'user_id'  => $target_user_id,
                'template' => $template,
                'tag'      => $tagChoice,
                'rows'     => array_values($valid_data),
            ];
            unset($_SESSION['preview_data'], $_SESSION['import_params']);
            header('Location: process_import.php');
            exit;
        }
        $error = t('No valid data to import.');
    }
    // Action: upload + preview
    elseif ($action === 'preview' && isset($_FILES['csv_file'])) {
        $upload = $_FILES['csv_file'];
        if (empty($upload['tmp_name']) || !is_uploaded_file($upload['tmp_name']) || ($upload['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
            $error = t('No file selected or upload failed.');
        } elseif ($upload['size'] > CSV_MAX_FILE_BYTES) {
            $error = t('File too large (Max 2MB).');
        } else {
            $file_type = function_exists('mime_content_type') ? mime_content_type($upload['tmp_name']) : 'text/plain';
            if (!in_array($file_type, ['text/plain', 'text/csv', 'application/csv', 'application/vnd.ms-excel', 'inode/x-empty'], true)
                || !preg_match('/\.csv$/i', (string)$upload['name'])) {
                $error = t('Invalid file type. Please upload a CSV file.');
            } elseif (($handle = fopen($upload['tmp_name'], 'r')) === false) {
                $error = t('The file could not be read.');
            } else {
                // Skip a UTF-8 BOM and detect the delimiter (Excel in German locales writes ";")
                $bom = fread($handle, 3);
                if ($bom !== "\xEF\xBB\xBF") rewind($handle);
                $firstLine = (string)fgets($handle);
                rewind($handle);
                if ($bom === "\xEF\xBB\xBF") fread($handle, 3);
                $delimiter = substr_count($firstLine, ';') > substr_count($firstLine, ',') ? ';' : ',';

                $headers = fgetcsv($handle, 4096, $delimiter);
                if (!$headers) {
                    $error = t('Empty or invalid CSV file.');
                } else {
                    $expected_columns = ['name', 'role', 'email', 'phone'];
                    $column_map = [];
                    foreach ($headers as $index => $header) {
                        $h = mb_strtolower(trim((string)$header), 'UTF-8');
                        if (in_array($h, $expected_columns, true)) $column_map[$h] = $index;
                    }
                    $missing = array_diff($expected_columns, array_keys($column_map));
                    if ($missing) {
                        $error = t('Missing required columns: {columns}', ['columns' => implode(', ', $missing)]);
                    } else {
                        $row_num = 1;
                        while (($data = fgetcsv($handle, 4096, $delimiter)) !== false) {
                            $row_num++;
                            if (count(array_filter($data, function ($v) { return trim((string)$v) !== ''; })) === 0) continue; // skip empty lines
                            if (count($preview_data) >= CSV_MAX_ROWS) {
                                $error = t('Only the first {max} rows are processed per import.', ['max' => CSV_MAX_ROWS]);
                                break;
                            }

                            // Values are stored raw (output is escaped when rendered).
                            [$clean, $row_errors] = validateSignatureFields([
                                'name'  => $data[$column_map['name']]  ?? '',
                                'role'  => $data[$column_map['role']]  ?? '',
                                'email' => $data[$column_map['email']] ?? '',
                                'phone' => $data[$column_map['phone']] ?? '',
                            ], true);

                            $is_valid = empty($row_errors);
                            if ($is_valid) $valid_rows++;

                            $preview_data[] = [
                                'row' => $row_num - 1,
                                'name' => $clean['name'], 'role' => $clean['role'],
                                'email' => $clean['email'], 'phone' => $clean['phone'],
                                'errors' => $row_errors, 'is_valid' => $is_valid,
                            ];
                        }
                        fclose($handle);

                        $_SESSION['preview_data'] = $preview_data;
                        $_SESSION['import_params'] = ['user_id' => $target_user_id, 'template' => $template, 'tag' => $tagChoice];
                        $total_rows = count($preview_data);
                    }
                }
            }
        }
    }
}

// Recover Session Data
if (empty($preview_data) && isset($_SESSION['preview_data'])) {
    $preview_data = $_SESSION['preview_data'];
    $total_rows = count($preview_data);
    $valid_rows = count(array_filter($preview_data, fn($row) => $row['is_valid']));
    if (isset($_SESSION['import_params'])) {
        $form_user_id = $_SESSION['import_params']['user_id'];
        $form_template = $_SESSION['import_params']['template'];
        $form_tag = $_SESSION['import_params']['tag'] ?? $form_tag;
    }
}

$csrf_token = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="<?= e(currentLang()) ?>" dir="<?= e(langDir()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= et('CSV Import') ?> - SubSignature</title>
    <?= i18nHead() ?>
    <script src="<?= assetUrl('js/theme.js') ?>"></script>
    <link rel="stylesheet" href="<?= assetUrl('css/theme.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/style.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/all.min.css') ?>">
    <style>
        /* Modern Upload Area Styling */
        .upload-area {
            border: 2px dashed var(--border-strong);
            border-radius: 12px;
            background: var(--bg-subtle);
            padding: 3rem 2rem;
            text-align: center;
            cursor: pointer;
            transition: all 0.2s ease;
            position: relative;
        }
        .upload-area:hover, .upload-area.dragover {
            border-color: var(--primary);
            background: var(--bg-hover);
        }
        .upload-icon {
            font-size: 3rem;
            color: var(--text-faint);
            margin-bottom: 1rem;
            transition: color 0.2s;
        }
        .upload-area:hover .upload-icon { color: var(--primary); }
        
        .upload-text { font-size: 1.1rem; font-weight: 600; color: var(--text-main); margin-bottom: 0.5rem; }
        .upload-hint { font-size: 0.85rem; color: var(--text-muted); }
        
        /* Hide default file input */
        #csv_file {
            position: absolute; width: 100%; height: 100%; top: 0; left: 0;
            opacity: 0; cursor: pointer;
        }

        /* File Selected State */
        .file-selected-info {
            display: none; /* Hidden by default */
            margin-top: 1rem;
            background: var(--bg-white); padding: 0.75rem; border-radius: 8px;
            border: 1px solid var(--border);
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            align-items: center; gap: 0.75rem;
            text-align: left;
        }
        .file-icon { color: #10b981; font-size: 1.25rem; }
        .filename { font-weight: 600; color: var(--text-main); font-size: 0.9rem; }
        .filesize { color: var(--text-muted); font-size: 0.8rem; }

        /* Preview Table & Stats */
        .preview-stats { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
        .stat-badge { padding: 0.5rem 1rem; border-radius: 8px; font-weight: 600; font-size: 0.9rem; display: flex; align-items: center; gap: 0.5rem; }
        .stat-valid { background: var(--success-bg); color: var(--success-text); }
        .stat-error { background: var(--danger-bg); color: var(--danger-text); }
        .stat-total { background: var(--bg-subtle); color: var(--text-main); }
        
        .preview-table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
        .preview-table th { background: var(--bg-subtle); padding: 0.75rem; text-align: left; font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); }
        .preview-table td { padding: 0.75rem; border-bottom: 1px solid var(--border); }
        .preview-table tr.row-valid td { background: rgba(220, 252, 231, 0.3); }
        .preview-table tr.row-error td { background: rgba(254, 226, 226, 0.3); }
        .error-list { margin: 0; padding-left: 1.2rem; color: var(--danger-text); font-size: 0.8rem; }
        
        .help-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-top: 1rem; }
        .help-card { background: var(--bg-subtle); padding: 1rem; border-radius: 8px; text-align: center; text-decoration: none; color: var(--text-main); border: 1px solid var(--border); transition: all 0.2s; cursor: pointer; }
        .help-card:hover { border-color: var(--primary); transform: translateY(-2px); box-shadow: var(--shadow); }
        .help-icon { font-size: 1.5rem; color: var(--primary); margin-bottom: 0.5rem; display: block; }

        .alert { padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; display: flex; gap: 0.75rem; align-items: center; }
        .alert-success { background: var(--success-bg); color: var(--success-text); border: 1px solid var(--success-border); }
        .alert-error { background: var(--danger-bg); color: var(--danger-text); border: 1px solid var(--danger-border); }
        
        .form-actions-centered { display: flex; justify-content: center; gap: 1rem; margin-top: 2rem; padding-top: 1.5rem; border-top: 1px solid var(--border); }
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
            </div>
    </aside>

    <main class="main-content">
        
        <header class="page-header">
            <h2><?= et('Batch Import') ?></h2>
            <p><?= et('Upload a CSV file to generate multiple signatures at once.') ?></p>
        </header>

        <?php if ($error): ?>
            <div class="alert alert-error"><i class="fas fa-exclamation-circle"></i> <?php echo e($error); ?></div>
        <?php endif; ?>
        
        <?php if (isset($_GET['success'])): ?>
            <div class="alert alert-success"><i class="fas fa-check-circle"></i> <?= et('Successfully imported {count} signatures!', ['count' => (int)$_GET['success']]) ?></div>
        <?php endif; ?>

        <section class="card">
            <div class="card-header">
                <h3><i class="fas fa-cloud-upload-alt"></i> <?= et('Import Configuration') ?></h3>
            </div>
            
            <form method="POST" enctype="multipart/form-data" id="uploadForm">
                <input type="hidden" name="csrf_token" value="<?php echo e($csrf_token); ?>">
                
                <div class="form-grid">
                    <div class="form-group" style="grid-column: 1 / -1;">
                        <label><?= et('CSV File Upload') ?></label>
                        <div class="upload-area" id="dropZone">
                            <input type="file" id="csv_file" name="csv_file" accept=".csv,text/csv" required>
                            
                            <div class="upload-content">
                                <i class="fas fa-file-csv upload-icon"></i>
                                <div class="upload-text"><?= et('Click to upload or drag & drop') ?></div>
                                <div class="upload-hint"><?= et('Max file size: 2MB. Format: UTF-8 CSV') ?></div>
                            </div>
                            
                            <div class="file-selected-info" id="fileInfo">
                                <i class="fas fa-check-circle file-icon"></i>
                                <div>
                                    <div class="filename" id="fileNameDisplay"><?= et('data.csv') ?></div>
                                    <div class="filesize" id="fileSizeDisplay">12 KB</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label for="template"><?= et('Signature Template') ?></label>
                        <select id="template" name="template" required>
                            <?php foreach ($templates as $filename => $display_name): ?>
                                <option value="<?php echo e($filename); ?>" <?php echo ($filename == $form_template) ? 'selected' : ''; ?>>
                                    <?php echo e($display_name); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <?php if ($is_admin && !empty($users)): ?>
                    <div class="form-group">
                        <label for="user_id"><?= et('Assign to User') ?></label>
                        <select id="user_id" name="user_id">
                            <?php foreach ($users as $user): ?>
                                <option value="<?php echo (int)$user['id']; ?>" <?php echo ($user['id'] == $form_user_id) ? 'selected' : ''; ?>>
                                    <?php echo e($user['full_name'] ?: $user['username']); ?> (<?php echo e($user['username']); ?>)
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <?php else: ?>
                        <input type="hidden" name="user_id" value="<?php echo (int)$user_id; ?>">
                    <?php endif; ?>

                    <?php if ($is_admin): ?>
                    <div class="form-group">
                        <label><?= et('Tag for imported signatures') ?></label>
                        <?php echo renderTagPicker($db, $form_tag, ''); ?>
                    </div>
                    <?php endif; ?>
                </div>
                
                <div class="form-actions">
                    <input type="hidden" name="action" value="preview">
                    <button type="button" onclick="resetForm()" class="btn btn-danger"><i class="fas fa-trash-alt"></i> <?= et('Clear') ?></button>
                    <button type="submit" class="btn btn-primary"><i class="fas fa-eye"></i> <?= et('Preview Import') ?></button>
                </div>
            </form>
        </section>
        
        <?php if ($total_rows > 0): ?>
        <section class="card">
            <div class="card-header" style="display: flex; justify-content: space-between; align-items: center;">
                <h3><i class="fas fa-table"></i> <?= et('Data Validation') ?></h3>
                <?php $previewTag = ($form_tag['new'] !== '') ? $form_tag['new'] : importTagName($db, (int)$form_tag['id']); ?>
                <?php if ($previewTag !== ''): ?>
                <span style="font-size:0.85rem; color:var(--text-muted);"><i class="fas fa-tag"></i> <?= et('Tag') ?>: <strong><?php echo e($previewTag); ?></strong></span>
                <?php endif; ?>
                
                <?php if ($valid_rows > 0): ?>
                <form method="POST" style="margin:0;">
                    <input type="hidden" name="csrf_token" value="<?php echo e($csrf_token); ?>">
                    <input type="hidden" name="user_id" value="<?php echo e($form_user_id); ?>">
                    <input type="hidden" name="template" value="<?php echo e($form_template); ?>">
                    <input type="hidden" name="action" value="import">
                    
                    <button type="submit" class="btn btn-success btn-sm" style="font-size: 0.9rem;">
                        <i class="fas fa-file-import"></i> <?= et('Start Import') ?>
                    </button>
                </form>
                <?php endif; ?>
            </div>
            
            <div class="preview-stats">
                <div class="stat-badge stat-valid"><i class="fas fa-check-circle"></i> <?= et('{count} Valid', ['count' => $valid_rows]) ?></div>
                <div class="stat-badge stat-error"><i class="fas fa-exclamation-triangle"></i> <?= et('{count} Errors', ['count' => $total_rows - $valid_rows]) ?></div>
                <div class="stat-badge stat-total"><i class="fas fa-list"></i> <?= et('{count} Total', ['count' => $total_rows]) ?></div>
            </div>

            <div class="table-responsive">
                <table class="preview-table">
                    <thead>
                        <tr>
                            <th style="width:50px">#</th>
                            <th><?= et('Name') ?></th>
                            <th><?= et('Role') ?></th>
                            <th><?= et('Email') ?></th>
                            <th><?= et('Phone') ?></th>
                            <th><?= et('Status') ?></th>
                            <th><?= et('Issues') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($preview_data as $row): ?>
                        <tr class="<?php echo $row['is_valid'] ? 'row-valid' : 'row-error'; ?>">
                            <td><b><?php echo (int)$row['row']; ?></b></td>
                            <td><?php echo e($row['name']); ?></td>
                            <td><?php echo e($row['role']); ?></td>
                            <td><?php echo e($row['email']); ?></td>
                            <td><?php echo e($row['phone']); ?></td>
                            <td>
                                <?php echo $row['is_valid'] ? 
                                    '<span style="color:var(--success-text); font-weight:700; font-size:0.8rem;">VALID</span>' : 
                                    '<span style="color:var(--danger-text); font-weight:700; font-size:0.8rem;">ERROR</span>'; ?>
                            </td>
                            <td>
                                <?php if (!empty($row['errors'])): ?>
                                    <ul class="error-list">
                                        <?php foreach ($row['errors'] as $err): ?>
                                            <li><?php echo e($err); ?></li>
                                        <?php endforeach; ?>
                                    </ul>
                                <?php else: ?>
                                    <span style="color:var(--text-faint);">-</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            
            <?php if ($valid_rows > 0): ?>
                <div class="form-actions-centered">
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="<?php echo e($csrf_token); ?>">
                        <input type="hidden" name="user_id" value="<?php echo e($form_user_id); ?>">
                        <input type="hidden" name="template" value="<?php echo e($form_template); ?>">
                        <input type="hidden" name="action" value="import">
                        
                        <button type="button" onclick="window.location.href='csv_import.php?cancel=1'" class="btn btn-danger"><i class="fas fa-times"></i> <?= et('Cancel') ?></button>
                        <button type="submit" class="btn btn-success"><i class="fas fa-file-import"></i> <?= et('Confirm & Import') ?></button>
                    </form>
                </div>
            <?php endif; ?>
        </section>
        <?php endif; ?>
        
        <section class="card" style="background:transparent; border:none; box-shadow:none; padding:0;">
            <div class="help-grid">
                <button onclick="downloadSample()" class="help-card">
                    <span class="help-icon"><i class="fas fa-download"></i></span>
                    <span class="help-text"><?= et('Download Sample CSV') ?></span>
                </button>
                <button onclick="showCSVGuide()" class="help-card">
                    <span class="help-icon"><i class="fas fa-info-circle"></i></span>
                    <span class="help-text"><?= et('View Format Guide') ?></span>
                </button>
            </div>
        </section>

    </main>
    
    <script>
    // Drag & Drop Visuals and File Selection
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('csv_file');
    const fileInfo = document.getElementById('fileInfo');
    const fileNameDisplay = document.getElementById('fileNameDisplay');
    const fileSizeDisplay = document.getElementById('fileSizeDisplay');
    const uploadContent = document.querySelector('.upload-content');

    // Show visual feedback when file is selected
    fileInput.addEventListener('change', function(e) {
        if (this.files && this.files[0]) {
            const file = this.files[0];
            
            // Security: Client-side size check
            if (file.size > 2 * 1024 * 1024) {
                alert(<?= tj('File is too large! Maximum allowed is 2MB.') ?>);
                this.value = '';
                return;
            }

            uploadContent.style.display = 'none'; // Hide default text
            fileInfo.style.display = 'flex';      // Show file info
            
            fileNameDisplay.textContent = file.name;
            fileSizeDisplay.textContent = (file.size / 1024).toFixed(1) + ' KB';
            
            dropZone.style.borderColor = '#10b981'; // Green border
            dropZone.style.background = 'var(--success-bg)';
        }
    });

    // Reset Form
    function resetForm() {
        if (confirm(<?= tj('Clear form settings?') ?>)) {
            window.location.href = 'csv_import.php?cancel=1';
        }
    }
    
    // Help Functions
    function showCSVGuide() {
        alert(<?= tj('CSV REQUIREMENTS:

1. Required Headers:
   name, role, email, phone

2. Format:
   - Comma separated values
   - UTF-8 Encoding

Example:
name,role,email,phone
John Doe,Manager,john@test.com,+123456789') ?>);
    }
    
    function downloadSample() {
        const csvContent = 'name,role,email,phone\n' +
                         'John Doe,Senior Developer,john@example.com,+49 89 123456\n' +
                         'Jane Smith,Marketing Manager,jane@example.com,+49 89 654321';
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'sample_import.csv';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    }
    
    // Loading Spinner on Submit
    document.getElementById('uploadForm').addEventListener('submit', function() {
        if(fileInput.files.length === 0) return; // Don't spin if no file
        const btn = this.querySelector('button[type="submit"]');
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ' + <?= tj('Processing...') ?>;
        btn.disabled = true;
    });
    </script>
</body>
</html>
