<?php
// admin_templates.php

require_once 'includes/config.php';
requireAdmin();

$message = '';
$error = '';

// ---------------------------------------------------------
// SECURITY: CSRF Token Generation
// ---------------------------------------------------------
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

// ---------------------------------------------------------
// HELPER: Default Template Logic (stored in a text file)
// ---------------------------------------------------------
$default_config_file = __DIR__ . '/templates/default_config.txt';

function getCurrentDefault($file) {
    if (file_exists($file)) {
        return trim(file_get_contents($file));
    }
    return 'signature_default.html'; // Fallback
}

$current_default = getCurrentDefault($default_config_file);

// ---------------------------------------------------------
// 1. ACTION: SET DEFAULT TEMPLATE
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['set_default'])) {
    // Security: CSRF Check
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $error = "Security Error: Invalid CSRF Token.";
    } else {
        // Security: Sanitize input (basename prevents path traversal)
        $new_default = basename($_POST['template_name']);
        
        if (file_exists(__DIR__ . '/templates/' . $new_default)) {
            if (file_put_contents($default_config_file, $new_default) !== false) {
                $message = "Default template updated to: " . htmlspecialchars($new_default);
                $current_default = $new_default;
            } else {
                $error = "Could not save setting. Check file permissions.";
            }
        } else {
            $error = "Template file not found.";
        }
    }
}

// ---------------------------------------------------------
// 2. ACTION: IMPORT TEMPLATES
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['import_templates'])) {
    
    // Security: CSRF Check
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $error = "Security Error: Invalid CSRF Token.";
    } 
    // Check if files exist
    elseif (isset($_FILES['html_files'])) {
        $uploaded_files = $_FILES['html_files'];
        $success_count = 0;
        $error_details = [];

        for ($i = 0; $i < count($uploaded_files['name']); $i++) {
            $filename = $uploaded_files['name'][$i];
            $tmp_name = $uploaded_files['tmp_name'][$i];
            $file_error = $uploaded_files['error'][$i];

            if ($file_error === UPLOAD_ERR_OK) {
                
                // Security: Validate Extension (.html only)
                $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
                if ($ext !== 'html') {
                    $error_details[] = "$filename: Only .html files allowed.";
                    continue;
                }

                // Security: Validate Content (No PHP tags allowed)
                $content = file_get_contents($tmp_name);
                if (strpos($content, '<?php') !== false || strpos($content, '<?=') !== false) {
                    $error_details[] = "$filename: Contains PHP code (Security Violation).";
                    continue;
                }

                // Security: Sanitize Filename
                // Remove special chars, ensure lower case
                $safe_name = preg_replace('/[^a-z0-9_]/', '', strtolower(pathinfo($filename, PATHINFO_FILENAME)));
                
                // Enforce prefix 'signature_'
                if (strpos($safe_name, 'signature_') !== 0) {
                    $safe_name = 'signature_' . $safe_name;
                }
                $final_name = $safe_name . '.html';
                $target_path = 'templates/' . $final_name;

                // Prevent silent overwriting
                if (file_exists($target_path)) {
                    $final_name = $safe_name . '_' . time() . '.html';
                    $target_path = 'templates/' . $final_name;
                }

                if (move_uploaded_file($tmp_name, $target_path)) {
                    $success_count++;
                } else {
                    $error_details[] = "$filename: Failed to move file.";
                }
            }
        }

        if ($success_count > 0) {
            $message = "Successfully imported $success_count template(s).";
        }
        if (!empty($error_details)) {
            $error = implode('<br>', $error_details);
        }
    }
}

// ---------------------------------------------------------
// 3. ACTION: RENAME TEMPLATE
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['rename_template'])) {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $error = "Security Error: Invalid Token.";
    } else {
        $old_name = basename($_POST['old_name']);
        $new_name = trim($_POST['new_name']);
        
        // Validation
        if (empty($new_name)) {
            $error = "New name is required!";
        } elseif (!preg_match('/^signature_[a-z0-9_]+\.html$/i', $new_name)) {
            $error = "Format must be: signature_name.html (lowercase, alphanumeric, underscores)";
        } else {
            $old_path = 'templates/' . $old_name;
            $new_path = 'templates/' . $new_name;
            
            if (!file_exists($old_path)) $error = "Original file not found!";
            elseif (file_exists($new_path)) $error = "Name already exists!";
            elseif (rename($old_path, $new_path)) {
                
                // Update default config if we renamed the default template
                if ($old_name === $current_default) {
                    file_put_contents($default_config_file, $new_name);
                    $current_default = $new_name;
                }
                
                // Update Database references
                $stmt = $db->prepare("UPDATE user_signatures SET template = ? WHERE template = ?");
                $stmt->bindValue(1, $new_name, SQLITE3_TEXT);
                $stmt->bindValue(2, $old_name, SQLITE3_TEXT);
                $stmt->execute();
                
                $message = "Template renamed successfully.";
            } else {
                $error = "Error renaming file.";
            }
        }
    }
}

// ---------------------------------------------------------
// 4. ACTION: DELETE TEMPLATE
// ---------------------------------------------------------
if (isset($_GET['delete'])) {
    if (!isset($_GET['token']) || !hash_equals($_SESSION['csrf_token'], $_GET['token'])) {
        $error = "Security Error: Invalid Token.";
    } else {
        $template = basename($_GET['delete']);
        $template_path = 'templates/' . $template;
        
        // Prevent deleting the ACTIVE default
        if ($template === $current_default) {
            $error = "Cannot delete the active default template! Please set another default first.";
        } elseif (file_exists($template_path)) {
            if (unlink($template_path)) {
                $message = "Template deleted successfully.";
            } else {
                $error = "Error deleting file.";
            }
        } else {
            $error = "Template not found!";
        }
    }
    // Clean Redirect to remove GET params
    $param = $error ? 'error='.urlencode($error) : 'message='.urlencode($message);
    header('Location: admin_templates.php?' . $param);
    exit;
}

// ---------------------------------------------------------
// 5. DATA LOADING & SORTING
// ---------------------------------------------------------
$templates = [];
$template_files = glob('templates/*.html');

if ($template_files) {
    foreach ($template_files as $file) {
        $filename = basename($file);
        
        // Count usage in DB
        $stmt = $db->prepare("SELECT COUNT(*) as count FROM user_signatures WHERE template = ?");
        $stmt->bindValue(1, $filename, SQLITE3_TEXT);
        $result = $stmt->execute();
        $usage = $result->fetchArray(SQLITE3_ASSOC)['count'];
        
        $templates[] = [
            'filename' => $filename,
            'display_name' => ucfirst(str_replace(['signature_', '.html', '_'], ['', '', ' '], $filename)),
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

if (isset($_GET['message'])) $message = $_GET['message'];
if (isset($_GET['error'])) $error = $_GET['error'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Template Management - SubSignature</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/all.min.css">
    
    <style>
        .rename-row { display: none; background: #f8fafc; }
        .inline-form { display: flex; align-items: center; justify-content: flex-end; gap: 10px; padding: 10px; }
        
        .template-badge { padding: 4px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; display: inline-block; margin-right: 5px; }
        .badge-default { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; } /* Green for Active Default */
        .badge-active { background: #e0f2fe; color: #0284c7; } /* Blue for used templates */
        .badge-unused { background: #f1f5f9; color: #64748b; }
        
        /* Star Button Styles */
        .btn-star { background: transparent; border: 1px solid #cbd5e1; color: #cbd5e1; cursor: pointer; border-radius: 4px; padding: 4px 8px;}
        .btn-star:hover { border-color: #eab308; color: #eab308; }
        .btn-star.active { background: #fef08a; border-color: #eab308; color: #ca8a04; pointer-events: none; }
        
        /* Modal Styles */
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.5); display: none; justify-content: center; align-items: center; z-index: 1000; backdrop-filter: blur(2px); }
        .modal-box { background: white; width: 90%; max-width: 500px; padding: 2rem; border-radius: 12px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1); position: relative; }
        .modal-header h3 { margin: 0; color: var(--text-main); font-size: 1.25rem; }
        .modal-close { position: absolute; top: 1rem; right: 1rem; cursor: pointer; color: var(--text-muted); font-size: 1.2rem; }
        
        /* Upload Area */
        .upload-area { border: 2px dashed #cbd5e1; border-radius: 8px; padding: 2rem; text-align: center; cursor: pointer; transition: all 0.2s; background: #f8fafc; position: relative; margin-top: 1rem; }
        .upload-area:hover { border-color: var(--primary); background: #eff6ff; }
        .upload-input { position: absolute; width: 100%; height: 100%; top: 0; left: 0; opacity: 0; cursor: pointer; }
    </style>
</head>
<body>

    <aside class="sidebar">
        <?php include 'includes/navbar.php'; ?>
        
        <div class="sidebar-footer">
            <div class="user-profile">
                <div class="avatar"><?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?></div>
                <div class="user-info">
                    <div><?php echo htmlspecialchars($_SESSION['username']); ?></div>
                    <span>Administrator</span>
                </div>
            </div>
            <a href="logout.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> <span>Sign Out</span></a>
        </div>
    </aside>

    <main class="main-content">
        
        <header class="page-header">
            <h2>Template Management</h2>
            <p>Manage, rename, import, and set default signature templates.</p>
        </header>

        <?php if ($message): ?>
            <div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="alert alert-error"><i class="fas fa-exclamation-circle"></i> <?php echo $error; ?></div>
        <?php endif; ?>

        <div class="form-grid" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); margin-bottom: 2rem;">
            <div class="card" style="padding: 1.5rem; text-align:center;">
                <div style="color: #64748b; margin-bottom: 0.5rem;">Total Templates</div>
                <div style="font-size: 2rem; font-weight: 700; color: #1e293b;"><?php echo count($templates); ?></div>
            </div>
            <div class="card" style="padding: 1.5rem; text-align:center;">
                <div style="color: #64748b; margin-bottom: 0.5rem;">Total Usage</div>
                <div style="font-size: 2rem; font-weight: 700; color: #1e293b;"><?php echo array_sum(array_column($templates, 'usage')); ?></div>
            </div>
        </div>

        <section class="card">
            <div class="card-header">
                <h3><i class="fas fa-list"></i> Installed Templates</h3>
                <div style="display:flex; gap: 0.5rem;">
                    <button onclick="openImportModal()" class="btn btn-sm btn-success">
                        <i class="fas fa-file-import"></i> Import HTML
                    </button>
                    
                    <a href="template_editor.php" class="btn btn-sm btn-primary">
                        <i class="fas fa-plus"></i> New
                    </a>
                    <a href="templates/" target="_blank" class="btn btn-sm btn-secondary">
                        <i class="fas fa-folder-open"></i> Folder
                    </a>
                </div>
            </div>
            
            <div style="overflow-x: auto;">
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="background: #f8fafc; text-align: left; border-bottom: 1px solid #e2e8f0;">
                            <th style="padding: 1rem; width: 50px;">Def.</th>
                            <th style="padding: 1rem;">Name</th>
                            <th style="padding: 1rem;">Filename</th>
                            <th style="padding: 1rem;">Usage</th>
                            <th style="padding: 1rem; text-align: right;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($templates as $t): ?>
                        <tr style="border-bottom: 1px solid #e2e8f0;">
                            
                            <td style="padding: 1rem; text-align: center;">
                                <form method="POST" style="margin:0;">
                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                    <input type="hidden" name="set_default" value="1">
                                    <input type="hidden" name="template_name" value="<?php echo htmlspecialchars($t['filename']); ?>">
                                    
                                    <?php if ($t['is_default']): ?>
                                        <button type="button" class="btn-star active" title="Current Default">
                                            <i class="fas fa-star"></i>
                                        </button>
                                    <?php else: ?>
                                        <button type="submit" class="btn-star" title="Set as Default">
                                            <i class="far fa-star"></i>
                                        </button>
                                    <?php endif; ?>
                                </form>
                            </td>

                            <td style="padding: 1rem;">
                                <strong><?php echo htmlspecialchars($t['display_name']); ?></strong>
                                <?php if ($t['is_default']): ?>
                                    <span class="template-badge badge-default" style="margin-left:5px;">Default</span>
                                <?php endif; ?>
                            </td>
                            
                            <td style="padding: 1rem; color: #64748b;"><code><?php echo htmlspecialchars($t['filename']); ?></code></td>
                            
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
                                    <a href="template_editor.php?edit=<?php echo urlencode($t['filename']); ?>" class="btn btn-sm btn-primary" title="Edit"><i class="fas fa-pen"></i></a>
                                    
                                    <a href="preview_template.php?template=<?php echo urlencode($t['filename']); ?>" target="_blank" class="btn btn-sm btn-secondary" title="Preview"><i class="fas fa-eye"></i></a>
                                    
                                    <button type="button" onclick="toggleRename('<?php echo md5($t['filename']); ?>')" class="btn btn-sm btn-secondary" title="Rename"><i class="fas fa-i-cursor"></i></button>
                                    
                                    <?php if (!$t['is_default']): ?>
                                        <a href="admin_templates.php?delete=<?php echo urlencode($t['filename']); ?>&token=<?php echo $csrf_token; ?>" class="btn btn-sm btn-danger" onclick="return confirm('Really delete?')" title="Delete"><i class="fas fa-trash"></i></a>
                                    <?php else: ?>
                                        <button class="btn btn-sm btn-secondary" disabled style="opacity:0.5; cursor:not-allowed;"><i class="fas fa-trash"></i></button>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                        
                        <tr id="rename-<?php echo md5($t['filename']); ?>" class="rename-row">
                            <td colspan="5">
                                <form method="POST" class="inline-form">
                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                    <input type="hidden" name="rename_template" value="1">
                                    <input type="hidden" name="old_name" value="<?php echo htmlspecialchars($t['filename']); ?>">
                                    
                                    <span>Rename to:</span>
                                    <input type="text" name="new_name" value="<?php echo htmlspecialchars($t['filename']); ?>" required style="padding: 5px; border: 1px solid #e2e8f0; border-radius: 4px; width: 250px;">
                                    
                                    <button type="submit" class="btn btn-sm btn-primary">Save</button>
                                    <button type="button" onclick="toggleRename('<?php echo md5($t['filename']); ?>')" class="btn btn-sm btn-secondary">Cancel</button>
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
                <h3><i class="fas fa-cloud-upload-alt" style="color:var(--primary);"></i> Import Templates</h3>
                <p style="color:var(--text-muted); font-size:0.9rem; margin-top:0.5rem;">
                    Upload new HTML templates. Only <code>.html</code> files allowed.
                </p>
            </div>
            
            <form method="POST" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                <input type="hidden" name="import_templates" value="1">
                
                <div class="upload-area" id="dropZone">
                    <input type="file" name="html_files[]" class="upload-input" accept=".html" multiple required onchange="showFileCount(this)">
                    <i class="fas fa-file-code" style="font-size: 2.5rem; color: #cbd5e1; margin-bottom: 1rem;"></i>
                    <div id="uploadText" style="font-weight: 500; color: var(--text-main);">
                        Click to select or drag & drop files
                    </div>
                    <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.5rem;">
                        Files will be renamed to <code>signature_*.html</code>
                    </div>
                </div>
                
                <div style="display:flex; justify-content:flex-end; gap:0.5rem; margin-top: 1.5rem;">
                    <button type="button" class="btn btn-danger" style="background:white; color:var(--text-main); border:1px solid var(--border);" onclick="closeImportModal()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Start Import</button>
                </div>
            </form>
        </div>
    </div>

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
            text.innerHTML = `<strong>${input.files.length}</strong> file(s) selected`;
            text.style.color = '#166534';
        } else {
            text.innerHTML = 'Click to select or drag & drop files';
            text.style.color = 'var(--text-main)';
        }
    }
    
    // --- JS: Drag & Drop Visuals ---
    const dropZone = document.getElementById('dropZone');
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = 'var(--primary)';
        dropZone.style.background = '#eff6ff';
    });
    dropZone.addEventListener('dragleave', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = '#cbd5e1';
        dropZone.style.background = '#f8fafc';
    });
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = '#166534'; // Success green
        dropZone.style.background = '#f0fdf4';
        
        // Pass dropped files to input
        const input = dropZone.querySelector('input');
        input.files = e.dataTransfer.files;
        showFileCount(input);
    });

    // Auto-hide alerts
    setTimeout(() => {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(el => el.style.display = 'none');
    }, 5000);
    </script>
</body>
</html>
