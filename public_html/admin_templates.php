<?php
require_once 'includes/config.php';
requireAdmin();

$message = '';
$error = '';

// Security: CSRF Token Check
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

// --- LOGIC: DELETE TEMPLATE ---
if (isset($_GET['delete'])) {
    // 1. Verify Token
    if (!isset($_GET['token']) || !hash_equals($_SESSION['csrf_token'], $_GET['token'])) {
        $error = "Security Error: Invalid Token.";
    } else {
        // 2. Sanitize Input
        $template = basename($_GET['delete']); // Prevent Directory Traversal
        $template_path = 'templates/' . $template;
        
        if ($template === 'signature_default.html') {
            $error = "Cannot delete the default template!";
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
    // Clean Redirect to remove query params
    if ($error) header('Location: admin_templates.php?error=' . urlencode($error));
    else header('Location: admin_templates.php?message=' . urlencode($message));
    exit;
}

// --- LOGIC: RENAME TEMPLATE ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['rename_template'])) {
    // 1. Verify Token
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $error = "Security Error: Invalid Token.";
    } else {
        // 2. Sanitize Input
        $old_name = basename($_POST['old_name']);
        $new_name = trim($_POST['new_name']);
        
        // 3. Validation
        if (empty($new_name)) {
            $error = "New name is required!";
        } elseif (!preg_match('/^signature_[a-z0-9_]+\.html$/i', $new_name)) {
            $error = "Format must be: signature_name.html";
        } else {
            $old_path = 'templates/' . $old_name;
            $new_path = 'templates/' . $new_name;
            
            if (!file_exists($old_path)) {
                $error = "Original file not found!";
            } elseif (file_exists($new_path)) {
                $error = "A template with this name already exists!";
            } elseif (rename($old_path, $new_path)) {
                $message = "Template renamed successfully.";
                
                // 4. Update Database References
                // Ensures users using the old template are migrated to the new name
                $stmt = $db->prepare("UPDATE user_signatures SET template = ? WHERE template = ?");
                $stmt->bindValue(1, $new_name, SQLITE3_TEXT);
                $stmt->bindValue(2, $old_name, SQLITE3_TEXT);
                $stmt->execute();
            } else {
                $error = "Error renaming file.";
            }
        }
    }
}

// --- LOAD DATA ---
$templates = [];
// Security: glob() is safe here as it only reads the specific directory
$template_files = glob('templates/*.html');

if ($template_files) {
    foreach ($template_files as $file) {
        $filename = basename($file);
        $content = file_get_contents($file);
        $size = filesize($file);
        $modified = filemtime($file);
        
        // Count usage in DB
        $stmt = $db->prepare("SELECT COUNT(*) as count FROM user_signatures WHERE template = ?");
        $stmt->bindValue(1, $filename, SQLITE3_TEXT);
        $result = $stmt->execute();
        $usage = $result->fetchArray(SQLITE3_ASSOC)['count'];
        
        $templates[] = [
            'filename' => $filename,
            'display_name' => ucfirst(str_replace(['signature_', '.html', '_'], ['', '', ' '], $filename)),
            'size' => $size,
            'modified' => $modified,
            'usage' => $usage
        ];
    }
}

// Sort by usage (most used first)
usort($templates, function($a, $b) { return $b['usage'] - $a['usage']; });
$default_template = 'signature_default.html';

// Capture messages from redirect
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
        .badge-default { background: #ffedd5; color: #9a3412; }
        .badge-active { background: #dcfce7; color: #166534; }
        .badge-unused { background: #f1f5f9; color: #64748b; }
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
                    <div><?php echo htmlspecialchars($_SESSION['username']); ?></div>
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
            <h2>Template Management</h2>
            <p>Manage, rename, and delete HTML signature templates.</p>
        </header>

        <?php if ($message): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="alert alert-error">
                <i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error); ?>
            </div>
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
                            <th style="padding: 1rem;">Name</th>
                            <th style="padding: 1rem;">Filename</th>
                            <th style="padding: 1rem;">Status</th>
                            <th style="padding: 1rem; text-align: right;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($templates as $t): ?>
                        <tr style="border-bottom: 1px solid #e2e8f0;">
                            <td style="padding: 1rem;"><strong><?php echo htmlspecialchars($t['display_name']); ?></strong></td>
                            <td style="padding: 1rem; color: #64748b;"><code><?php echo htmlspecialchars($t['filename']); ?></code></td>
                            
                            <td style="padding: 1rem;">
                                <?php 
                                    // 1. Show 'Default' Badge if applicable
                                    if ($t['filename'] === $default_template) {
                                        echo '<span class="template-badge badge-default">Default</span>';
                                    }
                                    
                                    // 2. Show 'Users' Badge if used (regardless if default or not)
                                    if ($t['usage'] > 0) {
                                        echo '<span class="template-badge badge-active">' . $t['usage'] . ' Users</span>';
                                    } 
                                    // 3. Only show 'Unused' if NOT default AND NOT used
                                    elseif ($t['filename'] !== $default_template) {
                                        echo '<span class="template-badge badge-unused">Unused</span>';
                                    }
                                ?>
                            </td>
                            
                            <td style="padding: 1rem; text-align: right;">
                                <div style="display: inline-flex; gap: 0.5rem;">
                                    <a href="template_editor.php?edit=<?php echo urlencode($t['filename']); ?>" class="btn btn-sm btn-primary" title="Edit">
                                        <i class="fas fa-pen"></i>
                                    </a>
                                    
                                    <a href="preview_template.php?template=<?php echo urlencode($t['filename']); ?>" target="_blank" class="btn btn-sm btn-secondary" title="Preview">
                                        <i class="fas fa-eye"></i>
                                    </a>
                                    
                                    <button type="button" onclick="toggleRename('<?php echo md5($t['filename']); ?>')" class="btn btn-sm btn-secondary" title="Rename">
                                        <i class="fas fa-i-cursor"></i>
                                    </button>
                                    
                                    <?php if ($t['filename'] !== $default_template): ?>
                                        <a href="admin_templates.php?delete=<?php echo urlencode($t['filename']); ?>&token=<?php echo $csrf_token; ?>" 
                                           class="btn btn-sm btn-danger" 
                                           onclick="return confirm('Really delete?')" 
                                           title="Delete">
                                            <i class="fas fa-trash"></i>
                                        </a>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                        
                        <tr id="rename-<?php echo md5($t['filename']); ?>" class="rename-row">
                            <td colspan="4">
                                <form method="POST" class="inline-form">
                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                    <input type="hidden" name="old_name" value="<?php echo htmlspecialchars($t['filename']); ?>">
                                    
                                    <span>Rename to:</span>
                                    <input type="text" name="new_name" value="<?php echo htmlspecialchars($t['filename']); ?>" required style="padding: 5px; border: 1px solid #e2e8f0; border-radius: 4px;">
                                    
                                    <button type="submit" name="rename_template" class="btn btn-sm btn-primary">Save</button>
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

    <script>
    function toggleRename(id) {
        // Hide all other rename rows
        document.querySelectorAll('.rename-row').forEach(el => el.style.display = 'none');
        
        // Toggle current row
        const row = document.getElementById('rename-' + id);
        if (row.style.display === 'none' || row.style.display === '') {
            row.style.display = 'table-row';
        } else {
            row.style.display = 'none';
        }
    }
    
    // Auto-hide alerts
    setTimeout(() => {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(el => el.style.display = 'none');
    }, 4000);
    </script>
</body>
</html>
