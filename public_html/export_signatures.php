<?php
require_once 'includes/config.php';
requireLogin();

$user_id = $_SESSION['user_id'];
$is_admin = isAdmin();

// Initialize variables
$signatures = [];
$users = [];
$selected_user_id = $user_id;
$current_user_info = [];

// Get current user info
$user_stmt = $db->prepare("SELECT username, full_name FROM users WHERE id = ?");
$user_stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
$user_result = $user_stmt->execute();
$current_user_info = $user_result->fetchArray(SQLITE3_ASSOC);

// Check if viewing another user's signatures (admin only)
if ($is_admin && isset($_GET['view_user'])) {
    $selected_user_id = (int)$_GET['view_user'];
} 
// Check if form submitted to view user
elseif ($is_admin && isset($_POST['view_user'])) {
    $selected_user_id = (int)$_POST['user_id'];
}

// Check if export is requested
$export_requested = false;
$export_user_id = $selected_user_id;

if (isset($_GET['export'])) {
    $export_requested = true;
    // Wenn Admin, darf er die User-ID via GET überschreiben
    if ($is_admin && isset($_GET['user_id'])) {
        $export_user_id = (int)$_GET['user_id'];
    }
} 
elseif (isset($_POST['export_type']) && $_POST['export_type'] === 'selected') {
    $export_requested = true;
    $export_user_id = isset($_POST['user_id']) ? (int)$_POST['user_id'] : $selected_user_id;
}

// Check access rights - user can only export their own signatures unless admin
if (!$is_admin && $export_user_id != $_SESSION['user_id']) {
    header('Location: generator.php');
    exit;
}

// If export is requested, generate CSV
if ($export_requested) {
    // WICHTIG: Buffer leeren, damit keine Leerzeichen vor der CSV ausgegeben werden
    if (ob_get_length()) ob_end_clean();

    // Get user info for filename
    $export_user_stmt = $db->prepare("SELECT username, full_name FROM users WHERE id = ?");
    $export_user_stmt->bindValue(1, $export_user_id, SQLITE3_INTEGER);
    $export_user_result = $export_user_stmt->execute();
    $export_user_info = $export_user_result->fetchArray(SQLITE3_ASSOC);
    
    // Load signatures for export
    $export_stmt = $db->prepare("SELECT name, role, email, phone, template, created_at 
                               FROM user_signatures WHERE user_id = ? ORDER BY created_at DESC");
    $export_stmt->bindValue(1, $export_user_id, SQLITE3_INTEGER);
    $export_result = $export_stmt->execute();
    
    // Generate filename
    $display_name = $export_user_info['full_name'] ?? $export_user_info['username'] ?? 'user';
    $clean_name = preg_replace('/[^a-z0-9]/i', '_', strtolower($display_name));
    $filename = 'signatures_' . $clean_name . '_' . date('Y-m-d') . '.csv';
    
    // Set headers for CSV download
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Pragma: no-cache');
    header('Expires: 0');
    
    // Create output stream
    $output = fopen('php://output', 'w');
    
    // Add UTF-8 BOM for Excel compatibility
    fwrite($output, "\xEF\xBB\xBF");
    
    // CSV header row
    fputcsv($output, ['Name', 'Role', 'Email', 'Phone', 'Template', 'Created Date']);
    
    // Data rows
    while ($sig = $export_result->fetchArray(SQLITE3_ASSOC)) {
        fputcsv($output, [
            $sig['name'],
            $sig['role'],
            $sig['email'],
            $sig['phone'],
            $sig['template'],
            date('Y-m-d H:i:s', strtotime($sig['created_at']))
        ]);
    }
    
    fclose($output);
    exit;
}

// Load signatures for selected user (for preview)
$stmt = $db->prepare("SELECT name, role, email, phone, template, created_at 
                     FROM user_signatures WHERE user_id = ? ORDER BY created_at DESC");
$stmt->bindValue(1, $selected_user_id, SQLITE3_INTEGER);
$result = $stmt->execute();

$signatures = [];
while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
    $signatures[] = $row;
}

// Get selected user info for display
$selected_user_stmt = $db->prepare("SELECT username, full_name FROM users WHERE id = ?");
$selected_user_stmt->bindValue(1, $selected_user_id, SQLITE3_INTEGER);
$selected_user_result = $selected_user_stmt->execute();
$selected_user_info = $selected_user_result->fetchArray(SQLITE3_ASSOC);

// For admin: Load all users for dropdown
if ($is_admin) {
    $stmt = $db->prepare("SELECT id, username, full_name FROM users WHERE is_active = 1 ORDER BY username");
    $result = $stmt->execute();
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $users[] = $row;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Export Signatures - SubSignature</title>
    
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/all.min.css">
    
    <style>
        /* Export Specific Styles */
        .user-header-card {
            background: linear-gradient(135deg, #e0e7ff 0%, #f3f4f6 100%);
            border: 1px solid #c7d2fe;
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }

        .user-info-large {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .user-avatar-large {
            width: 50px;
            height: 50px;
            background: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--primary);
            font-size: 1.5rem;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }

        .user-details h3 { margin: 0; font-size: 1.1rem; color: var(--text-main); }
        .user-details span { color: var(--text-muted); font-size: 0.9rem; }

        .signature-count-badge {
            background: white;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-weight: 600;
            color: var(--primary);
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }

        .warning-banner {
            background: #fffbeb;
            border-left: 4px solid #f59e0b;
            color: #b45309;
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        /* Export Options Grid */
        .export-options {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
        }

        .option-card {
            background: white;
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            transition: all 0.2s;
        }

        .option-card:hover {
            border-color: var(--primary);
            box-shadow: 0 4px 12px rgba(0,0,0,0.05);
        }

        .option-icon {
            font-size: 2.5rem;
            margin-bottom: 1rem;
            display: inline-block;
        }

        /* --- FIX: Styles für die Buttons (falls in style.css fehlend) --- */
        .btn-warning {
            background-color: #f59e0b;
            color: white !important; /* Erzwinge weiße Schrift */
            border: 1px solid #d97706;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            text-decoration: none;
        }
        .btn-warning:hover {
            background-color: #d97706;
            color: white !important;
        }
        /* ------------------------------------------------------------- */

        /* Preview Table Styles */
        .table-container {
            overflow-x: auto;
            border: 1px solid var(--border);
            border-radius: 8px;
        }
        
        .preview-table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
        .preview-table th { background: #f8fafc; padding: 1rem; text-align: left; font-weight: 600; color: var(--text-muted); border-bottom: 1px solid var(--border); }
        .preview-table td { padding: 1rem; border-bottom: 1px solid var(--border); color: var(--text-main); }
        .preview-table tr:last-child td { border-bottom: none; }
        
        .template-tag {
            background: #f1f5f9;
            padding: 2px 8px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.85rem;
            color: var(--text-muted);
        }

        /* Loading Overlay */
        .loading-overlay {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(255,255,255,0.9); z-index: 9999;
            display: none; justify-content: center; align-items: center;
            flex-direction: column; backdrop-filter: blur(2px);
        }
        .spinner {
            width: 40px; height: 40px; border: 4px solid #e2e8f0;
            border-top: 4px solid var(--primary); border-radius: 50%;
            animation: spin 1s linear infinite; margin-bottom: 1rem;
        }
        @keyframes spin { to { transform: rotate(360deg); } }

        @media (max-width: 768px) {
            .user-header-card { flex-direction: column; align-items: flex-start; }
            .user-info-large { width: 100%; }
        }
    </style>
</head>
<body>

    <div class="loading-overlay" id="loadingOverlay">
        <div class="spinner"></div>
        <h3 id="loadingText">Processing...</h3>
    </div>

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
            <h2>Export Signatures</h2>
            <p>Download your data as CSV or ZIP archives.</p>
        </header>

        <div class="user-header-card">
            <div class="user-info-large">
                <div class="user-avatar-large">
                    <i class="fas fa-user"></i>
                </div>
                <div class="user-details">
                    <h3><?php echo htmlspecialchars($selected_user_info['full_name'] ?? $selected_user_info['username'] ?? 'Unknown'); ?></h3>
                    <span><?php echo htmlspecialchars($selected_user_info['username'] ?? ''); ?></span>
                </div>
            </div>
            
            <div style="display: flex; align-items: center; gap: 1rem;">
                <span class="signature-count-badge">
                    <i class="fas fa-signature"></i> <?php echo count($signatures); ?> Signatures
                </span>
                <?php if ($selected_user_id != $_SESSION['user_id']): ?>
                    <a href="export_signatures.php" class="btn btn-sm btn-secondary" style="border-radius:20px;">
                        View My Data
                    </a>
                <?php endif; ?>
            </div>
        </div>

        <?php if ($selected_user_id != $_SESSION['user_id']): ?>
            <div class="warning-banner">
                <i class="fas fa-exclamation-triangle"></i>
                <div>
                    <strong>Admin View:</strong> You are viewing another user's data. Exports will contain their signatures.
                </div>
            </div>
        <?php endif; ?>

        <?php if ($is_admin && !empty($users)): ?>
        <section class="card">
            <div class="card-header">
                <h3><i class="fas fa-users-cog"></i> Select User to Manage</h3>
            </div>
            <form method="GET" style="display: flex; gap: 1rem; align-items: flex-end; flex-wrap: wrap;">
                <div class="form-group" style="flex: 1; min-width: 250px;">
                    <label for="view_user">Choose User Account</label>
                    <select id="view_user" name="view_user" onchange="this.form.submit()" style="width: 100%; padding: 0.75rem; border: 1px solid var(--border); border-radius: 8px;">
                        <?php foreach ($users as $user): ?>
                            <option value="<?php echo $user['id']; ?>" <?php echo $user['id'] == $selected_user_id ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($user['full_name'] ?: $user['username']); ?> (<?php echo htmlspecialchars($user['username']); ?>)
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group">
                     <button type="submit" class="btn btn-primary" style="height: 48px;">
                        <i class="fas fa-sync-alt"></i> Load User
                     </button>
                </div>
            </form>
        </section>
        <?php endif; ?>

        <?php if (count($signatures) > 0): ?>
        <div class="export-options">
            <div class="option-card">
                <i class="fas fa-file-csv option-icon" style="color: #10b981;"></i>
                <h4>Export CSV</h4>
                <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1.5rem;">
                    Download a spreadsheet with all signature data (Name, Role, Email, etc.).
                </p>
                <a href="export_signatures.php?export=1&user_id=<?php echo $selected_user_id; ?>" class="btn btn-success" style="width: 100%; justify-content: center;">
                    <i class="fas fa-download"></i> Download CSV
                </a>
            </div>

            <div class="option-card">
                <i class="fas fa-file-archive option-icon" style="color: #f59e0b;"></i>
                <h4>Download HTML (ZIP)</h4>
                <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1.5rem;">
                    Get all signatures as separate HTML files packed in a ZIP archive.
                </p>
                <a href="download_all.php?user_id=<?php echo $selected_user_id; ?>" class="btn btn-warning" style="width: 100%; justify-content: center;" onclick="startZipDownload(event)">
                    <i class="fas fa-file-zipper"></i> Download ZIP
                </a>
            </div>
        </div>

        <section class="card" style="margin-top: 2rem;">
            <div class="card-header">
                <h3><i class="fas fa-table"></i> Data Preview (Recent)</h3>
            </div>
            <div class="table-container">
                <table class="preview-table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Role</th>
                            <th>Email</th>
                            <th>Phone</th>
                            <th>Template</th>
                            <th>Date</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php $limit = 0; ?>
                        <?php foreach ($signatures as $sig): ?>
                            <?php if ($limit++ >= 5) break; ?>
                            <tr>
                                <td><?php echo htmlspecialchars($sig['name']); ?></td>
                                <td><?php echo htmlspecialchars($sig['role']); ?></td>
                                <td><?php echo htmlspecialchars($sig['email']); ?></td>
                                <td><?php echo htmlspecialchars($sig['phone']); ?></td>
                                <td><span class="template-tag"><?php echo htmlspecialchars($sig['template']); ?></span></td>
                                <td><?php echo date('M d, Y', strtotime($sig['created_at'])); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <?php if (count($signatures) > 5): ?>
                <p style="text-align: center; margin-top: 1rem; color: var(--text-muted); font-size: 0.9rem;">
                    ... and <?php echo count($signatures) - 5; ?> more records available for export.
                </p>
            <?php endif; ?>
        </section>

        <?php else: ?>
            <div class="card" style="text-align: center; padding: 4rem;">
                <i class="fas fa-folder-open" style="font-size: 3rem; color: #cbd5e1; margin-bottom: 1rem;"></i>
                <h3 style="color: var(--text-muted);">No signatures found</h3>
                <p style="color: var(--text-muted);">This user hasn't generated any signatures yet.</p>
                <?php if ($selected_user_id == $_SESSION['user_id']): ?>
                    <a href="generator.php" class="btn btn-primary" style="margin-top: 1rem;">Create Signature</a>
                <?php endif; ?>
            </div>
        <?php endif; ?>

    </main>

    <script>
        function startZipDownload(e) {
            e.preventDefault();
            const url = e.currentTarget.href;
            
            const overlay = document.getElementById('loadingOverlay');
            const text = document.getElementById('loadingText');
            
            overlay.style.display = 'flex';
            text.textContent = 'Generating ZIP Archive...';
            
            // Trigger download
            window.location.href = url;
            
            // Hide overlay after delay (since we can't track download progress easily)
            setTimeout(() => {
                overlay.style.display = 'none';
            }, 3000);
        }
    </script>
</body>
</html>
