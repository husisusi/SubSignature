<?php

require_once 'includes/config.php';
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
$user_id = $_SESSION['user_id'];

// Load Users (Admin only)
$users = [];
if ($is_admin) {
    $stmt = $db->prepare("SELECT id, username, full_name FROM users WHERE is_active = 1 ORDER BY username");
    $result = $stmt->execute();
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $users[] = $row;
    }
}

// Load Templates (Secure Glob)
$templates = [];
$template_files = glob('templates/*.html');
foreach ($template_files as $file) {
    // Only load files from the templates directory to prevent traversal
    if (dirname($file) === 'templates') {
        $templates[basename($file)] = ucfirst(str_replace(['signature_', '.html', '_'], ['', '', ' '], basename($file)));
    }
}

// Initialize Variables
$error = '';
$success = '';
$preview_data = [];
$total_rows = 0;
$valid_rows = 0;
$form_user_id = $user_id;
$form_template = 'signature_default.html';

// ---------------------------------------------------------
// PROCESS POST REQUEST
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // 1. CSRF Protection
    if (!isset($_POST['csrf_token']) || !verifyCSRFToken($_POST['csrf_token'])) {
        die("Security Error: Invalid CSRF Token. Please refresh the page.");
    }

    $target_user_id = $_POST['user_id'] ?? $user_id;
    $template = $_POST['template'] ?? 'signature_default.html';
    $action = $_POST['action'] ?? 'preview';
    
    $form_user_id = $target_user_id;
    $form_template = $template;
    
    // 2. Permission Check
    if (!$is_admin && $target_user_id != $user_id) {
        $error = "Access Denied: You can only import for yourself.";
    } 
    // 3. Action: Import
    elseif ($action === 'import' && isset($_SESSION['preview_data'])) {
        $preview_data = $_SESSION['preview_data'];
        $valid_data = array_filter($preview_data, fn($row) => $row['is_valid']);
        
        if (count($valid_data) > 0) {
            $_SESSION['import_data'] = [
                'user_id' => $target_user_id,
                'template' => $template,
                'rows' => $valid_data
            ];
            unset($_SESSION['preview_data']);
            header('Location: process_import.php');
            exit;
        } else {
            $error = "No valid data to import.";
        }
    }
    // 4. Action: Preview (File Upload)
    elseif ($action === 'preview' && isset($_FILES['csv_file'])) {
        if (empty($_FILES['csv_file']['tmp_name'])) {
            $error = "No file selected.";
        } else {
            $file_tmp = $_FILES['csv_file']['tmp_name'];
            $file_size = $_FILES['csv_file']['size'];
            $file_name = $_FILES['csv_file']['name'];
            $file_type = mime_content_type($file_tmp); // Server-side MIME check
            
            // Security: Size Limit (2MB)
            if ($file_size > 2 * 1024 * 1024) {
                $error = "File too large (Max 2MB).";
            }
            // Security: Type Check
            elseif (!in_array($file_type, ['text/plain', 'text/csv', 'application/vnd.ms-excel']) && !preg_match('/\.csv$/i', $file_name)) {
                $error = "Invalid file type. Please upload a CSV file.";
            } else {
                if (($handle = fopen($file_tmp, 'r')) !== FALSE) {
                    // Check for BOM
                    $bom = fread($handle, 3);
                    if ($bom !== "\xEF\xBB\xBF") rewind($handle);
                    
                    $headers = fgetcsv($handle, 1000, ',');
                    
                    if (!$headers) {
                        $error = "Empty or invalid CSV file.";
                    } else {
                        // Normalize Headers
                        $expected_columns = ['name', 'role', 'email', 'phone'];
                        $column_map = [];
                        foreach ($headers as $index => $header) {
                            $h = mb_strtolower(trim($header), 'UTF-8');
                            if (in_array($h, $expected_columns)) $column_map[$h] = $index;
                        }
                        
                        $missing = array_diff($expected_columns, array_keys($column_map));
                        if (!empty($missing)) {
                            $error = "Missing required columns: " . implode(', ', $missing);
                        } else {
                            $row_num = 1;
                            // Sanitizer Closure
                            $sanitizeCSV = function($str) {
                                $str = trim($str ?? '');
                                // Prevent Formula Injection
                                if (preg_match('/^[=\+\-@]/', $str)) return "'" . $str;
                                return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
                            };
                            
                            while (($data = fgetcsv($handle, 1000, ',')) !== FALSE) {
                                $row_num++;
                                if (count(array_filter($data)) === 0) continue; // Skip empty lines
                                
                                $name = $sanitizeCSV($data[$column_map['name']] ?? '');
                                $role = $sanitizeCSV($data[$column_map['role']] ?? '');
                                $email = $sanitizeCSV($data[$column_map['email']] ?? '');
                                $phone = trim($data[$column_map['phone']] ?? '');
                                
                                $row_errors = [];
                                if (!$name) $row_errors[] = "Name missing";
                                if (!$role) $row_errors[] = "Role missing";
                                if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) $row_errors[] = "Invalid Email";
                                if (!$phone) $row_errors[] = "Phone missing";
                                
                                $is_valid = empty($row_errors);
                                if ($is_valid) $valid_rows++;
                                
                                $preview_data[] = [
                                    'row' => $row_num - 1,
                                    'name' => $name, 'role' => $role,
                                    'email' => $email, 'phone' => $phone,
                                    'errors' => $row_errors, 'is_valid' => $is_valid
                                ];
                            }
                            fclose($handle);
                            
                            $_SESSION['preview_data'] = $preview_data;
                            $_SESSION['import_params'] = ['user_id' => $target_user_id, 'template' => $template];
                            $total_rows = count($preview_data);
                        }
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
    }
}

$csrf_token = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSV Import - SubSignature</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/all.min.css">
    <style>
        /* Modern Upload Area Styling */
        .upload-area {
            border: 2px dashed #cbd5e1;
            border-radius: 12px;
            background: #f8fafc;
            padding: 3rem 2rem;
            text-align: center;
            cursor: pointer;
            transition: all 0.2s ease;
            position: relative;
        }
        .upload-area:hover, .upload-area.dragover {
            border-color: var(--primary);
            background: #eff6ff;
        }
        .upload-icon {
            font-size: 3rem;
            color: #94a3b8;
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
            background: white; padding: 0.75rem; border-radius: 8px;
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
        .stat-valid { background: #dcfce7; color: #166534; }
        .stat-error { background: #fee2e2; color: #991b1b; }
        .stat-total { background: #f1f5f9; color: var(--text-main); }
        
        .preview-table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
        .preview-table th { background: #f8fafc; padding: 0.75rem; text-align: left; font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); }
        .preview-table td { padding: 0.75rem; border-bottom: 1px solid var(--border); }
        .preview-table tr.row-valid td { background: rgba(220, 252, 231, 0.3); }
        .preview-table tr.row-error td { background: rgba(254, 226, 226, 0.3); }
        .error-list { margin: 0; padding-left: 1.2rem; color: #dc2626; font-size: 0.8rem; }
        
        .help-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-top: 1rem; }
        .help-card { background: #f8fafc; padding: 1rem; border-radius: 8px; text-align: center; text-decoration: none; color: var(--text-main); border: 1px solid var(--border); transition: all 0.2s; cursor: pointer; }
        .help-card:hover { border-color: var(--primary); transform: translateY(-2px); box-shadow: var(--shadow); }
        .help-icon { font-size: 1.5rem; color: var(--primary); margin-bottom: 0.5rem; display: block; }

        .alert { padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; display: flex; gap: 0.75rem; align-items: center; }
        .alert-success { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
        .alert-error { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
        
        .form-actions-centered { display: flex; justify-content: center; gap: 1rem; margin-top: 2rem; padding-top: 1.5rem; border-top: 1px solid var(--border); }
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
                    <span><?php echo isAdmin() ? 'Administrator' : 'User'; ?></span>
                </div>
            </div>
            <a href="logout.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> <span>Sign Out</span></a>
            <div style="text-align: center; margin-top: 0.75rem; font-size: 0.7rem; color: #94a3b8;">
                SubSignature <a href="about.php" style="color: inherit; text-decoration: none; font-weight: 600;">v1.0.1</a>
            </div>
        </div>
    </aside>

    <main class="main-content">
        
        <header class="page-header">
            <h2>Batch Import</h2>
            <p>Upload a CSV file to generate multiple signatures at once.</p>
        </header>

        <?php if ($error): ?>
            <div class="alert alert-error"><i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <?php if (isset($_GET['success'])): ?>
            <div class="alert alert-success"><i class="fas fa-check-circle"></i> Successfully imported <?php echo htmlspecialchars($_GET['success']); ?> signatures!</div>
        <?php endif; ?>

        <section class="card">
            <div class="card-header">
                <h3><i class="fas fa-cloud-upload-alt"></i> Import Configuration</h3>
            </div>
            
            <form method="POST" enctype="multipart/form-data" id="uploadForm">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                
                <div class="form-grid">
                    <div class="form-group" style="grid-column: 1 / -1;">
                        <label>CSV File Upload</label>
                        <div class="upload-area" id="dropZone">
                            <input type="file" id="csv_file" name="csv_file" accept=".csv,text/csv" required>
                            
                            <div class="upload-content">
                                <i class="fas fa-file-csv upload-icon"></i>
                                <div class="upload-text">Click to upload or drag & drop</div>
                                <div class="upload-hint">Max file size: 2MB. Format: UTF-8 CSV</div>
                            </div>
                            
                            <div class="file-selected-info" id="fileInfo">
                                <i class="fas fa-check-circle file-icon"></i>
                                <div>
                                    <div class="filename" id="fileNameDisplay">data.csv</div>
                                    <div class="filesize" id="fileSizeDisplay">12 KB</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label for="template">Signature Template</label>
                        <select id="template" name="template" required>
                            <?php foreach ($templates as $filename => $display_name): ?>
                                <option value="<?php echo htmlspecialchars($filename); ?>" <?php echo ($filename == $form_template) ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($display_name); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <?php if ($is_admin && !empty($users)): ?>
                    <div class="form-group">
                        <label for="user_id">Assign to User</label>
                        <select id="user_id" name="user_id">
                            <?php foreach ($users as $user): ?>
                                <option value="<?php echo $user['id']; ?>" <?php echo ($user['id'] == $form_user_id) ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($user['full_name'] ?: $user['username']); ?> (<?php echo htmlspecialchars($user['username']); ?>)
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <?php else: ?>
                        <input type="hidden" name="user_id" value="<?php echo $user_id; ?>">
                    <?php endif; ?>
                </div>
                
                <div class="form-actions">
                    <input type="hidden" name="action" value="preview">
                    <button type="button" onclick="resetForm()" class="btn btn-danger"><i class="fas fa-trash-alt"></i> Clear</button>
                    <button type="submit" class="btn btn-primary"><i class="fas fa-eye"></i> Preview Import</button>
                </div>
            </form>
        </section>
        
        <?php if ($total_rows > 0): ?>
        <section class="card">
            <div class="card-header" style="display: flex; justify-content: space-between; align-items: center;">
                <h3><i class="fas fa-table"></i> Data Validation</h3>
                
                <?php if ($valid_rows > 0): ?>
                <form method="POST" style="margin:0;">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                    <input type="hidden" name="user_id" value="<?php echo htmlspecialchars($form_user_id); ?>">
                    <input type="hidden" name="template" value="<?php echo htmlspecialchars($form_template); ?>">
                    <input type="hidden" name="action" value="import">
                    
                    <button type="submit" class="btn btn-success btn-sm" style="font-size: 0.9rem;">
                        <i class="fas fa-file-import"></i> Start Import
                    </button>
                </form>
                <?php endif; ?>
            </div>
            
            <div class="preview-stats">
                <div class="stat-badge stat-valid"><i class="fas fa-check-circle"></i> <?php echo $valid_rows; ?> Valid</div>
                <div class="stat-badge stat-error"><i class="fas fa-exclamation-triangle"></i> <?php echo $total_rows - $valid_rows; ?> Errors</div>
                <div class="stat-badge stat-total"><i class="fas fa-list"></i> <?php echo $total_rows; ?> Total</div>
            </div>

            <div class="table-responsive">
                <table class="preview-table">
                    <thead>
                        <tr>
                            <th style="width:50px">#</th>
                            <th>Name</th>
                            <th>Role</th>
                            <th>Email</th>
                            <th>Phone</th>
                            <th>Status</th>
                            <th>Issues</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($preview_data as $row): ?>
                        <tr class="<?php echo $row['is_valid'] ? 'row-valid' : 'row-error'; ?>">
                            <td><b><?php echo $row['row']; ?></b></td>
                            <td><?php echo htmlspecialchars($row['name']); ?></td>
                            <td><?php echo htmlspecialchars($row['role']); ?></td>
                            <td><?php echo htmlspecialchars($row['email']); ?></td>
                            <td><?php echo htmlspecialchars($row['phone']); ?></td>
                            <td>
                                <?php echo $row['is_valid'] ? 
                                    '<span style="color:#166534; font-weight:700; font-size:0.8rem;">VALID</span>' : 
                                    '<span style="color:#991b1b; font-weight:700; font-size:0.8rem;">ERROR</span>'; ?>
                            </td>
                            <td>
                                <?php if (!empty($row['errors'])): ?>
                                    <ul class="error-list">
                                        <?php foreach ($row['errors'] as $err): ?>
                                            <li><?php echo htmlspecialchars($err); ?></li>
                                        <?php endforeach; ?>
                                    </ul>
                                <?php else: ?>
                                    <span style="color:#94a3b8;">-</span>
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
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                        <input type="hidden" name="user_id" value="<?php echo htmlspecialchars($form_user_id); ?>">
                        <input type="hidden" name="template" value="<?php echo htmlspecialchars($form_template); ?>">
                        <input type="hidden" name="action" value="import">
                        
                        <button type="button" onclick="window.location.href='csv_import.php?cancel=1'" class="btn btn-danger"><i class="fas fa-times"></i> Cancel</button>
                        <button type="submit" class="btn btn-success"><i class="fas fa-file-import"></i> Confirm & Import</button>
                    </form>
                </div>
            <?php endif; ?>
        </section>
        <?php endif; ?>
        
        <section class="card" style="background:transparent; border:none; box-shadow:none; padding:0;">
            <div class="help-grid">
                <button onclick="downloadSample()" class="help-card">
                    <span class="help-icon"><i class="fas fa-download"></i></span>
                    <span class="help-text">Download Sample CSV</span>
                </button>
                <button onclick="showCSVGuide()" class="help-card">
                    <span class="help-icon"><i class="fas fa-info-circle"></i></span>
                    <span class="help-text">View Format Guide</span>
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
                alert('File is too large! Maximum allowed is 2MB.');
                this.value = '';
                return;
            }

            uploadContent.style.display = 'none'; // Hide default text
            fileInfo.style.display = 'flex';      // Show file info
            
            fileNameDisplay.textContent = file.name;
            fileSizeDisplay.textContent = (file.size / 1024).toFixed(1) + ' KB';
            
            dropZone.style.borderColor = '#10b981'; // Green border
            dropZone.style.background = '#ecfdf5';
        }
    });

    // Reset Form
    function resetForm() {
        if (confirm('Clear form settings?')) {
            window.location.href = 'csv_import.php?cancel=1';
        }
    }
    
    // Help Functions
    function showCSVGuide() {
        alert(`CSV REQUIREMENTS:\n\n1. Required Headers:\n   name, role, email, phone\n\n2. Format:\n   - Comma separated values\n   - UTF-8 Encoding\n\nExample:\nname,role,email,phone\nJohn Doe,Manager,john@test.com,+123456789`);
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
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
        btn.disabled = true;
    });
    </script>
</body>
</html>
