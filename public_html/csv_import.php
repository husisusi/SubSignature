<?php
require_once 'includes/config.php';
requireLogin();

// --- NEW: Cancel Logic (Clear Session) ---
if (isset($_GET['cancel'])) {
    unset($_SESSION['preview_data']);
    unset($_SESSION['import_params']);
    header('Location: csv_import.php');
    exit;
}
// -------------------------------------------

// Only admins can import for other users
$is_admin = isAdmin();
$user_id = $_SESSION['user_id'];

// For admins: Load all users for dropdown
$users = [];
if ($is_admin) {
    $stmt = $db->prepare("SELECT id, username, full_name FROM users WHERE is_active = 1 ORDER BY username");
    $result = $stmt->execute();
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $users[] = $row;
    }
}

// Load Templates for dropdown
// Security: strictly scanning specific folder, preventing path traversal
$templates = [];
$template_files = glob('templates/*.html');
foreach ($template_files as $file) {
    $templates[basename($file)] = ucfirst(str_replace(['signature_', '.html', '_'], ['', '', ' '], basename($file)));
}

$error = '';
$success = '';
$preview_data = [];
$total_rows = 0;
$valid_rows = 0;

// Store form data for redisplay
$form_user_id = $user_id;
$form_template = 'signature_default.html';

// Process CSV upload
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // --- SECURITY: CSRF Protection ---
    if (!isset($_POST['csrf_token']) || !verifyCSRFToken($_POST['csrf_token'])) {
        die("Security Error: Invalid CSRF Token. Please refresh the page.");
    }

    $target_user_id = $_POST['user_id'] ?? $user_id;
    $template = $_POST['template'] ?? 'signature_default.html';
    $action = $_POST['action'] ?? 'preview';
    
    $form_user_id = $target_user_id;
    $form_template = $template;
    
    // Access Control Check
    if (!$is_admin && $target_user_id != $user_id) {
        $error = "You can only import for yourself!";
    } 
    // Action: Import (Execution Phase)
    elseif ($action === 'import' && isset($_SESSION['preview_data'])) {
        $preview_data = $_SESSION['preview_data'];
        $valid_data = array_filter($preview_data, fn($row) => $row['is_valid']);
        $valid_rows = count($valid_data);
        
        if ($valid_rows > 0) {
            // Store validated data in session for the processor script
            $_SESSION['import_data'] = [
                'user_id' => $target_user_id,
                'template' => $template,
                'rows' => $valid_data
            ];
            unset($_SESSION['preview_data']); // Clear preview
            header('Location: process_import.php');
            exit;
        } else {
            $error = "No valid rows to import!";
        }
    }
    // Action: Preview (Upload Phase)
    elseif ($action === 'preview' && isset($_FILES['csv_file'])) {
        if (empty($_FILES['csv_file']['tmp_name'])) {
            $error = "Please select a CSV file!";
        } else {
            $file = $_FILES['csv_file']['tmp_name'];
            $file_type = $_FILES['csv_file']['type'];
            $file_name = $_FILES['csv_file']['name'];
            
            // Security: Max size 2MB
            if ($_FILES['csv_file']['size'] > 2 * 1024 * 1024) {
                $error = "File is too large! Maximum size is 2MB.";
            }
            // Security: MIME and extension check
            elseif (!in_array($file_type, ['text/csv', 'text/plain', 'application/vnd.ms-excel']) && 
                   !preg_match('/\.csv$/i', $file_name)) {
                $error = "Please upload a valid CSV file!";
            } else {
                if (($handle = fopen($file, 'r')) !== FALSE) {
                    // BOM Handling (Byte Order Mark)
                    $bom = fread($handle, 3);
                    if ($bom !== "\xEF\xBB\xBF") rewind($handle);

                    // Read Header
                    $headers = fgetcsv($handle, 1000, ',');
                    
                    if ($headers === FALSE) {
                        $error = "Invalid CSV file or empty file!";
                    } else {
                        // Normalize headers to lowercase for mapping
                        $expected_columns = ['name', 'role', 'email', 'phone'];
                        $column_map = [];
                        
                        foreach ($headers as $index => $header) {
                            $header_lower = mb_strtolower(trim($header), 'UTF-8');
                            if (in_array($header_lower, $expected_columns)) {
                                $column_map[$header_lower] = $index;
                            }
                        }
                        
                        $missing_columns = array_diff($expected_columns, array_keys($column_map));
                        if (!empty($missing_columns)) {
                            $error = "Missing required columns: " . implode(', ', $missing_columns);
                        } else {
                            $row_number = 1;
                            
                            // Security: Define sanitizer outside loop for performance
                            // Prevents CSV Injection (Formula Injection)
                            $sanitizeCSV = function($input) {
                                $input = trim($input ?? '');
                                if (preg_match('/^[=\+\-@]/', $input)) return "'" . $input; 
                                return $input;
                            };

                            while (($data = fgetcsv($handle, 1000, ',')) !== FALSE) {
                                $row_number++;
                                // Skip empty rows
                                if (count(array_filter($data, function($value) { return trim($value) !== ''; })) === 0) continue;
                                
                                $name = $sanitizeCSV($data[$column_map['name']] ?? '');
                                $role = $sanitizeCSV($data[$column_map['role']] ?? '');
                                $email = $sanitizeCSV($data[$column_map['email']] ?? '');
                                $phone = trim($data[$column_map['phone']] ?? '');
                                
                                // Validation Logic
                                $row_errors = [];
                                if (empty($name)) $row_errors[] = "Name is required";
                                if (empty($role)) $row_errors[] = "Role is required";
                                if (empty($email)) $row_errors[] = "Email is required";
                                elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) $row_errors[] = "Invalid email format";
                                if (empty($phone)) $row_errors[] = "Phone is required";
                                elseif (!preg_match('/^[\+\d\s\-\(\)]{8,20}$/', $phone)) $row_errors[] = "Invalid phone format";
                                
                                $is_valid = empty($row_errors);
                                if ($is_valid) $valid_rows++;
                                
                                $preview_data[] = [
                                    'row' => $row_number - 1,
                                    'name' => $name,
                                    'role' => $role,
                                    'email' => $email,
                                    'phone' => $phone,
                                    'errors' => $row_errors,
                                    'is_valid' => $is_valid
                                ];
                            }
                            fclose($handle);
                            
                            // Store results in session
                            $total_rows = count($preview_data);
                            $_SESSION['preview_data'] = $preview_data;
                            $_SESSION['import_params'] = ['user_id' => $target_user_id, 'template' => $template];
                        }
                    }
                } else {
                    $error = "Cannot read CSV file!";
                }
            }
        }
    }
}

// Recover Session Data if available (e.g. on page refresh)
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
        /* Import Specific Styles */
        .file-upload-wrapper {
            background: #f8fafc;
            border: 2px dashed var(--border);
            border-radius: 8px;
            padding: 2rem;
            text-align: center;
            transition: all 0.2s;
        }
        .file-upload-wrapper:hover {
            border-color: var(--primary);
            background: #eff6ff;
        }
        
        .preview-stats {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
            margin-bottom: 1.5rem;
        }
        
        .stat-badge {
            padding: 0.5rem 1rem;
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .stat-valid { background: #dcfce7; color: #166534; }
        .stat-error { background: #fee2e2; color: #991b1b; }
        .stat-total { background: #f1f5f9; color: var(--text-main); }
        
        /* Table overrides for preview */
        .preview-table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
        .preview-table th { background: #f8fafc; padding: 0.75rem; text-align: left; font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); }
        .preview-table td { padding: 0.75rem; border-bottom: 1px solid var(--border); }
        .preview-table tr.row-valid td { background: rgba(220, 252, 231, 0.3); }
        .preview-table tr.row-error td { background: rgba(254, 226, 226, 0.3); }
        
        .error-list { margin: 0; padding-left: 1.2rem; color: #dc2626; font-size: 0.8rem; }
        
        .help-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }
        
        .help-card {
            background: #f8fafc;
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
            text-decoration: none;
            color: var(--text-main);
            border: 1px solid var(--border);
            transition: all 0.2s;
            cursor: pointer;
        }
        .help-card:hover {
            border-color: var(--primary);
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        .help-icon { font-size: 1.5rem; color: var(--primary); margin-bottom: 0.5rem; display: block; }
        
        .form-actions-centered {
            display: flex;
            justify-content: center;
            gap: 1rem;
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border);
        }

        /* Input File Custom Styling */
        input[type="file"] {
            width: 100%;
            padding: 0.5rem;
            background: white;
            border: 1px solid var(--border);
            border-radius: 6px;
        }
        
        /* Alert customization */
        .alert { padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; display: flex; gap: 0.75rem; align-items: center; }
        .alert-success { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
        .alert-error { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
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
            <h2>Batch Import</h2>
            <p>Upload a CSV file to generate multiple signatures at once.</p>
        </header>

        <?php if ($error): ?>
            <div class="alert alert-error">
                <i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>
        
        <?php if (isset($_GET['success'])): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i> Successfully imported <?php echo htmlspecialchars($_GET['success']); ?> signatures!
            </div>
        <?php endif; ?>

        <section class="card">
            <div class="card-header">
                <h3><i class="fas fa-cloud-upload-alt"></i> Upload Settings</h3>
            </div>
            
            <form method="POST" enctype="multipart/form-data" id="uploadForm">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                
                <div class="form-grid">
                    <div class="form-group" style="grid-column: 1 / -1;">
                        <label for="csv_file">CSV File</label>
                        <input type="file" id="csv_file" name="csv_file" accept=".csv,text/csv" required>
                        <p style="font-size:0.85rem; color:var(--text-muted); margin-top:0.5rem;">
                            Required columns: <code>name</code>, <code>role</code>, <code>email</code>, <code>phone</code>. Max size: 2MB.
                        </p>
                    </div>
                    
                    <div class="form-group">
                        <label for="template">Signature Template</label>
                        <select id="template" name="template" required>
                            <?php foreach ($templates as $filename => $display_name): ?>
                                <option value="<?php echo htmlspecialchars($filename); ?>"
                                    <?php echo ($filename == $form_template) ? 'selected' : ''; ?>>
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
                                <option value="<?php echo $user['id']; ?>" 
                                    <?php echo ($user['id'] == $form_user_id) ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($user['full_name'] ?: $user['username']); ?>
                                    (<?php echo htmlspecialchars($user['username']); ?>)
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
                    <button type="button" onclick="resetForm()" class="btn btn-danger">
                        <i class="fas fa-trash-alt"></i> Clear
                    </button>
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-eye"></i> Preview Import
                    </button>
                </div>
            </form>
        </section>
        
        <?php if ($total_rows > 0): ?>
        <section class="card">
            <div class="card-header" style="display: flex; justify-content: space-between; align-items: center;">
                <h3><i class="fas fa-table"></i> Data Preview</h3>
                
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
                <div class="stat-badge stat-valid">
                    <i class="fas fa-check-circle"></i> <?php echo $valid_rows; ?> Valid
                </div>
                <div class="stat-badge stat-error">
                    <i class="fas fa-exclamation-triangle"></i> <?php echo $total_rows - $valid_rows; ?> Errors
                </div>
                <div class="stat-badge stat-total">
                    <i class="fas fa-list"></i> <?php echo $total_rows; ?> Total Rows
                </div>
            </div>

            <?php if ($valid_rows > 0): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check"></i> Ready to import <?php echo $valid_rows; ?> signatures.
                </div>
            <?php else: ?>
                <div class="alert alert-error">
                    <i class="fas fa-times-circle"></i> No valid rows found. Please check your CSV file.
                </div>
            <?php endif; ?>
            
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
                                <?php if ($row['is_valid']): ?>
                                    <span style="color:#166534; font-weight:700; font-size:0.8rem;">VALID</span>
                                <?php else: ?>
                                    <span style="color:#991b1b; font-weight:700; font-size:0.8rem;">ERROR</span>
                                <?php endif; ?>
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
                        
                        <button type="button" onclick="window.location.href='csv_import.php?cancel=1'" class="btn btn-danger">
                            <i class="fas fa-times"></i> Cancel
                        </button>
                        <button type="submit" class="btn btn-success">
                            <i class="fas fa-file-import"></i> Start Import
                        </button>
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
                <a href="export_signatures.php" class="help-card">
                    <span class="help-icon"><i class="fas fa-file-export"></i></span>
                    <span class="help-text">Export Existing Data</span>
                </a>
            </div>
        </section>

    </main>
    
    <script>
    function resetForm() {
        if (confirm('Clear form settings?')) {
            window.location.href = 'csv_import.php?cancel=1';
        }
    }
    
    function showCSVGuide() {
        alert(`CSV REQUIREMENTS:\n\n1. Required Headers:\n   name, role, email, phone\n\n2. Format:\n   - Comma separated values\n   - UTF-8 Encoding\n   - No special characters in phone numbers except + and -\n\nExample:\nname,role,email,phone\nJohn Doe,Manager,john@test.com,+123456789`);
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
    
    // File size check
    document.getElementById('csv_file').addEventListener('change', function(e) {
        const file = e.target.files[0];
        if (file && file.size > 2 * 1024 * 1024) {
            alert('File too large (Max 2MB)');
            e.target.value = '';
        }
    });
    
    // Spinner
    document.getElementById('uploadForm').addEventListener('submit', function() {
        const btn = this.querySelector('button[type="submit"]');
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
        btn.disabled = true;
    });
    </script>
</body>
</html>
