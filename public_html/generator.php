<?php
require_once 'includes/config.php';
requireLogin();

// 1. Security: Generate CSRF Token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$user_id = $_SESSION['user_id'];
$message = '';

// --- PAGINATION & SEARCH LOGIC START ---

// 1. Get Search Term & Page Number securely
$search = trim($_GET['search'] ?? '');
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
if ($page < 1) $page = 1;
$limit = 25; // Number of signatures per page (Performance fix)
$offset = ($page - 1) * $limit;

// 2. Build Query Conditions
$whereSQL = "WHERE user_id = :uid";
$params = [':uid' => $user_id];

if (!empty($search)) {
    // Security: Search logic using named parameters
    $whereSQL .= " AND (name LIKE :search OR email LIKE :search OR role LIKE :search)";
    $params[':search'] = '%' . $search . '%';
}

// 3. Get Total Count (for Pagination)
$countSql = "SELECT COUNT(*) as total FROM user_signatures $whereSQL";
$stmt = $db->prepare($countSql);
foreach ($params as $key => $val) {
    $stmt->bindValue($key, $val, is_int($val) ? SQLITE3_INTEGER : SQLITE3_TEXT);
}
$totalResult = $stmt->execute();
$totalRow = $totalResult->fetchArray(SQLITE3_ASSOC);
$totalSignatures = $totalRow['total'];
$totalPages = ceil($totalSignatures / $limit);

// 4. Get Data (Limited)
$dataSql = "SELECT * FROM user_signatures $whereSQL ORDER BY created_at DESC LIMIT :limit OFFSET :offset";
$stmt = $db->prepare($dataSql);
foreach ($params as $key => $val) {
    $stmt->bindValue($key, $val, is_int($val) ? SQLITE3_INTEGER : SQLITE3_TEXT);
}
// Bind Limit/Offset
$stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
$stmt->bindValue(':offset', $offset, SQLITE3_INTEGER);

$result = $stmt->execute();
$signatures = [];
while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
    $signatures[] = $row;
}
// --- PAGINATION & SEARCH LOGIC END ---


// Data Persistence Logic (for the Create Form)
$formData = $_SESSION['form_data'] ?? [];
$defaultName = $formData['name'] ?? $_SESSION['full_name'] ?? '';
$defaultEmail = $formData['email'] ?? $_SESSION['email'] ?? '';
$defaultRole = $formData['role'] ?? '';
$defaultPhone = $formData['phone'] ?? '';
$defaultTemplate = $formData['template'] ?? 'signature_default.html';

// Handle Actions (Delete All) via POST
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete_all') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Security Error: Invalid CSRF Token");
    }
    
    // Only delete signatures for this user
    $stmt = $db->prepare("DELETE FROM user_signatures WHERE user_id = ?");
    $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
    $stmt->execute();
    
    // Redirect to clear Search/Page params and refresh
    header("Location: generator.php?success=deleted");
    exit;
}

if (isset($_GET['success']) && $_GET['success'] == 'deleted') {
    $message = "All signatures deleted successfully!";
    $signatures = []; // Clear current view
    $totalSignatures = 0;
}

// Load Templates
$templates = [];
$template_files = glob('templates/*.html');
if ($template_files) {
    foreach ($template_files as $file) {
        $templates[basename($file)] = basename($file);
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SubSignature Dashboard</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/all.min.css">
    
    <style>
        /* CSS copied from previous version */
        .alert { padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; display: flex; gap: 0.75rem; align-items: center; }
        .alert-success { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
        .empty-state { text-align: center; padding: 4rem 1rem; color: #94a3b8; }
        .empty-icon { font-size: 3rem; margin-bottom: 1rem; opacity: 0.5; }
        .loading-overlay { position: fixed; inset: 0; background: rgba(255,255,255,0.9); z-index: 999; display: none; justify-content: center; align-items: center; backdrop-filter: blur(2px); }
        .spinner { width: 40px; height: 40px; border: 3px solid #e2e8f0; border-top-color: #4f46e5; border-radius: 50%; animation: spin 1s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .sig-preview-container { display: none; margin-top: 1rem; border: 1px dashed #e2e8f0; background: #f8fafc; padding: 10px; border-radius: 8px; width: 100%; }
        .preview-iframe { width: 100%; height: 180px; border: none; background: white; border-radius: 4px; }
        .visually-hidden { position: absolute; left: -9999px; opacity: 0; }

        /* NEW STYLES FOR SEARCH & PAGINATION */
        .search-bar-container {
            display: flex;
            gap: 10px;
            margin-bottom: 1.5rem;
            background: #f8fafc;
            padding: 1rem;
            border-radius: 8px;
            border: 1px solid var(--border);
        }
        .search-input {
            flex: 1;
            padding: 0.6rem;
            border: 1px solid #cbd5e1;
            border-radius: 6px;
        }
        .pagination {
            display: flex;
            justify-content: center;
            gap: 5px;
            margin-top: 2rem;
        }
        .page-link {
            padding: 0.5rem 1rem;
            border: 1px solid var(--border);
            background: white;
            text-decoration: none;
            color: var(--text-main);
            border-radius: 6px;
            transition: all 0.2s;
        }
        .page-link:hover { background: #f1f5f9; }
        .page-link.active { background: var(--primary); color: white; border-color: var(--primary); }
        .page-link.disabled { opacity: 0.5; cursor: not-allowed; pointer-events: none; }
    </style>
</head>
<body>

    <aside class="sidebar">
        <?php if (file_exists('includes/navbar.php')) include 'includes/navbar.php'; ?>
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
            <h2>Signature Generator</h2>
            <p>Create, manage and export your email signatures.</p>
        </header>

        <?php if ($message): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>

        <section class="card" id="create-form">
            <div class="card-header">
                <h3><i class="far fa-edit"></i> New Signature</h3>
            </div>
            
            <form action="generate.php" method="POST" id="signatureForm">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

                <div class="form-grid">
                    <div class="form-group">
                        <label>Name</label>
                        <input type="text" id="inp_name" name="name" required 
                               value="<?php echo htmlspecialchars($defaultName, ENT_QUOTES, 'UTF-8'); ?>"
                               placeholder="e.g. Sarah Smith">
                    </div>
                    
                    <div class="form-group">
                        <label>Position / Role</label>
                        <input type="text" id="inp_role" name="role" required 
                               value="<?php echo htmlspecialchars($defaultRole, ENT_QUOTES, 'UTF-8'); ?>"
                               placeholder="e.g. Marketing Manager">
                    </div>
                    
                    <div class="form-group">
                        <label>Email Address</label>
                        <input type="email" id="inp_email" name="email" required 
                               value="<?php echo htmlspecialchars($defaultEmail, ENT_QUOTES, 'UTF-8'); ?>"
                               placeholder="sarah@company.com">
                    </div>
                    
                    <div class="form-group">
                        <label>Phone Number</label>
                        <input type="tel" id="inp_phone" name="phone" required 
                               value="<?php echo htmlspecialchars($defaultPhone, ENT_QUOTES, 'UTF-8'); ?>"
                               placeholder="+49 123 456789">
                    </div>
                    
                    <div class="form-group" style="grid-column: 1 / -1;">
                        <label>Select Template</label>
                        <select name="template" id="inp_template" required>
                            <?php foreach ($templates as $template): ?>
                                <?php 
                                $cleanName = ucfirst(str_replace(['signature_', '.html', '_'], ['','',' '], $template));
                                $selected = ($template == $defaultTemplate) ? 'selected' : '';
                                ?>
                                <option value="<?php echo htmlspecialchars($template, ENT_QUOTES, 'UTF-8'); ?>" <?php echo $selected; ?>>
                                    <?php echo htmlspecialchars($cleanName, ENT_QUOTES, 'UTF-8'); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>

                <div class="form-actions">
                    <button type="submit" name="action" value="preview" class="btn btn-preview" onclick="saveToStorage()">
                        <i class="fas fa-eye"></i> Preview
                    </button>
                    <button type="submit" name="action" value="save" class="btn btn-primary" onclick="saveToStorage()">
                        <i class="fas fa-save"></i> Save Signature
                    </button>
                </div>
            </form>
        </section>

        <?php if (isset($_SESSION['preview'])): ?>
        <section class="card">
            <div class="card-header">
                <h3>Preview Result</h3>
                <button onclick="closePreview()" class="btn btn-sm btn-danger" style="border:none">Close</button>
            </div>
            
            <div class="preview-box">
                <div class="preview-html" id="signatureContainer"><?php echo $_SESSION['preview']; ?></div>
                <textarea id="rawHtmlSource" class="visually-hidden"><?php echo htmlspecialchars($_SESSION['preview']); ?></textarea>
            </div>
            
            <div class="form-actions" style="margin-top:0">
                <a href="download.php?type=preview" class="btn btn-success">
                    <i class="fas fa-download"></i> Download HTML
                </a>
                <button type="button" onclick="copyToClipboard()" class="btn btn-primary">
                    <i class="fas fa-copy"></i> Copy Code
                </button>
            </div>
        </section>
        <?php 
            if (isset($_GET['clear'])) {
                unset($_SESSION['preview']);
                unset($_SESSION['form_data']);
                echo '<script>window.location.href = "generator.php";</script>';
                exit;
            }
        endif; 
        ?>

        <section class="card">
            <div class="card-header">
                <h3>My Signatures (<?php echo $totalSignatures; ?>)</h3>
                
                <div style="display:flex; gap:0.5rem">
                <?php if ($totalSignatures > 0): ?>
                    <button onclick="downloadAllSignatures()" class="btn btn-sm btn-success">
                        <i class="fas fa-file-archive"></i> Download All ZIP
                    </button>
                    <?php if (empty($search)): // Only allow delete all when not searching to avoid confusion ?>
                    <button onclick="confirmDeleteAll()" class="btn btn-sm btn-danger">
                        <i class="fas fa-trash-alt"></i> Delete All
                    </button>
                    <?php endif; ?>
                <?php endif; ?>
                </div>
            </div>

            <div class="search-bar-container">
                <form method="GET" action="generator.php" style="width:100%; display:flex; gap:10px;">
                    <input type="text" name="search" class="search-input" 
                           placeholder="Search by name, email or role..." 
                           value="<?php echo htmlspecialchars($search, ENT_QUOTES, 'UTF-8'); ?>">
                    <button type="submit" class="btn btn-primary"><i class="fas fa-search"></i> Search</button>
                    <?php if (!empty($search)): ?>
                        <a href="generator.php" class="btn btn-secondary" style="border:1px solid #ccc; color:#333">Clear</a>
                    <?php endif; ?>
                </form>
            </div>

            <div class="signature-list">
                <?php if (empty($signatures)): ?>
                    <div class="empty-state">
                        <i class="fas fa-folder-open empty-icon"></i>
                        <p>
                            <?php echo !empty($search) ? "No results found for '".htmlspecialchars($search)."'." : "No signatures generated yet."; ?>
                        </p>
                    </div>
                <?php else: ?>
                    <?php foreach ($signatures as $sig): ?>
                    
                    <?php 
                        // Generate preview safely
                        $tplPath = 'templates/' . basename($sig['template']);
                        $encodedHtml = "";

                        if (file_exists($tplPath)) {
                            $rawTpl = file_get_contents($tplPath);
                            $previewHtml = str_replace(
                                ['{{NAME}}', '{{ROLE}}', '{{EMAIL}}', '{{PHONE}}'],
                                [
                                    htmlspecialchars($sig['name'], ENT_QUOTES, 'UTF-8'), 
                                    htmlspecialchars($sig['role'], ENT_QUOTES, 'UTF-8'), 
                                    htmlspecialchars($sig['email'], ENT_QUOTES, 'UTF-8'), 
                                    htmlspecialchars($sig['phone'], ENT_QUOTES, 'UTF-8')
                                ],
                                $rawTpl
                            );
                            $encodedHtml = htmlspecialchars($previewHtml, ENT_QUOTES, 'UTF-8');
                        }
                    ?>

                    <div class="signature-item" style="flex-wrap: wrap;">
                        <div style="display:flex; justify-content:space-between; width:100%; align-items:center;">
                            <div class="sig-details">
                                <h4><?php echo htmlspecialchars($sig['name'], ENT_QUOTES, 'UTF-8'); ?></h4>
                                <p><?php echo htmlspecialchars($sig['role'], ENT_QUOTES, 'UTF-8'); ?> &bull; <?php echo htmlspecialchars($sig['email'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <p style="font-size:0.75rem; color:#94a3b8; margin-top:0.25rem">
                                    <i class="far fa-clock"></i> <?php echo date('M d, Y', strtotime($sig['created_at'])); ?>
                                    &bull; <span style="background:#f1f5f9; padding:2px 6px; border-radius:4px; font-family:monospace;"><?php echo htmlspecialchars($sig['template'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </p>
                            </div>
                            
                            <div class="sig-actions" style="display:flex; gap:0.5rem; align-items:center;">
                                <?php if($encodedHtml): ?>
                                <button onclick="togglePreview(<?php echo $sig['id']; ?>)" class="btn btn-sm btn-secondary" title="Show Preview" style="background:white; border:1px solid #e2e8f0;">
                                    <i class="fas fa-eye"></i>
                                </button>
                                <?php endif; ?>
                                
                                <a href="download.php?id=<?php echo $sig['id']; ?>" class="btn btn-sm btn-primary" title="Download">
                                    <i class="fas fa-download"></i>
                                </a>
                                <a href="generate.php?delete=<?php echo $sig['id']; ?>&csrf_token=<?php echo $_SESSION['csrf_token']; ?>" 
                                   class="btn btn-sm btn-danger"
                                   onclick="return confirm('Really delete?')" title="Delete">
                                    <i class="fas fa-trash"></i>
                                </a>
                            </div>
                        </div>

                        <div id="preview-<?php echo $sig['id']; ?>" class="sig-preview-container">
                            <div style="margin-bottom:5px; font-size:0.75rem; color:#64748b; font-weight:700; text-transform:uppercase;">HTML Preview</div>
                            <?php if ($encodedHtml): ?>
                                <iframe class="preview-iframe" sandbox="allow-same-origin" srcdoc="<?php echo $encodedHtml; ?>"></iframe>
                            <?php else: ?>
                                <div style="color:red; font-size:0.9rem;">Template file not found.</div>
                            <?php endif; ?>
                        </div>
                    </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>

            <?php if ($totalPages > 1): ?>
            <div class="pagination">
                <?php 
                    $urlPattern = "generator.php?search=" . urlencode($search) . "&page=";
                    
                    // Previous Button
                    if ($page > 1) {
                        echo '<a href="' . $urlPattern . ($page - 1) . '" class="page-link">&laquo; Prev</a>';
                    } else {
                        echo '<span class="page-link disabled">&laquo; Prev</span>';
                    }
                    
                    // Page Numbers (Show max 5 pages around current)
                    $start = max(1, $page - 2);
                    $end = min($totalPages, $page + 2);
                    
                    if ($start > 1) echo '<span class="page-link disabled">...</span>';
                    
                    for ($i = $start; $i <= $end; $i++) {
                        $active = ($i == $page) ? 'active' : '';
                        echo '<a href="' . $urlPattern . $i . '" class="page-link ' . $active . '">' . $i . '</a>';
                    }
                    
                    if ($end < $totalPages) echo '<span class="page-link disabled">...</span>';

                    // Next Button
                    if ($page < $totalPages) {
                        echo '<a href="' . $urlPattern . ($page + 1) . '" class="page-link">Next &raquo;</a>';
                    } else {
                        echo '<span class="page-link disabled">Next &raquo;</span>';
                    }
                ?>
            </div>
            <div style="text-align:center; font-size:0.8rem; color:#94a3b8; margin-top:0.5rem;">
                Page <?php echo $page; ?> of <?php echo $totalPages; ?>
            </div>
            <?php endif; ?>

        </section>

    </main>

    <div class="loading-overlay" id="loadingOverlay">
        <div style="text-align:center">
            <div class="spinner"></div>
            <p style="margin-top:1rem; font-weight:600">Processing...</p>
        </div>
    </div>
    
    <form id="deleteAllForm" method="POST" action="generator.php" style="display:none;">
        <input type="hidden" name="action" value="delete_all">
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    </form>

    <script>
        function saveToStorage() {
            const data = {
                name: document.getElementById('inp_name').value,
                role: document.getElementById('inp_role').value,
                email: document.getElementById('inp_email').value,
                phone: document.getElementById('inp_phone').value,
                template: document.getElementById('inp_template').value
            };
            sessionStorage.setItem('sig_form_data', JSON.stringify(data));
        }

        function loadFromStorage() {
            const roleInput = document.getElementById('inp_role');
            if (roleInput && roleInput.value === '' && sessionStorage.getItem('sig_form_data')) {
                try {
                    const data = JSON.parse(sessionStorage.getItem('sig_form_data'));
                    if(data.name) document.getElementById('inp_name').value = data.name;
                    if(data.role) document.getElementById('inp_role').value = data.role;
                    if(data.email) document.getElementById('inp_email').value = data.email;
                    if(data.phone) document.getElementById('inp_phone').value = data.phone;
                    if(data.template) document.getElementById('inp_template').value = data.template;
                } catch(e) { console.error(e); }
            }
        }
        document.addEventListener('DOMContentLoaded', loadFromStorage);

        const sigForm = document.getElementById('signatureForm');
        if(sigForm) {
            sigForm.addEventListener('submit', function(e) {
                const phone = document.getElementById('inp_phone').value;
                if (!/^[\+\d\s\-\(\)]{5,25}$/.test(phone)) {
                    alert('Please enter a valid phone number');
                    e.preventDefault();
                    return false;
                }
                document.getElementById('loadingOverlay').style.display = 'flex';
            });
        }

        function copyToClipboard() {
            const rawSource = document.getElementById('rawHtmlSource');
            const content = rawSource ? rawSource.value : document.querySelector('.preview-html').innerHTML;
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(content).then(() => alert('Copied!')).catch(e => fallbackCopy(content));
            } else { fallbackCopy(content); }
        }
        function fallbackCopy(text) {
            const ta = document.createElement("textarea");
            ta.value = text; ta.style.position="fixed"; document.body.appendChild(ta);
            ta.focus(); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
            alert('Copied!');
        }

        function closePreview() {
            sessionStorage.removeItem('sig_form_data');
            window.location.href = 'generator.php?clear=1';
        }
        function confirmDeleteAll() {
            if(confirm('Delete ALL signatures? Cannot be undone.')) document.getElementById('deleteAllForm').submit();
        }
        function downloadAllSignatures() {
            const overlay = document.getElementById('loadingOverlay');
            overlay.style.display = 'flex';
            setTimeout(() => { window.location.href = 'download_all.php'; setTimeout(() => overlay.style.display='none', 3000); }, 500);
        }
        function togglePreview(id) {
            const el = document.getElementById('preview-' + id);
            const icon = el.parentElement.querySelector('.btn-secondary i');
            el.style.display = (el.style.display === 'block') ? 'none' : 'block';
            icon.className = (el.style.display === 'block') ? 'fas fa-eye-slash' : 'fas fa-eye';
        }
    </script>
</body>
</html>
