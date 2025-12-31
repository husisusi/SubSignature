<?php
require_once 'includes/config.php';
requireLogin();

// 1. Security: Generate CSRF Token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$user_id = $_SESSION['user_id'];
$message = '';

// --- PAGINATION & SEARCH LOGIC ---
$search = trim($_GET['search'] ?? '');
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
if ($page < 1) $page = 1;
$limit = 25; 
$offset = ($page - 1) * $limit;

$whereSQL = "WHERE user_id = :uid";
$params = [':uid' => $user_id];

if (!empty($search)) {
    $whereSQL .= " AND (name LIKE :search OR email LIKE :search OR role LIKE :search)";
    $params[':search'] = '%' . $search . '%';
}

$countSql = "SELECT COUNT(*) as total FROM user_signatures $whereSQL";
$stmt = $db->prepare($countSql);
foreach ($params as $key => $val) {
    $stmt->bindValue($key, $val, is_int($val) ? SQLITE3_INTEGER : SQLITE3_TEXT);
}
$totalResult = $stmt->execute();
$totalSignatures = $totalResult->fetchArray(SQLITE3_ASSOC)['total'];
$totalPages = ceil($totalSignatures / $limit);

$dataSql = "SELECT * FROM user_signatures $whereSQL ORDER BY created_at DESC LIMIT :limit OFFSET :offset";
$stmt = $db->prepare($dataSql);
foreach ($params as $key => $val) {
    $stmt->bindValue($key, $val, is_int($val) ? SQLITE3_INTEGER : SQLITE3_TEXT);
}
$stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
$stmt->bindValue(':offset', $offset, SQLITE3_INTEGER);

$result = $stmt->execute();
$signatures = [];
while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
    $signatures[] = $row;
}

// Data Persistence Logic
$formData = $_SESSION['form_data'] ?? [];
$defaultName = $formData['name'] ?? $_SESSION['full_name'] ?? '';
$defaultEmail = $formData['email'] ?? $_SESSION['email'] ?? '';
$defaultRole = $formData['role'] ?? '';
$defaultPhone = $formData['phone'] ?? '';
$defaultTemplate = $formData['template'] ?? 'signature_default.html';

// Handle Actions (Delete All)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete_all') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Security Error: Invalid CSRF Token");
    }
    $stmt = $db->prepare("DELETE FROM user_signatures WHERE user_id = ?");
    $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
    $stmt->execute();
    header("Location: generator.php?success=deleted");
    exit;
}

if (isset($_GET['success']) && $_GET['success'] == 'deleted') {
    $message = "All signatures deleted successfully!";
    $signatures = [];
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
    <title>SubSignature Generator</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/all.min.css">
    
    <style>
        /* --- COMPACT STYLES --- */
        .compact-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }
        .form-group { margin-bottom: 10px; }
        .form-group label {
            font-size: 0.85rem;
            font-weight: 600;
            margin-bottom: 3px;
            color: #475569;
        }
        .form-group input, .form-group select {
            padding: 8px;
            font-size: 0.95rem;
        }
        
        /* Compact Header Actions */
        .header-actions { display: flex; gap: 8px; align-items: center; }

        /* --- EXISTING STYLES --- */
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
        
        .search-bar-container { display: flex; gap: 10px; margin-bottom: 1.5rem; background: #f8fafc; padding: 1rem; border-radius: 8px; border: 1px solid var(--border); }
        .search-input { flex: 1; padding: 0.6rem; border: 1px solid #cbd5e1; border-radius: 6px; }
        .pagination { display: flex; justify-content: center; gap: 5px; margin-top: 2rem; }
        .page-link { padding: 0.5rem 1rem; border: 1px solid var(--border); background: white; text-decoration: none; color: var(--text-main); border-radius: 6px; }
        .page-link.active { background: var(--primary); color: white; border-color: var(--primary); }
        .page-link.disabled { opacity: 0.5; pointer-events: none; }
        
        @media (max-width: 768px) { .compact-grid { grid-template-columns: 1fr; } }
    </style>
</head>
<body>

    <aside class="sidebar">
        <?php if (file_exists('includes/navbar.php')) include 'includes/navbar.php'; ?>
        <div class="sidebar-footer">
            <div class="user-profile">
                <div class="avatar"><?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?></div>
                <div class="user-info">
                    <div><?php echo htmlspecialchars($_SESSION['username']); ?></div>
                    <span><?php echo isAdmin() ? 'Administrator' : 'User'; ?></span>
                </div>
            </div>
            <a href="logout.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> <span>Sign Out</span></a>
        </div>
    </aside>

    <main class="main-content">
        
        <header class="page-header">
            <h2>Signature Generator</h2>
            <p>Create and manage your email signatures.</p>
        </header>

        <?php if ($message): ?>
            <div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>

        <section class="card" id="create-form">
            <div class="card-header">
                <h3><i class="far fa-edit"></i> New Signature</h3>
            </div>
            
            <form action="generate.php" method="POST" id="signatureForm">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

                <div class="compact-grid">
                    <div>
                        <div class="form-group">
                            <label>Name</label>
                            <input type="text" id="inp_name" name="name" required 
                                   value="<?php echo htmlspecialchars($defaultName); ?>" placeholder="e.g. Sarah Smith">
                        </div>
                        <div class="form-group">
                            <label>Email</label>
                            <input type="email" id="inp_email" name="email" required 
                                   value="<?php echo htmlspecialchars($defaultEmail); ?>" placeholder="sarah@company.com">
                        </div>
                    </div>
                    
                    <div>
                        <div class="form-group">
                            <label>Position / Role</label>
                            <input type="text" id="inp_role" name="role" required 
                                   value="<?php echo htmlspecialchars($defaultRole); ?>" placeholder="e.g. Manager">
                        </div>
                        <div class="form-group">
                            <label>Phone</label>
                            <input type="tel" id="inp_phone" name="phone" required 
                                   value="<?php echo htmlspecialchars($defaultPhone); ?>" placeholder="+49 123 456789">
                        </div>
                    </div>
                </div>
                
                <div class="form-group" style="margin-top: 0.5rem;">
                    <label>Select Template</label>
                    <select name="template" id="inp_template" required style="width:100%">
                        <?php foreach ($templates as $template): ?>
                            <?php 
                            $cleanName = ucfirst(str_replace(['signature_', '.html', '_'], ['','',' '], $template));
                            $selected = ($template == $defaultTemplate) ? 'selected' : '';
                            ?>
                            <option value="<?php echo htmlspecialchars($template); ?>" <?php echo $selected; ?>>
                                <?php echo htmlspecialchars($cleanName); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="form-actions" style="margin-top: 10px;">
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
            <div class="card-header" style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 1.5rem;">
                <h3 style="margin:0;">Preview</h3>
                
                <div class="header-actions">
                    <button type="button" onclick="copyToClipboard()" class="btn btn-sm btn-primary"><i class="fas fa-copy"></i> Copy</button>
                    <a href="download.php?type=preview" class="btn btn-sm btn-success"><i class="fas fa-download"></i> HTML</a>
                    <button onclick="closePreview()" class="btn btn-sm btn-danger" style="background:white; color:#dc2626; border:1px solid #fecaca;"><i class="fas fa-times"></i></button>
                </div>
            </div>
            
            <div class="preview-box" style="padding:1.5rem; background:white;">
                <div class="preview-html" id="signatureContainer"><?php echo $_SESSION['preview']; ?></div>
                <textarea id="rawHtmlSource" class="visually-hidden"><?php echo htmlspecialchars($_SESSION['preview']); ?></textarea>
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
                    <button onclick="downloadAllSignatures()" class="btn btn-sm btn-success"><i class="fas fa-file-archive"></i> ZIP</button>
                    <?php if (empty($search)): ?>
                    <button onclick="confirmDeleteAll()" class="btn btn-sm btn-danger"><i class="fas fa-trash-alt"></i> Delete All</button>
                    <?php endif; ?>
                <?php endif; ?>
                </div>
            </div>

            <div class="search-bar-container">
                <form method="GET" action="generator.php" style="width:100%; display:flex; gap:10px;">
                    <input type="text" name="search" class="search-input" placeholder="Search..." value="<?php echo htmlspecialchars($search); ?>">
                    <button type="submit" class="btn btn-primary"><i class="fas fa-search"></i></button>
                    <?php if (!empty($search)): ?><a href="generator.php" class="btn btn-secondary">Clear</a><?php endif; ?>
                </form>
            </div>

            <div class="signature-list">
                <?php if (empty($signatures)): ?>
                    <div class="empty-state">
                        <i class="fas fa-folder-open empty-icon"></i>
                        <p><?php echo !empty($search) ? "No results found." : "No signatures generated yet."; ?></p>
                    </div>
                <?php else: ?>
                    <?php foreach ($signatures as $sig): ?>
                    <?php 
                        $tplPath = 'templates/' . basename($sig['template']);
                        $encodedHtml = "";
                        if (file_exists($tplPath)) {
                            $rawTpl = file_get_contents($tplPath);
                            $previewHtml = str_replace(
                                ['{{NAME}}', '{{ROLE}}', '{{EMAIL}}', '{{PHONE}}'],
                                [htmlspecialchars($sig['name']), htmlspecialchars($sig['role']), htmlspecialchars($sig['email']), htmlspecialchars($sig['phone'])],
                                $rawTpl
                            );
                            $encodedHtml = htmlspecialchars($previewHtml, ENT_QUOTES, 'UTF-8');
                        }
                    ?>
                    <div class="signature-item" style="flex-wrap: wrap;">
                        <div style="display:flex; justify-content:space-between; width:100%; align-items:center;">
                            <div class="sig-details">
                                <h4><?php echo htmlspecialchars($sig['name']); ?></h4>
                                <p style="font-size:0.85rem; color:#64748b; margin-top:0.25rem"><?php echo htmlspecialchars($sig['role']); ?> &bull; <?php echo htmlspecialchars($sig['email']); ?></p>
                            </div>
                            
                            <div class="sig-actions" style="display:flex; gap:0.5rem;">
                                <?php if($encodedHtml): ?>
                                <button onclick="togglePreview(<?php echo $sig['id']; ?>)" class="btn btn-sm btn-secondary" style="background:white; border:1px solid #e2e8f0;"><i class="fas fa-eye"></i></button>
                                <?php endif; ?>
                                <a href="download.php?id=<?php echo $sig['id']; ?>" class="btn btn-sm btn-primary"><i class="fas fa-download"></i></a>
                                <a href="generate.php?delete=<?php echo $sig['id']; ?>&csrf_token=<?php echo $_SESSION['csrf_token']; ?>" class="btn btn-sm btn-danger" onclick="return confirm('Delete?')"><i class="fas fa-trash"></i></a>
                            </div>
                        </div>

                        <div id="preview-<?php echo $sig['id']; ?>" class="sig-preview-container">
                            <?php if ($encodedHtml): ?><iframe class="preview-iframe" sandbox="allow-same-origin" srcdoc="<?php echo $encodedHtml; ?>"></iframe><?php endif; ?>
                        </div>
                    </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>

            <?php if ($totalPages > 1): ?>
            <div class="pagination">
                <?php 
                    $urlPattern = "generator.php?search=" . urlencode($search) . "&page=";
                    if ($page > 1) echo '<a href="' . $urlPattern . ($page - 1) . '" class="page-link">&laquo;</a>';
                    else echo '<span class="page-link disabled">&laquo;</span>';
                    
                    $start = max(1, $page - 2);
                    $end = min($totalPages, $page + 2);
                    for ($i = $start; $i <= $end; $i++) {
                        $active = ($i == $page) ? 'active' : '';
                        echo '<a href="' . $urlPattern . $i . '" class="page-link ' . $active . '">' . $i . '</a>';
                    }
                    if ($page < $totalPages) echo '<a href="' . $urlPattern . ($page + 1) . '" class="page-link">&raquo;</a>';
                    else echo '<span class="page-link disabled">&raquo;</span>';
                ?>
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
            el.style.display = (el.style.display === 'block') ? 'none' : 'block';
        }
    </script>
</body>
</html>
