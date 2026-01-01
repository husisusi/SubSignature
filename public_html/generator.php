<?php
require_once 'includes/config.php';
requireLogin();

// 1. SECURITY & BACKEND LOGIC
// ---------------------------------------------------------------------
// CSRF Token generieren
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$user_id = $_SESSION['user_id'];
$message = '';

// Standardwerte laden (aus Session oder Nutzerprofil)
$formData = $_SESSION['form_data'] ?? [];
$defaultName = $formData['name'] ?? $_SESSION['full_name'] ?? '';
$defaultEmail = $formData['email'] ?? $_SESSION['email'] ?? '';
$defaultRole = $formData['role'] ?? '';
$defaultPhone = $formData['phone'] ?? '';
// Check for custom default config
$configFile = __DIR__ . '/templates/default_config.txt';
$systemDefault = file_exists($configFile) ? trim(file_get_contents($configFile)) : 'signature_default.html';

$defaultTemplate = $formData['template'] ?? $systemDefault;

// Templates JavaScript load (Live Preview)
$templatesJS = [];
$templatesDir = __DIR__ . '/templates';
$template_files_glob = glob($templatesDir . '/*.html');
if ($template_files_glob) {
    foreach ($template_files_glob as $file) {
        $basename = basename($file);
        $templatesJS[$basename] = file_get_contents($file);
    }
}

// SEARCH & PAGINATION
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

// FORMULAR AKTIONEN (Speichern / Löschen)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF Prüfung (Prio 1 Security)
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Security Error: Invalid CSRF Token");
    }

    // Speichern
    if (isset($_POST['action']) && $_POST['action'] === 'save') {
        $name = trim($_POST['name'] ?? '');
        $role = trim($_POST['role'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $phone = trim($_POST['phone'] ?? '');
        $template = trim($_POST['template'] ?? '');

        $stmt = $db->prepare("INSERT INTO user_signatures (user_id, name, role, email, phone, template) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
        $stmt->bindValue(2, $name, SQLITE3_TEXT);
        $stmt->bindValue(3, $role, SQLITE3_TEXT);
        $stmt->bindValue(4, $email, SQLITE3_TEXT);
        $stmt->bindValue(5, $phone, SQLITE3_TEXT);
        $stmt->bindValue(6, $template, SQLITE3_TEXT);
        $stmt->execute();

        $_SESSION['form_data'] = $_POST;
        header("Location: generator.php?success=1");
        exit;
    }
    
    // Alles löschen
    if (isset($_POST['action']) && $_POST['action'] === 'delete_all') {
        $stmt = $db->prepare("DELETE FROM user_signatures WHERE user_id = ?");
        $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
        $stmt->execute();
        header("Location: generator.php?success=deleted");
        exit;
    }
}

if (isset($_GET['success'])) {
    if ($_GET['success'] == 'deleted') $message = "All signatures deleted successfully!";
    else $message = "Signature saved successfully!";
}

// Templates Liste für PHP (Dropdown)
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
    <title>Signature Generator</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/all.min.css">
    
    <style>
        /* --- GENERAL --- */
        .visually-hidden { position: absolute; left: -9999px; opacity: 0; }
        .alert { padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; display: flex; gap: 0.75rem; align-items: center; }
        .alert-success { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }

        /* --- SPLIT EDITOR STYLES --- */
        .split-editor-container {
            display: grid;
            grid-template-columns: 1fr 1fr; 
            gap: 2rem;
            align-items: start;
        }

        /* LEFT: Form */
        .form-column .form-group { margin-bottom: 1rem; }
        .form-column label { display: block; font-size: 0.85rem; font-weight: 600; color: #475569; margin-bottom: 0.4rem; }
        .form-column input, .form-column select { width: 100%; padding: 0.75rem; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 0.95rem; background: #f8fafc; }
        .form-column input:focus { background: white; border-color: var(--primary); outline: none; }

        /* RIGHT: Preview (Sticky) */
        .preview-column { position: sticky; top: 20px; }
        .live-preview-box {
            background: #f1f5f9; border-radius: 12px; padding: 2rem;
            min-height: 300px; display: flex; align-items: center; justify-content: center;
            border: 1px solid #e2e8f0;
        }
        .preview-paper {
            background: white; padding: 2rem; border-radius: 8px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); width: 100%; overflow: hidden;
        }
        .preview-header { font-size: 0.8rem; font-weight: bold; color: #94a3b8; margin-bottom: 10px; text-transform: uppercase; letter-spacing: 0.5px; }

        /* --- LIST & SEARCH STYLES --- */
        .search-bar-container { display: flex; gap: 10px; margin-bottom: 1.5rem; background: #f8fafc; padding: 1rem; border-radius: 8px; border: 1px solid var(--border); }
        .search-input { flex: 1; padding: 0.6rem; border: 1px solid #cbd5e1; border-radius: 6px; }
        .empty-state { text-align: center; padding: 4rem 1rem; color: #94a3b8; }
        .empty-icon { font-size: 3rem; margin-bottom: 1rem; opacity: 0.5; }
        .pagination { display: flex; justify-content: center; gap: 5px; margin-top: 2rem; }
        .page-link { padding: 0.5rem 1rem; border: 1px solid var(--border); background: white; text-decoration: none; color: var(--text-main); border-radius: 6px; }
        .page-link.active { background: var(--primary); color: white; border-color: var(--primary); }
        .page-link.disabled { opacity: 0.5; pointer-events: none; }

        /* --- MODAL FOR SAVED PREVIEW --- */
        .modal-overlay {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.5); z-index: 9999;
            display: none; justify-content: center; align-items: center;
            backdrop-filter: blur(3px);
        }
        .modal-box {
            background: white; width: 90%; max-width: 700px;
            border-radius: 12px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.1);
            overflow: hidden; animation: popIn 0.2s ease-out;
        }
        @keyframes popIn { from {transform: scale(0.95); opacity: 0;} to {transform: scale(1); opacity: 1;} }
        .modal-header { padding: 1rem 1.5rem; border-bottom: 1px solid #e2e8f0; display: flex; justify-content: space-between; align-items: center; background: #f8fafc; }
        .modal-body { padding: 0; height: 300px; background: white; }
        .modal-iframe { width: 100%; height: 100%; border: none; }
        .modal-footer { padding: 1rem; text-align: right; border-top: 1px solid #e2e8f0; background: #f8fafc; }
        .close-modal-btn { background: none; border: none; font-size: 1.5rem; cursor: pointer; color: #64748b; }

        @media (max-width: 900px) { .split-editor-container { grid-template-columns: 1fr; } .preview-column { position: static; margin-top: 20px; } }
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
            
            <form action="generator.php" method="POST" id="signatureForm">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

                <div class="split-editor-container">
                    
                    <div class="form-column">
                        <div class="form-group">
                            <label>Template</label>
                            <select name="template" id="inp_template" required>
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

                        <div class="form-group">
                            <label>Full Name</label>
                            <input type="text" id="inp_name" name="name" required 
                                   value="<?php echo htmlspecialchars($defaultName); ?>" placeholder="e.g. Sarah Smith">
                        </div>

                        <div class="form-group">
                            <label>Job Title / Position</label>
                            <input type="text" id="inp_role" name="role" required 
                                   value="<?php echo htmlspecialchars($defaultRole); ?>" placeholder="e.g. CEO">
                        </div>

                        <div class="form-group">
                            <label>Email Address</label>
                            <input type="email" id="inp_email" name="email" required 
                                   value="<?php echo htmlspecialchars($defaultEmail); ?>" placeholder="sarah@company.com">
                        </div>

                        <div class="form-group">
                            <label>Phone Number</label>
                            <input type="tel" id="inp_phone" name="phone" required 
                                   value="<?php echo htmlspecialchars($defaultPhone); ?>" placeholder="+49 123 456789">
                        </div>

                        <div class="form-actions" style="margin-top: 1.5rem;">
                            <button type="submit" name="action" value="save" class="btn btn-primary" style="width:100%">
                                <i class="fas fa-save"></i> Save Signature
                            </button>
                        </div>
                    </div>

                    <div class="preview-column">
                        <div class="live-preview-box">
                            <div style="width:100%">
                                <div class="preview-header"><i class="fas fa-eye"></i> Live Preview</div>
                                <div class="preview-paper">
                                    <div id="live-render-area"></div>
                                </div>
                                <div style="text-align:center; margin-top:10px; font-size:0.8rem; color:#94a3b8;">
                                    Updates automatically as you type
                                </div>
                            </div>
                        </div>
                    </div>

                </div>
            </form>
        </section>

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
                        // HTML PREPARE FOR MODAL PREVIEW
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
                                    <textarea id="source-<?php echo $sig['id']; ?>" class="visually-hidden"><?php echo $encodedHtml; ?></textarea>
                                    <button onclick="openModal(<?php echo $sig['id']; ?>)" class="btn btn-sm btn-secondary" style="background:white; border:1px solid #cbd5e1;" title="Preview">
                                        <i class="fas fa-eye"></i>
                                    </button>
                                <?php endif; ?>

                                <a href="download.php?id=<?php echo $sig['id']; ?>" class="btn btn-sm btn-primary"><i class="fas fa-download"></i></a>
                                <a href="generate.php?delete=<?php echo $sig['id']; ?>&csrf_token=<?php echo $_SESSION['csrf_token']; ?>" class="btn btn-sm btn-danger" onclick="return confirm('Delete?')"><i class="fas fa-trash"></i></a>
                            </div>
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

    <div id="previewModal" class="modal-overlay">
        <div class="modal-box">
            <div class="modal-header">
                <h3 style="margin:0">Signature Preview</h3>
                <button class="close-modal-btn" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body">
                <iframe id="modalFrame" class="modal-iframe" sandbox="allow-same-origin"></iframe>
            </div>
            <div class="modal-footer">
                <button class="btn btn-sm btn-secondary" onclick="closeModal()">Close</button>
            </div>
        </div>
    </div>
    
    <form id="deleteAllForm" method="POST" action="generator.php" style="display:none;">
        <input type="hidden" name="action" value="delete_all">
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    </form>

    <script>
        // 1. LIVE PREVIEW LOGIC
        const rawTemplates = <?php echo json_encode($templatesJS); ?>;

        const inputs = {
            name: document.getElementById('inp_name'),
            role: document.getElementById('inp_role'),
            email: document.getElementById('inp_email'),
            phone: document.getElementById('inp_phone'),
            template: document.getElementById('inp_template')
        };
        const renderArea = document.getElementById('live-render-area');

        function renderSignature() {
            const selectedFile = inputs.template.value;
            let html = rawTemplates[selectedFile] || '<p style="color:#cbd5e1; text-align:center; padding:20px;">Template not found</p>';

            html = html.replace(/{{NAME}}/g, inputs.name.value || 'Your Name');
            html = html.replace(/{{ROLE}}/g, inputs.role.value || 'Job Title');
            html = html.replace(/{{EMAIL}}/g, inputs.email.value || 'email@example.com');
            html = html.replace(/{{PHONE}}/g, inputs.phone.value || '+1 234 567 890');
            const cleanPhone = inputs.phone.value.replace(/[^0-9+]/g, '');
            html = html.replace(/{{PHONE_CLEAN}}/g, cleanPhone);

            renderArea.innerHTML = html;
        }

        Object.values(inputs).forEach(input => {
            if(input) {
                input.addEventListener('input', renderSignature);
                input.addEventListener('change', renderSignature);
            }
        });

        // 2. STORAGE LOGIC
        function saveToStorage() {
            const data = {
                name: inputs.name.value,
                role: inputs.role.value,
                email: inputs.email.value,
                phone: inputs.phone.value,
                template: inputs.template.value
            };
            sessionStorage.setItem('sig_form_data', JSON.stringify(data));
        }

        function loadFromStorage() {
            const roleInput = document.getElementById('inp_role');
            if (roleInput && roleInput.value === '' && sessionStorage.getItem('sig_form_data')) {
                try {
                    const data = JSON.parse(sessionStorage.getItem('sig_form_data'));
                    if(data.name) inputs.name.value = data.name;
                    if(data.role) inputs.role.value = data.role;
                    if(data.email) inputs.email.value = data.email;
                    if(data.phone) inputs.phone.value = data.phone;
                    if(data.template) inputs.template.value = data.template;
                } catch(e) {}
            }
            renderSignature();
        }

        document.addEventListener('DOMContentLoaded', loadFromStorage);

        // 3. MODAL LOGIC (FIXED SPACING)
        const modal = document.getElementById('previewModal');
        const modalFrame = document.getElementById('modalFrame');

        function openModal(id) {
            const source = document.getElementById('source-' + id);
            if (source) {
                // CSS Reset injected directly into iframe source
                const styleReset = `
                    <style>
                        body { margin: 0; padding: 20px; font-family: Arial, Helvetica, sans-serif; background-color: #ffffff; }
                        p { margin: 0; padding: 0; line-height: 1.4; } 
                        table { border-collapse: collapse; border-spacing: 0; }
                        td { padding: 0; vertical-align: top; }
                        a { text-decoration: none; color: inherit; }
                    </style>
                `;
                
                modalFrame.srcdoc = styleReset + source.value;
                modal.style.display = 'flex';
            }
        }

        function closeModal() {
            modal.style.display = 'none';
            modalFrame.srcdoc = '';
        }

        window.onclick = function(event) {
            if (event.target == modal) {
                closeModal();
            }
        }

        // 4. HELPERS
        function confirmDeleteAll() { if(confirm('Delete ALL signatures?')) document.getElementById('deleteAllForm').submit(); }
        function downloadAllSignatures() { window.location.href = 'download_all.php'; }
    </script>
</body>
</html>
