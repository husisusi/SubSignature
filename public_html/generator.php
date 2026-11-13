<?php
/**
 * generator.php - create, preview and manage the user's own signatures.
 */
require_once 'includes/config.php';
requireLogin();

$user_id = (int)$_SESSION['user_id'];

// ---------------------------------------------------------------------
// 1. FORM ACTIONS (POST + CSRF)
// ---------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    requireCsrf();
    $action = $_POST['action'] ?? '';

    if ($action === 'save') {
        [$fields, $errors] = validateSignatureFields($_POST, true);
        $template = resolveTemplateName($_POST['template'] ?? '');
        $_SESSION['form_data'] = $fields + ['template' => $template];

        if ($errors) {
            setFlash('error', implode(' ', $errors));
        } else {
            $stmt = $db->prepare('INSERT INTO user_signatures (user_id, name, role, email, phone, template) VALUES (?, ?, ?, ?, ?, ?)');
            $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
            $stmt->bindValue(2, $fields['name'], SQLITE3_TEXT);
            $stmt->bindValue(3, $fields['role'], SQLITE3_TEXT);
            $stmt->bindValue(4, $fields['email'], SQLITE3_TEXT);
            $stmt->bindValue(5, $fields['phone'], SQLITE3_TEXT);
            $stmt->bindValue(6, $template, SQLITE3_TEXT);
            $stmt->execute();
            setFlash('success', t('Signature saved successfully!'));
        }
        header('Location: generator.php');
        exit;
    }

    if ($action === 'delete_all') {
        $stmt = $db->prepare('DELETE FROM user_signatures WHERE user_id = ?');
        $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
        $stmt->execute();
        setFlash('success', t('All signatures deleted successfully!'));
        header('Location: generator.php');
        exit;
    }

    header('Location: generator.php');
    exit;
}

$message = popFlash('success') ?: (string)($_SESSION['success'] ?? '');
$errorMessage = popFlash('error') ?: (string)($_SESSION['error'] ?? '');
unset($_SESSION['success'], $_SESSION['error']);

// ---------------------------------------------------------------------
// 2. FORM DEFAULTS
// ---------------------------------------------------------------------
$formData = $_SESSION['form_data'] ?? [];
unset($_SESSION['form_data']);

// On a fresh page load the administrator's default template is preselected.
$defaultTemplate = getDefaultTemplateName();
$defaultName  = $formData['name']  ?? ($_SESSION['full_name'] ?? '');
$defaultEmail = $formData['email'] ?? ($_SESSION['email'] ?? '');
$defaultRole  = $formData['role']  ?? '';
$defaultPhone = $formData['phone'] ?? '';

// Templates for the dropdown and for the JavaScript live preview. The HTML
// is passed through the server-side sanitiser and again client-side.
$templates = [];
$templatesJS = [];
foreach (listSignatureTemplates() as $file) {
    $templates[$file] = $file;
    $templatesJS[$file] = sanitizeTemplateHtml(loadSignatureTemplate($file));
}

// ---------------------------------------------------------------------
// 3. SEARCH & PAGINATION
// ---------------------------------------------------------------------
$search = cleanText($_GET['search'] ?? '', 100);
$page = max(1, min(100000, (int)($_GET['page'] ?? 1)));
$limit = 25;
$offset = ($page - 1) * $limit;

$whereSQL = 'WHERE user_id = :uid';
$params = [':uid' => $user_id];
if ($search !== '') {
    $whereSQL .= ' AND (name LIKE :search ESCAPE \'\\\' OR email LIKE :search ESCAPE \'\\\' OR role LIKE :search ESCAPE \'\\\')';
    // Escape LIKE wildcards in the user's search text.
    $params[':search'] = '%' . addcslashes($search, '%_\\') . '%';
}

$stmt = $db->prepare("SELECT COUNT(*) FROM user_signatures $whereSQL");
foreach ($params as $key => $val) {
    $stmt->bindValue($key, $val, is_int($val) ? SQLITE3_INTEGER : SQLITE3_TEXT);
}
$totalSignatures = (int)$stmt->execute()->fetchArray(SQLITE3_NUM)[0];
$totalPages = (int)ceil($totalSignatures / $limit);

$stmt = $db->prepare("SELECT * FROM user_signatures $whereSQL ORDER BY created_at DESC, id DESC LIMIT :limit OFFSET :offset");
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
?>
<!DOCTYPE html>
<html lang="<?= e(currentLang()) ?>" dir="<?= e(langDir()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= et('Signature Generator') ?></title>
    <?= i18nHead() ?>
    <script src="<?= assetUrl('js/theme.js') ?>"></script>
    <script src="<?= assetUrl('js/alerts.js') ?>"></script>
    <link rel="stylesheet" href="<?= assetUrl('css/theme.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/style.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/all.min.css') ?>">
    <?php echo csrfMeta(); ?>
    
    <style>
        /* --- GENERAL --- */
        .visually-hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0, 0, 0, 0); opacity: 0; }

        /* --- SPLIT EDITOR STYLES --- */
        .split-editor-container {
            display: grid;
            grid-template-columns: 1fr 1fr; 
            gap: 2rem;
            align-items: start;
        }

        /* LEFT: Form */
        .form-column .form-group { margin-bottom: 1rem; }
        .form-column label { display: block; font-size: 0.85rem; font-weight: 600; color: var(--text-muted); margin-bottom: 0.4rem; }
        .form-column input, .form-column select { width: 100%; padding: 0.75rem; border: 1px solid var(--border-strong); border-radius: 6px; font-size: 0.95rem; background: var(--bg-subtle); }
        .form-column input:focus { background: var(--bg-white); border-color: var(--primary); outline: none; }

        /* --- BUTTON FIX (Flexbox for equal sizing) --- */
        .form-actions {
            display: flex;
            flex-direction: column; /* Buttons vertically stacked */
            gap: 12px; /* Consistent spacing */
            margin-top: 1.5rem;
        }
        
        .form-actions .btn {
            width: 100%;
            box-sizing: border-box; /* IMPORTANT: Ensures padding/borders don't affect width calculations */
            display: inline-flex;
            justify-content: center;
            align-items: center;
            gap: 8px; /* Space between icon and text */
            height: 45px; /* Forced equal height */
            margin: 0 !important; /* Remove any override margins */
            cursor: pointer;
        }

        /* RIGHT: Preview (Sticky) */
        .preview-column { position: sticky; top: 20px; }
        .live-preview-box {
            background: var(--bg-subtle); border-radius: 12px; padding: 2rem;
            min-height: 300px; display: flex; align-items: center; justify-content: center;
            border: 1px solid var(--border);
        }
        .preview-paper {
            background: var(--bg-white); padding: 2rem; border-radius: 8px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); width: 100%; overflow: hidden;
        }
        .preview-header { font-size: 0.8rem; font-weight: bold; color: var(--text-faint); margin-bottom: 10px; text-transform: uppercase; letter-spacing: 0.5px; }

        /* --- LIST & SEARCH STYLES --- */
        .search-bar-container { display: flex; gap: 10px; margin-bottom: 1.5rem; background: var(--bg-subtle); padding: 1rem; border-radius: 8px; border: 1px solid var(--border); }
        .search-input { flex: 1; padding: 0.6rem; border: 1px solid var(--border-strong); border-radius: 6px; }
        .empty-state { text-align: center; padding: 4rem 1rem; color: var(--text-faint); }
        .empty-icon { font-size: 3rem; margin-bottom: 1rem; opacity: 0.5; }
        .pagination { display: flex; justify-content: center; gap: 5px; margin-top: 2rem; }
        .page-link { padding: 0.5rem 1rem; border: 1px solid var(--border); background: var(--bg-white); text-decoration: none; color: var(--text-main); border-radius: 6px; }
        .page-link.active { background: var(--primary); color: white; border-color: var(--primary); }
        .page-link.disabled { opacity: 0.5; pointer-events: none; }

        /* --- MODAL FOR SAVED PREVIEW --- */
        .modal-overlay {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.5); z-index: 9999;
            display: none; justify-content: center; align-items: center;
            backdrop-filter: blur(3px);
        }
        /* --- CHANGED: Made modal significantly larger --- */
        .modal-box {
            background: var(--bg-white); 
            width: 95%; /* Use almost full width on small screens */
            max-width: 1100px; /* Max width increased for desktop */
            border-radius: 12px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.1);
            overflow: hidden; animation: popIn 0.2s ease-out;
        }
        @keyframes popIn { from {transform: scale(0.95); opacity: 0;} to {transform: scale(1); opacity: 1;} }
        
        .modal-header { padding: 1rem 1.5rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: var(--bg-subtle); }
        
        /* --- CHANGED: Increased height for better visibility --- */
        .modal-body { 
            padding: 0; 
            height: 600px; /* Height increased */
            background: var(--bg-white); 
        }
        
        .modal-iframe { width: 100%; height: 100%; border: none; }
        .modal-footer { padding: 1rem; text-align: right; border-top: 1px solid var(--border); background: var(--bg-subtle); }
        .close-modal-btn { background: none; border: none; font-size: 1.5rem; cursor: pointer; color: var(--text-muted); }

        @media (max-width: 900px) { .split-editor-container { grid-template-columns: 1fr; } .preview-column { position: static; margin-top: 20px; } }
    </style>
</head>
<body>

    <aside class="sidebar">
        <?php if (file_exists('includes/navbar.php')) include 'includes/navbar.php'; ?>
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
            <h2><?= et('Signature Generator') ?></h2>
            <p><?= et('Create and manage your email signatures.') ?></p>
        </header>

        <?= flashAlerts($message, $errorMessage) ?>

        <section class="card" id="create-form">
            <div class="card-header">
                <h3><i class="far fa-edit"></i> <?= et('New Signature') ?></h3>
            </div>
            
            <form action="generator.php" method="POST" id="signatureForm">
                <?php echo csrfField(); ?>

                <div class="split-editor-container">
                    
                    <div class="form-column">
                        <div class="form-group">
                            <label><?= et('Template') ?></label>
                            <select name="template" id="inp_template" required>
                                <?php foreach ($templates as $template): ?>
                                    <?php
                                    $cleanName = templateDisplayName($template);
                                    $selected = ($template === $defaultTemplate) ? 'selected' : '';
                                    ?>
                                    <option value="<?php echo e($template); ?>" <?php echo $selected; ?>>
                                        <?php echo e($cleanName); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>

                        <div class="form-group">
                            <label><?= et('Full Name') ?></label>
                            <input type="text" id="inp_name" name="name" required maxlength="100" 
                                   value="<?php echo e($defaultName); ?>" placeholder="<?= et('e.g. Sarah Smith') ?>">
                        </div>

                        <div class="form-group">
                            <label><?= et('Job Title / Position') ?></label>
                            <input type="text" id="inp_role" name="role" required maxlength="100" 
                                   value="<?php echo e($defaultRole); ?>" placeholder="<?= et('e.g. CEO') ?>">
                        </div>

                        <div class="form-group">
                            <label><?= et('Email Address') ?></label>
                            <input type="email" id="inp_email" name="email" required maxlength="254" 
                                   value="<?php echo e($defaultEmail); ?>" placeholder="sarah@company.com">
                        </div>

                        <div class="form-group">
                            <label><?= et('Phone Number') ?></label>
                            <input type="tel" id="inp_phone" name="phone" required maxlength="30" 
                                   value="<?php echo e($defaultPhone); ?>" placeholder="+49 123 456789">
                        </div>

                        <div class="form-actions">
                            <button type="submit" name="action" value="save" class="btn btn-primary">
                                <i class="fas fa-save"></i> <?= et('Save Signature') ?>
                            </button>

                            <button type="button" id="btn-copy" class="btn btn-secondary">
                                <i class="fas fa-code"></i> <?= et('Copy HTML Code') ?>
                            </button>
                        </div>
                        
                    </div>

                    <div class="preview-column">
                        <div class="live-preview-box">
                            <div style="width:100%">
                                <div class="preview-header"><i class="fas fa-eye"></i> <?= et('Live Preview') ?></div>
                                <div class="preview-paper">
                                    <div id="live-render-area"></div>
                                </div>
                                <div style="text-align:center; margin-top:10px; font-size:0.8rem; color:var(--text-faint);">
                                    <?= et('Updates automatically as you type') ?>
                                </div>
                            </div>
                        </div>
                    </div>

                </div>
            </form>
        </section>

        <section class="card">
            <div class="card-header">
                <h3><?= et('My Signatures ({count})', ['count' => $totalSignatures]) ?></h3>
                <div style="display:flex; gap:0.5rem">
                <?php if ($totalSignatures > 0): ?>
                    <a href="download_all.php" class="btn btn-sm btn-success"><i class="fas fa-file-archive"></i> ZIP</a>
                    <?php if (empty($search)): ?>
                    <button type="button" data-post="generator.php" data-params='{"action":"delete_all"}' data-confirm="<?= et('Delete ALL signatures?') ?>" class="btn btn-sm btn-danger"><i class="fas fa-trash-alt"></i> <?= et('Delete All') ?></button>
                    <?php endif; ?>
                <?php endif; ?>
                </div>
            </div>

            <div class="search-bar-container">
                <form method="GET" action="generator.php" style="width:100%; display:flex; gap:10px;">
                    <input type="text" name="search" class="search-input" placeholder="<?= et('Search...') ?>" value="<?php echo e($search); ?>">
                    <button type="submit" class="btn btn-primary"><i class="fas fa-search"></i></button>
                    <?php if (!empty($search)): ?><a href="generator.php" class="btn btn-secondary"><?= et('Clear') ?></a><?php endif; ?>
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
                    <?php $encodedHtml = e(renderStoredSignature($sig)); ?>
                    <div class="signature-item" style="flex-wrap: wrap;">
                        <div style="display:flex; justify-content:space-between; width:100%; align-items:center;">
                            <div class="sig-details">
                                <h4><?php echo e($sig['name']); ?></h4>
                                <p style="font-size:0.85rem; color:var(--text-muted); margin-top:0.25rem"><?php echo e($sig['role']); ?> &bull; <?php echo e($sig['email']); ?></p>
                            </div>
                            
                            <div class="sig-actions" style="display:flex; gap:0.5rem;">
                                <?php if ($encodedHtml !== ''): ?>
                                    <textarea id="source-<?php echo (int)$sig['id']; ?>" class="visually-hidden"><?php echo $encodedHtml; ?></textarea>
                                    <button data-preview-id="<?php echo (int)$sig['id']; ?>" class="btn btn-sm btn-secondary" style="background:var(--bg-white); border:1px solid var(--border-strong);" title="<?= et('Preview') ?>">
                                        <i class="fas fa-eye"></i>
                                    </button>
                                <?php endif; ?>

                                <a href="download.php?id=<?php echo (int)$sig['id']; ?>" class="btn btn-sm btn-primary"><i class="fas fa-download"></i></a>
                                <button type="button" data-post="generate.php" data-params='{"action":"delete","id":"<?php echo (int)$sig['id']; ?>"}' data-confirm="<?= et('Delete?') ?>" class="btn btn-sm btn-danger"><i class="fas fa-trash"></i></button>
                            </div>
                        </div>
                    </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>

            <?php if ($totalPages > 1): ?>
            <div class="pagination">
                <?php 
                    $urlPattern = "generator.php?search=" . urlencode($search) . "&amp;page=";
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
                <h3 style="margin:0"><?= et('Signature Preview') ?></h3>
                <button class="close-modal-btn" id="modalCloseX" type="button">&times;</button>
            </div>
            <div class="modal-body">
                <iframe id="modalFrame" class="modal-iframe" sandbox=""></iframe>
            </div>
            <div class="modal-footer">
                <button class="btn btn-sm btn-secondary" id="modalCloseBtn" type="button"><?= et('Close') ?></button>
            </div>
        </div>
    </div>
    
    <script src="<?= assetUrl('js/post-action.js') ?>"></script>
    <script src="<?= assetUrl('js/safe-html.js') ?>"></script>
    <script>
        // Company-wide placeholder values ({{COMPANY}} etc., Admin -> System Configuration)
        const COMPANY_VALUES = <?= json_encode(companyFields(), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

        // ---------------------------------------------------------
        // 1. LIVE PREVIEW LOGIC
        // ---------------------------------------------------------
        // Inject Templates from PHP
        const rawTemplates = <?php echo json_encode($templatesJS, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); ?>;

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
            const template = rawTemplates[selectedFile];
            if (!template) {
                renderArea.innerHTML = '<p style="color:var(--border-strong); text-align:center; padding:20px;">Template not found</p>';
                return;
            }

            // Values are HTML-escaped by SafeHtml.fill (no XSS through the form fields);
            // the result is sanitised once more before it is inserted into the page.
            const phone = inputs.phone.value || '+1 234 567 890';
            const html = SafeHtml.fill(template, {
                NAME: inputs.name.value || <?= tj('Your Name') ?>,
                ROLE: inputs.role.value || <?= tj('Job Title') ?>,
                EMAIL: inputs.email.value || 'email@example.com',
                PHONE: phone,
                COMPANY: COMPANY_VALUES.company,
                WEBSITE: COMPANY_VALUES.website,
                ADDRESS: COMPANY_VALUES.address,
                DISCLAIMER: COMPANY_VALUES.disclaimer,
                PHONE_CLEAN: (inputs.phone.value || phone).replace(/[^0-9+]/g, '')
            });
            renderArea.innerHTML = SafeHtml.sanitize(html);
        }

        // Add Event Listeners for Live Updates
        Object.values(inputs).forEach(input => {
            if(input) {
                input.addEventListener('input', renderSignature);
                input.addEventListener('change', renderSignature);
            }
        });

        // ---------------------------------------------------------
        // 2. STORAGE LOGIC (Session Storage)
        // ---------------------------------------------------------
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
            // Only load if the form seems empty (prevent overwriting admin defaults if needed)
            if (roleInput && roleInput.value === '' && sessionStorage.getItem('sig_form_data')) {
                try {
                    const data = JSON.parse(sessionStorage.getItem('sig_form_data'));
                    if(data.name) inputs.name.value = data.name;
                    if(data.role) inputs.role.value = data.role;
                    if(data.email) inputs.email.value = data.email;
                    if(data.phone) inputs.phone.value = data.phone;
                    // Note: We intentionally skip loading the template here to prioritize the PHP-defined default
                } catch(e) {}
            }
            // Trigger initial render
            renderSignature();
        }

        document.addEventListener('DOMContentLoaded', loadFromStorage);
        document.getElementById('signatureForm').addEventListener('input', saveToStorage);

        // ---------------------------------------------------------
        // 3. MODAL LOGIC (Preview Saved)
        // ---------------------------------------------------------
        const modal = document.getElementById('previewModal');
        const modalFrame = document.getElementById('modalFrame');

        function openModal(id) {
            const source = document.getElementById('source-' + id);
            if (source) {
                // Inject CSS Reset into iframe to ensure preview looks correct
                const styleReset = `
                    <style>
                        body { margin: 0; padding: 20px; font-family: Arial, Helvetica, sans-serif; background-color: #ffffff; color: #000000; }
                        p { margin: 0; padding: 0; line-height: 1.4; } 
                        table { border-collapse: collapse; border-spacing: 0; }
                        td { padding: 0; vertical-align: top; }
                        a { text-decoration: none; color: inherit; }
                    </style>
                `;
                
                modalFrame.srcdoc = styleReset + SafeHtml.sanitize(source.value);
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

        // ---------------------------------------------------------
        // 4. HELPERS
        // ---------------------------------------------------------
        document.querySelectorAll('[data-preview-id]').forEach(function (btn) {
            btn.addEventListener('click', function () { openModal(btn.getAttribute('data-preview-id')); });
        });
        document.getElementById('modalCloseX').addEventListener('click', closeModal);
        document.getElementById('modalCloseBtn').addEventListener('click', closeModal);

        // ---------------------------------------------------------
        // 5. COPY HTML SOURCE CODE FUNCTIONALITY
        // ---------------------------------------------------------
        const btnCopy = document.getElementById('btn-copy');
        
        if (btnCopy) {
            btnCopy.addEventListener('click', function() {
                const node = document.getElementById('live-render-area');
                
                // Security Check: Ensure element exists
                if (!node) return;

                // Grab the raw HTML string (inner code)
                const htmlCode = node.innerHTML.trim();

                // Robust fallback method for copying text (works on HTTP and HTTPS)
                try {
                    // Create a temporary textarea element
                    const tempTextArea = document.createElement("textarea");
                    tempTextArea.value = htmlCode;
                    
                    // Make it invisible but part of the DOM
                    tempTextArea.style.position = "fixed";
                    tempTextArea.style.left = "-9999px";
                    tempTextArea.style.top = "0";
                    document.body.appendChild(tempTextArea);
                    
                    // Select and copy
                    tempTextArea.focus();
                    tempTextArea.select();
                    const successful = document.execCommand('copy');
                    
                    // Cleanup
                    document.body.removeChild(tempTextArea);

                    // User Feedback
                    if (successful) {
                        const originalText = btnCopy.innerHTML;
                        btnCopy.innerHTML = '<i class="fas fa-check"></i> ' + <?= tj('HTML Copied!') ?>;
                        setTimeout(() => btnCopy.innerHTML = originalText, 2000);
                    } else {
                        SubSigAlert.show('error', <?= tj('Could not copy HTML code. Please copy manually.') ?>);
                    }

                } catch (err) {
                    console.error('Copy failed:', err);
                    SubSigAlert.show('error', <?= tj('Error copying code.') ?>);
                }
            });
        }
    </script>
</body>
</html>
