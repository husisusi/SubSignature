<?php
// all_signatures.php

require_once 'includes/config.php';
requireLogin();

// ---------------------------------------------------------
// 1. HELPER: RENDER ITEM
// ---------------------------------------------------------
function renderSignatureItem($sig, $target_user_id, $search, $show_owner_name = false) {
    // Final, sanitised HTML of the signature for the preview textarea.
    $encodedHtml = e(renderStoredSignature($sig));
    $deleteUrl = 'all_signatures.php?user_id=' . rawurlencode((string)$target_user_id) . '&search=' . rawurlencode($search);
    ?>
    <div class="signature-item" style="flex-wrap: nowrap; gap: 15px;">
        <div style="display:flex; align-items:center; padding-left:5px;">
            <input type="checkbox" class="sig-checkbox" value="<?php echo (int)$sig['id']; ?>" onchange="updateBulkButtons()">
        </div>

        <div style="flex-grow: 1;">
            <div style="display:flex; justify-content:space-between; width:100%; align-items:center; flex-wrap:wrap;">
                <div class="sig-details">
                    <div style="display:flex; align-items:center; gap:8px;">
                        <h4><?php echo e($sig['name']); ?></h4>
                        <?php if ($show_owner_name && !empty($sig['username'])): ?>
                        <span style="background:var(--info-bg); color:var(--info-text); font-size:0.7rem; padding:2px 6px; border-radius:4px; border:1px solid var(--info-border);">
                            <i class="fas fa-user"></i> <?php echo e($sig['username']); ?>
                        </span>
                        <?php endif; ?>
                    </div>
                    <p><?php echo e($sig['role']); ?> &bull; <?php echo e($sig['email']); ?></p>
                    <p style="font-size:0.75rem; color:var(--text-faint); margin-top:0.25rem">
                        <i class="far fa-clock"></i> <?php echo e(date('M d, Y', strtotime($sig['created_at']) ?: time())); ?>
                        &bull; <span style="background:var(--bg-subtle); padding:2px 6px; border-radius:4px; font-family:monospace;"><?php echo e($sig['template']); ?></span>
                    </p>
                </div>

                <div class="sig-actions" style="display:flex; gap:0.5rem; align-items:center;">
                    <?php if ($encodedHtml !== ''): ?>
                    <textarea id="source-<?php echo (int)$sig['id']; ?>" class="visually-hidden"><?php echo $encodedHtml; ?></textarea>
                    <button type="button" onclick="openModal(<?php echo (int)$sig['id']; ?>)" class="btn btn-sm btn-secondary" style="background:var(--bg-white); border:1px solid var(--border-strong);" title="<?= et('Preview') ?>"><i class="fas fa-eye"></i></button>
                    <?php endif; ?>
                    <a href="download.php?id=<?php echo (int)$sig['id']; ?>" class="btn btn-sm btn-primary" title="<?= et('Download') ?>"><i class="fas fa-download"></i></a>
                    <button type="button" data-post="<?php echo e($deleteUrl); ?>" data-params='{"action":"delete_one","id":"<?php echo (int)$sig['id']; ?>"}'
                       data-confirm="<?= et('Delete?') ?>" class="btn btn-sm btn-danger" title="<?= et('Delete') ?>"><i class="fas fa-trash"></i></button>
                </div>
            </div>
        </div>
    </div>
    <?php
}

// ---------------------------------------------------------
// 2. LOGIC & DATA FETCHING
// ---------------------------------------------------------
$current_user_id = (int)$_SESSION['user_id'];
$is_admin = isAdmin(); 
$message = '';

// User Select Logic
$target_user_id = $current_user_id;
$users_list = [];
if ($is_admin) {
    if (isset($_GET['user_id'])) {
        if ($_GET['user_id'] === 'all') $target_user_id = 'all';
        elseif (is_numeric($_GET['user_id'])) $target_user_id = (int)$_GET['user_id'];
    }
    if (!isset($_GET['ajax'])) {
        $resUsers = $db->query("SELECT id, username, full_name FROM users ORDER BY username ASC");
        while ($u = $resUsers->fetchArray(SQLITE3_ASSOC)) $users_list[] = $u;
    }
} else {
    $target_user_id = $current_user_id;
}

// Search & Query
$search = cleanText($_GET['search'] ?? '', 100);
$page = max(1, min(100000, (int)($_GET['page'] ?? 1)));
$limit = 10;
$offset = ($page - 1) * $limit;

$params = [];
$whereClauses = [];
if ($target_user_id !== 'all') { $whereClauses[] = "s.user_id = :uid"; $params[':uid'] = $target_user_id; }
if (!empty($search)) { $whereClauses[] = "(s.name LIKE :search ESCAPE '\\' OR s.email LIKE :search ESCAPE '\\' OR s.role LIKE :search ESCAPE '\\')"; $params[':search'] = '%' . addcslashes($search, '%_\\') . '%'; }
$whereSQL = !empty($whereClauses) ? "WHERE " . implode(' AND ', $whereClauses) : "";

// Count
$stmtCount = $db->prepare("SELECT COUNT(*) as total FROM user_signatures s $whereSQL");
foreach ($params as $k => $v) $stmtCount->bindValue($k, $v, is_int($v) ? SQLITE3_INTEGER : SQLITE3_TEXT);
$totalSignatures = $stmtCount->execute()->fetchArray(SQLITE3_ASSOC)['total'];

// Fetch
$stmt = $db->prepare("SELECT s.*, u.username FROM user_signatures s LEFT JOIN users u ON s.user_id = u.id $whereSQL ORDER BY s.created_at DESC, s.id DESC LIMIT :limit OFFSET :offset");
foreach ($params as $k => $v) $stmt->bindValue($k, $v, is_int($v) ? SQLITE3_INTEGER : SQLITE3_TEXT);
$stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
$stmt->bindValue(':offset', $offset, SQLITE3_INTEGER);
$result = $stmt->execute();
$signatures = [];
while ($row = $result->fetchArray(SQLITE3_ASSOC)) $signatures[] = $row;

// AJAX Handler
if (isset($_GET['ajax'])) {
    if (empty($signatures)) exit;
    foreach ($signatures as $sig) renderSignatureItem($sig, $target_user_id, $search, ($target_user_id === 'all'));
    exit;
}

// ---------------------------------------------------------
// 3. ACTION HANDLERS
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    requireCsrf();
    $action = $_POST['action'] ?? '';
    $redirect = 'all_signatures.php?user_id=' . rawurlencode((string)$target_user_id) . '&search=' . rawurlencode($search);

    // DELETE SINGLE (admins may delete any signature of the selected scope, users only their own)
    if ($action === 'delete_one') {
        $sql = 'DELETE FROM user_signatures WHERE id = :id';
        if ($target_user_id !== 'all') $sql .= ' AND user_id = :uid';
        $stmtDel = $db->prepare($sql);
        $stmtDel->bindValue(':id', (int)($_POST['id'] ?? 0), SQLITE3_INTEGER);
        if ($target_user_id !== 'all') $stmtDel->bindValue(':uid', $target_user_id, SQLITE3_INTEGER);
        $stmtDel->execute();
        setFlash('success', t('Signature deleted.'));
        header('Location: ' . $redirect);
        exit;
    }

    // DELETE ALL of the selected scope
    if ($action === 'delete_all') {
        if ($target_user_id === 'all') {
            // $target_user_id can only be 'all' for administrators (see above).
            $db->exec('DELETE FROM user_signatures');
            logSecurityEventToDB($db, 'SIGNATURES_DELETED_ALL', $current_user_id, 'Scope: all users');
        } else {
            $s = $db->prepare('DELETE FROM user_signatures WHERE user_id = ?');
            $s->bindValue(1, $target_user_id, SQLITE3_INTEGER);
            $s->execute();
        }
        setFlash('success', t('All signatures deleted!'));
        header('Location: ' . $redirect);
        exit;
    }

    // DELETE SELECTED (bulk, capped)
    if ($action === 'delete_selected') {
        $rawIds = $_POST['ids'] ?? [];
        $ids = is_array($rawIds) ? $rawIds : explode(',', (string)$rawIds);
        $ids = array_slice(array_unique(array_filter(array_map('intval', $ids), function ($v) { return $v > 0; })), 0, 1000);
        $count = 0;
        $db->exec('BEGIN');
        foreach ($ids as $id) {
            $sql = 'DELETE FROM user_signatures WHERE id = :id';
            if (!$is_admin) $sql .= ' AND user_id = :uid';
            $st = $db->prepare($sql);
            $st->bindValue(':id', $id, SQLITE3_INTEGER);
            if (!$is_admin) $st->bindValue(':uid', $current_user_id, SQLITE3_INTEGER);
            $st->execute();
            $count += $db->changes();
        }
        $db->exec('COMMIT');
        setFlash('success', t('{count} signatures deleted.', ['count' => $count]));
        header('Location: ' . $redirect);
        exit;
    }
}

$message = popFlash('success');
?>
<!DOCTYPE html>
<html lang="<?= e(currentLang()) ?>" dir="<?= e(langDir()) ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= et('All Signatures') ?> - SubSignature</title>
<?= i18nHead() ?>
<script src="<?= assetUrl('js/theme.js') ?>"></script>
<link rel="stylesheet" href="<?= assetUrl('css/theme.css') ?>">
<link rel="stylesheet" href="<?= assetUrl('css/style.css') ?>">
<link rel="stylesheet" href="<?= assetUrl('css/all.min.css') ?>">
<?php echo csrfMeta(); ?>
<style>
    .visually-hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0, 0, 0, 0); opacity: 0; }
    .alert { padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; display: flex; gap: 0.75rem; align-items: center; }
    .alert-success { background: var(--success-bg); color: var(--success-text); border: 1px solid var(--success-border); }
    .empty-state { text-align: center; padding: 4rem 1rem; color: var(--text-faint); }

    /* MODAL STYLES - UPDATED FOR LARGER PREVIEW */
    .modal-overlay { 
        position: fixed; top: 0; left: 0; width: 100%; height: 100%; 
        background: rgba(0,0,0,0.5); z-index: 9999; 
        display: none; justify-content: center; align-items: center; 
        backdrop-filter: blur(3px); 
    }
    .modal-box { 
        background: var(--bg-white); 
        width: 95%; /* Wider on small screens */
        max-width: 1100px; /* Max width increased to 1100px */
        border-radius: 12px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.1); 
        overflow: hidden; 
        display: flex; flex-direction: column;
        animation: popIn 0.2s ease-out; 
    }
    @keyframes popIn { from {transform: scale(0.95); opacity: 0;} to {transform: scale(1); opacity: 1;} }

    .modal-header { padding: 1rem 1.5rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: var(--bg-subtle); }
    
    .modal-body { 
        padding: 0; 
        height: 600px; /* Increased height to 600px */
        background: var(--bg-white); 
    }
    
    .modal-iframe { width: 100%; height: 100%; border: none; display: block; }
    .modal-footer { padding: 1rem; text-align: right; border-top: 1px solid var(--border); background: var(--bg-subtle); }

    .close-modal-btn { 
        background: none; border: none; font-size: 1.5rem; 
        cursor: pointer; color: var(--text-muted); padding: 0 10px; line-height: 1;
    }
    .close-modal-btn:hover { color: var(--text-main); }

    .filter-bar { background: var(--bg-white); padding: 1rem; border-radius: 8px; border: 1px solid var(--border); margin-bottom: 1.5rem; display: flex; gap: 1rem; flex-wrap: wrap; align-items: center; }

    /* MODERN DROPDOWN */
    .user-select {
        appearance: none; 
        -webkit-appearance: none;
        -moz-appearance: none;
        background-color: var(--bg-white);
        color: var(--text-main);
        padding: 0.6rem 2.5rem 0.6rem 1rem;
        border: 1px solid var(--border-strong);
        border-radius: 6px;
        min-width: 200px;
        font-weight: 500;
        font-size: 0.95rem;
        cursor: pointer;
        outline: none;
        transition: all 0.2s ease-in-out;
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='%23475569'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M19 9l-7 7-7-7'%3E%3C/path%3E%3C/svg%3E");
        background-repeat: no-repeat;
        background-position: right 1rem center;
        background-size: 1rem;
    }
    .user-select:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1); }
    .user-select:hover { border-color: var(--text-faint); }

    .search-input { flex: 1; padding: 0.6rem; border: 1px solid var(--border); border-radius: 6px; }
    .count-badge { background-color: var(--bg-hover); color: var(--primary); font-size: 0.9rem; padding: 0.3rem 0.8rem; border-radius: 999px; font-weight: 700; margin-left: 10px; border: 1px solid var(--info-border); }

    .infinite-spinner { text-align: center; padding: 2rem; display: none; color: var(--text-muted); }
    .end-of-results { text-align: center; padding: 2rem; display: none; color: var(--text-faint); font-size: 0.9rem; font-style: italic; }
    .sig-checkbox { width: 18px; height: 18px; cursor: pointer; }

    /* HEADER ACTION BUTTONS */
    .header-actions { display: flex; gap: 8px; align-items: center; }
    .btn-header { display: flex; align-items: center; gap: 6px; padding: 0.5rem 0.8rem; font-size: 0.85rem; }
    .btn-disabled { opacity: 0.5; pointer-events: none; cursor: not-allowed; }
</style>
</head>
<body>

<aside class="sidebar">
    <?php if (file_exists('includes/navbar.php')) include 'includes/navbar.php'; ?>
    <div class="sidebar-footer">
        <?= langSwitcher() ?>
        <div class="user-profile">
            <div class="avatar"><?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?></div>
            <div class="user-info"><div><?php echo e($_SESSION['username']); ?></div><span><?php echo $is_admin ? 'Administrator' : 'User'; ?></span></div>
        </div>
        <a href="logout.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> <span><?= et('Sign Out') ?></span></a>
    </div>
</aside>

<main class="main-content">
    <header class="page-header">
        <h2><?= et('Signature Management') ?></h2>
        <p><?= et('View, search and manage existing signatures.') ?></p>
    </header>

    <?php if ($message): ?>
    <div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo e($message); ?></div>
    <?php endif; ?>

    <section class="card">
        <div class="card-header">
            <div style="display: flex; align-items: center;">
                <h3 style="margin:0;"><i class="fas fa-list"></i> <?= et('Signatures') ?></h3>
                <span class="count-badge"><?php echo $totalSignatures; ?></span>
            </div>

            <div class="header-actions">
                <?php if (!empty($signatures)): ?>
                
                <?php if ($is_admin): ?>
                <button id="btnSendSelected" onclick="sendBulkEmail()" class="btn btn-sm btn-primary btn-header btn-disabled">
                    <i class="fas fa-paper-plane"></i> <?= et('Send Selected') ?>
                </button>
                <?php endif; ?>
                
                <button id="btnDeleteSelected" onclick="deleteSelectedItems()" class="btn btn-sm btn-danger btn-header btn-disabled">
                    <i class="fas fa-trash"></i> <?= et('Delete Selected') ?>
                </button>

                <div style="width:1px; height:20px; background:var(--border-strong); margin:0 5px;"></div>

                <button onclick="confirmDeleteAll()" class="btn btn-sm btn-danger btn-header">
                    <i class="fas fa-trash-alt"></i> <?= et('Delete All') ?>
                </button>
                <?php endif; ?>
            </div>
        </div>

        <div class="filter-bar">
            <form method="GET" action="all_signatures.php" style="display:flex; gap:10px; width:100%; flex-wrap:wrap;">
                <?php if ($is_admin): ?>
                <div style="flex-shrink:0;">
                    <select name="user_id" class="user-select" onchange="this.form.submit()">
                        <option value="all" <?php echo ($target_user_id === 'all') ? 'selected' : ''; ?>><?= et('All Users') ?></option>
                        <?php foreach ($users_list as $u): ?>
                        <option value="<?php echo (int)$u['id']; ?>" <?php echo ($u['id'] == $target_user_id) ? 'selected' : ''; ?>>
                            <?php echo e($u['username']); ?>
                        </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <?php endif; ?>
                <input type="text" name="search" class="search-input" placeholder="<?= et('Search...') ?>" value="<?php echo e($search); ?>">
                <button type="submit" class="btn btn-primary"><?= et('Search') ?></button>
                <?php if (!empty($search)): ?><a href="all_signatures.php?user_id=<?php echo e((string)$target_user_id); ?>" class="btn btn-secondary"><?= et('Clear') ?></a><?php endif; ?>
            </form>
        </div>

        <div style="padding: 10px 15px; background: var(--bg-subtle); border-bottom: 1px solid var(--border); display:flex; align-items:center; gap: 10px;">
            <input type="checkbox" id="selectAll" class="sig-checkbox" onchange="toggleSelectAll(this)">
            <label for="selectAll" style="font-weight:600; font-size:0.9rem; cursor:pointer; color:var(--text-muted);"><?= et('Select All visible') ?></label>
        </div>

        <div class="signature-list" id="signatureListContainer">
            <?php if (empty($signatures)): ?>
            <div class="empty-state"><i class="fas fa-folder-open empty-icon"></i><p><?= et('No signatures found.') ?></p></div>
            <?php else: ?>
            <?php foreach ($signatures as $sig) renderSignatureItem($sig, $target_user_id, $search, ($target_user_id === 'all')); ?>
            <?php endif; ?>
        </div>

        <div class="infinite-spinner" id="infiniteLoader"><i class="fas fa-spinner fa-spin fa-2x"></i><div style="margin-top:10px"><?= et('Loading more...') ?></div></div>
        <div id="sentinel"></div>
        <div class="end-of-results" id="endOfResults"><?= et('All signatures loaded.') ?></div>
    </section>
</main>

<div id="previewModal" class="modal-overlay">
    <div class="modal-box">
        <div class="modal-header"><h3 style="margin:0"><?= et('Preview') ?></h3><button class="close-modal-btn" onclick="closeModal()">&times;</button></div>
        <div class="modal-body"><iframe id="modalFrame" class="modal-iframe" sandbox=""></iframe></div>
        <div class="modal-footer"><button class="btn btn-sm btn-secondary" onclick="closeModal()"><?= et('Close') ?></button></div>
    </div>
</div>

<div id="progressModal" class="modal-overlay" style="z-index: 10000;">
    <div class="modal-box" style="max-width: 500px; height: auto; min-height: 250px;">
        <div class="modal-header">
            <h3 style="margin:0"><i class="fas fa-paper-plane"></i> <?= et('Sending Emails...') ?></h3>
        </div>
        <div class="modal-body" style="padding: 20px; display: flex; flex-direction: column; gap: 15px; height: auto;">
            <div style="width: 100%; background-color: var(--border); border-radius: 99px; overflow: hidden; height: 20px;">
                <div id="progressBarFill" style="width: 0%; height: 100%; background-color: var(--primary); transition: width 0.3s ease;"></div>
            </div>
            <div style="display: flex; justify-content: space-between; font-size: 0.9rem; color: var(--text-muted);">
                <span id="progressText"><?= et('Initializing...') ?></span>
                <span id="progressPercent">0%</span>
            </div>

            <div id="progressLog" style="flex-grow: 1; background: var(--bg-white); color: var(--text-main); font-family: monospace; font-size: 0.85rem; padding: 10px; border-radius: 6px; overflow-y: auto; max-height: 150px; border: 1px solid var(--border-strong); box-shadow: inset 0 2px 4px rgba(0,0,0,0.05);">
                <div>> <?= et('Ready to start...') ?></div>
            </div>
        </div>
        <div class="modal-footer" style="display:flex; justify-content:space-between;">
             <button id="btnCancelProgress" class="btn btn-sm btn-danger" onclick="cancelBulkEmail()">
                <i class="fas fa-stop-circle"></i> <?= et('Cancel') ?>
            </button>
            
            <button id="btnCloseProgress" class="btn btn-sm btn-secondary btn-disabled" onclick="closeProgressModal()"><?= et('Close') ?></button>
        </div>
    </div>
</div>

<form id="deleteAllForm" method="POST" action="all_signatures.php?user_id=<?php echo e(rawurlencode((string)$target_user_id)); ?>&amp;search=<?php echo e(rawurlencode($search)); ?>" style="display:none;">
    <input type="hidden" name="action" value="delete_all">
    <?php echo csrfField(); ?>
</form>

<form id="deleteSelectedForm" method="POST" action="all_signatures.php?user_id=<?php echo e(rawurlencode((string)$target_user_id)); ?>&amp;search=<?php echo e(rawurlencode($search)); ?>" style="display:none;">
    <input type="hidden" name="action" value="delete_selected">
    <?php echo csrfField(); ?>
</form>

<script src="<?= assetUrl('js/post-action.js') ?>"></script>
<script src="<?= assetUrl('js/safe-html.js') ?>"></script>
<script>
const CSRF_TOKEN = <?php echo json_encode(generateCSRFToken()); ?>;
let abortController = null; // Global variable to handle cancellation

// --- BUTTON ENABLE/DISABLE LOGIC ---
function updateBulkButtons() {
    const checkboxes = document.querySelectorAll('.sig-checkbox:not(#selectAll)');
    const selectedCount = Array.from(checkboxes).filter(cb => cb.checked).length;

    const btnSend = document.getElementById('btnSendSelected');
    const btnDel = document.getElementById('btnDeleteSelected');

    if (btnSend) {
        if (selectedCount > 0) {
            btnSend.classList.remove('btn-disabled');
            btnSend.innerHTML = '<i class="fas fa-paper-plane"></i> ' + <?= tj('Send Selected ({count})') ?>.replace('{count}', selectedCount);
        } else {
            btnSend.classList.add('btn-disabled');
            btnSend.innerHTML = '<i class="fas fa-paper-plane"></i> ' + <?= tj('Send Selected') ?>;
        }
    }

    if (btnDel) {
        if (selectedCount > 0) {
            btnDel.classList.remove('btn-disabled');
            btnDel.innerHTML = '<i class="fas fa-trash"></i> ' + <?= tj('Delete Selected ({count})') ?>.replace('{count}', selectedCount);
        } else {
            btnDel.classList.add('btn-disabled');
            btnDel.innerHTML = '<i class="fas fa-trash"></i> ' + <?= tj('Delete Selected') ?>;
        }
    }

    const selectAllCb = document.getElementById('selectAll');
    if (selectedCount === 0) selectAllCb.checked = false;
}

function toggleSelectAll(source) {
    document.querySelectorAll('.sig-checkbox:not(#selectAll)').forEach(cb => cb.checked = source.checked);
    updateBulkButtons();
}

// --- DELETE SELECTED ---
function deleteSelectedItems() {
    const checkboxes = document.querySelectorAll('.sig-checkbox:not(#selectAll):checked');
    const ids = Array.from(checkboxes).map(cb => cb.value);
    if (ids.length === 0) return;
    if (!confirm(<?= tj('Delete {count} signatures?') ?>.replace('{count}', ids.length))) return;

    const form = document.getElementById('deleteSelectedForm');
    while (form.firstChild) {
        if(form.firstChild.name === 'ids[]') form.removeChild(form.firstChild);
        else break;
    }

    ids.forEach(id => {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'ids[]';
        input.value = id;
        form.appendChild(input);
    });
    form.submit();
}

// --- SEND MAIL WITH LIVE STREAM & ABORT ---
async function sendBulkEmail() {
    const checkboxes = document.querySelectorAll('.sig-checkbox:not(#selectAll):checked');
    const ids = Array.from(checkboxes).map(cb => cb.value);
    
    if (ids.length === 0) return;
    
    // SECURITY: Ask only ONCE at the beginning.
    // We do NOT ask again when cancelling.
    if (!confirm(<?= tj('Start sending emails to {count} users?') ?>.replace('{count}', ids.length))) return;

    // 1. UI Reset
    const pModal = document.getElementById('progressModal');
    const pBar = document.getElementById('progressBarFill');
    const pText = document.getElementById('progressText');
    const pPercent = document.getElementById('progressPercent');
    const pLog = document.getElementById('progressLog');
    const btnClose = document.getElementById('btnCloseProgress');
    const btnCancel = document.getElementById('btnCancelProgress');

    pModal.style.display = 'flex';
    pBar.style.width = '0%';
    pBar.style.backgroundColor = 'var(--primary)'; // Blue (Reset)
    pText.innerText = <?= tj('{current} of {total}') ?>.replace('{current}', 0).replace('{total}', ids.length);
    pPercent.innerText = '0%';
    pLog.innerHTML = '<div>> ' + <?= tj('Connecting to server...') ?> + '</div>';
    
    // Button Status
    btnClose.classList.add('btn-disabled'); 
    btnCancel.classList.remove('btn-disabled');
    
    // "Panic Button" Styling
    btnCancel.innerHTML = '<i class="fas fa-stop-circle"></i> ' + <?= tj('STOP IMMEDIATELY') ?>;
    btnCancel.disabled = false;
    btnCancel.style.backgroundColor = '#dc2626';
    btnCancel.style.color = '#000000';
    btnCancel.style.fontWeight = 'bold';

    // 2. Prepare Data & Abort Controller
    abortController = new AbortController(); 
    const signal = abortController.signal;

    const formData = new FormData();
    formData.append('csrf_token', CSRF_TOKEN);
    ids.forEach(id => formData.append('ids[]', id));

    try {
        // 3. Start Fetch with 'signal' (Allows aborting)
        const response = await fetch('send_signature.php', {
            method: 'POST',
            body: formData,
            signal: signal 
        });

        if (!response.ok) throw new Error(<?= tj('Network error') ?>);

        const reader = response.body.getReader();
        const decoder = new TextDecoder("utf-8");
        let buffer = '';

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n\n');
            buffer = lines.pop(); // Keep last incomplete chunk

            for (const line of lines) {
                if (line.startsWith('data: ')) {
                    const jsonStr = line.replace('data: ', '').trim();
                    try {
                        const data = JSON.parse(jsonStr);
                        
                        if (data.status === 'finished') {
                            logMessage(<?= tj('DONE: {summary}') ?>.replace('{summary}', data.summary), 'var(--success-text)'); // Dark Green
                            finishProcess(true);
                        } else if (data.status === 'fatal_error') {
                            logMessage(<?= tj('ERROR: {message}') ?>.replace('{message}', data.message), '#dc2626'); // Red
                            finishProcess(false);
                        } else {
                            // Standard Log Entry
                            const color = (data.status === 'error') ? 'var(--danger-text)' : 'var(--text-main)';
                            logMessage(data.message, color);

                            if (data.progress) {
                                const pct = Math.round((data.progress.current / data.progress.total) * 100);
                                pBar.style.width = `${pct}%`;
                                pText.innerText = <?= tj('{current} of {total}') ?>.replace('{current}', data.progress.current).replace('{total}', data.progress.total);
                                pPercent.innerText = `${pct}%`;
                            }
                        }
                    } catch (e) { console.error(e); }
                }
            }
        }

    } catch (e) {
        if (e.name === 'AbortError') {
            // EXECUTES ON CANCELLATION
            logMessage('🛑 ' + <?= tj('ABORTED BY USER! Stopping immediately...') ?>, '#dc2626');
            pBar.style.backgroundColor = '#ef4444'; // Bar turns red
            logMessage(<?= tj('Connection closed. Server will stop processing.') ?>, 'var(--text-main)');
        } else {
            logMessage(<?= tj('System Error: {message}') ?>.replace('{message}', e.message), '#dc2626');
        }
        finishProcess(false);
    }
}

// THE NEW "PANIC BUTTON" FUNCTION
function cancelBulkEmail() {
    if (abortController) {
        // NO CONFIRMATION DIALOG! ABORT INSTANTLY.
        abortController.abort(); 
        
        const btnCancel = document.getElementById('btnCancelProgress');
        btnCancel.innerHTML = <?= tj('STOPPED') ?>;
        btnCancel.classList.add('btn-disabled');
    }
}

function logMessage(msg, color) {
    const pLog = document.getElementById('progressLog');
    const div = document.createElement('div');
    div.textContent = '> ' + msg; // textContent: server messages may contain user data
    div.style.color = color;
    div.style.borderBottom = "1px solid var(--border)"; 
    div.style.padding = "2px 0";
    pLog.appendChild(div);
    pLog.scrollTop = pLog.scrollHeight;
}

function finishProcess(success) {
    const btnClose = document.getElementById('btnCloseProgress');
    const btnCancel = document.getElementById('btnCancelProgress');
    
    btnClose.classList.remove('btn-disabled');
    btnClose.innerText = <?= tj('Done (Close)') ?>;
    
    btnCancel.classList.add('btn-disabled');
    btnCancel.disabled = true;

    btnClose.onclick = function() {
        closeProgressModal();
        window.location.reload(); 
    };
}

// --- MODALS (PREVIEW & PROGRESS) ---
const modal = document.getElementById('previewModal');
const modalFrame = document.getElementById('modalFrame');

function openModal(id) {
    const source = document.getElementById('source-' + id);
    if(source) {
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
function closeModal() { modal.style.display = 'none'; modalFrame.srcdoc=''; }
function closeProgressModal() { document.getElementById('progressModal').style.display = 'none'; }
window.onclick = e => { if(e.target == modal) closeModal(); }

// --- DELETE ALL ---
function confirmDeleteAll() {
    if(confirm(<?= tj('Delete ALL signatures displayed in this list?') ?>)) document.getElementById('deleteAllForm').submit();
}

// --- SCROLLING ---
document.addEventListener('DOMContentLoaded', function() {
    let page = 1; let loading = false; let more = true;
    const uid = <?php echo json_encode((string)$target_user_id); ?>;
    const search = <?php echo json_encode(rawurlencode($search)); ?>;
    const loader = document.getElementById('infiniteLoader');
    const cont = document.getElementById('signatureListContainer');
    const sentinel = document.getElementById('sentinel');

    if (cont.querySelector('.empty-state')) { more = false; sentinel.style.display = 'none'; }

    const loadMore = () => {
        if (loading || !more) return;
        loading = true; loader.style.display = 'block'; page++;
        fetch(`all_signatures.php?ajax=1&page=${page}&user_id=${encodeURIComponent(uid)}&search=${search}`, {credentials: 'same-origin'})
        .then(r => r.text())
        .then(html => {
            loader.style.display = 'none';
            if (html.trim() === '') { more = false; sentinel.style.display = 'none'; document.getElementById('endOfResults').style.display = 'block'; }
            else { cont.insertAdjacentHTML('beforeend', html); loading = false; }
        })
        .catch(() => { loading = false; loader.style.display = 'none'; });
    };
    const obs = new IntersectionObserver((e) => { if (e[0].isIntersecting && more && !loading) loadMore(); }, { rootMargin: '100px' });
    if (more) obs.observe(sentinel);
});
</script>
</body>
</html>
