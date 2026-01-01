<?php
// all_signatures.php

require_once 'includes/config.php';
requireLogin();

// ---------------------------------------------------------
// 1. HELPER: RENDER ITEM
// ---------------------------------------------------------
function renderSignatureItem($sig, $target_user_id, $search, $show_owner_name = false) {
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

    // CSRF Token für Links
    $csrf = $_SESSION['csrf_token'];
    ?>
    <div class="signature-item" style="flex-wrap: nowrap; gap: 15px;">
        <div style="display:flex; align-items:center; padding-left:5px;">
            <input type="checkbox" class="sig-checkbox" value="<?php echo $sig['id']; ?>" onchange="updateBulkButtons()">
        </div>

        <div style="flex-grow: 1;">
            <div style="display:flex; justify-content:space-between; width:100%; align-items:center; flex-wrap:wrap;">
                <div class="sig-details">
                    <div style="display:flex; align-items:center; gap:8px;">
                        <h4><?php echo htmlspecialchars($sig['name'], ENT_QUOTES, 'UTF-8'); ?></h4>
                        <?php if ($show_owner_name && !empty($sig['username'])): ?>
                        <span style="background:#e0f2fe; color:#0369a1; font-size:0.7rem; padding:2px 6px; border-radius:4px; border:1px solid #bae6fd;">
                            <i class="fas fa-user"></i> <?php echo htmlspecialchars($sig['username'], ENT_QUOTES, 'UTF-8'); ?>
                        </span>
                        <?php endif; ?>
                    </div>
                    <p><?php echo htmlspecialchars($sig['role'], ENT_QUOTES, 'UTF-8'); ?> &bull; <?php echo htmlspecialchars($sig['email'], ENT_QUOTES, 'UTF-8'); ?></p>
                    <p style="font-size:0.75rem; color:#94a3b8; margin-top:0.25rem">
                        <i class="far fa-clock"></i> <?php echo date('M d, Y', strtotime($sig['created_at'])); ?>
                        &bull; <span style="background:#f1f5f9; padding:2px 6px; border-radius:4px; font-family:monospace;"><?php echo htmlspecialchars($sig['template'], ENT_QUOTES, 'UTF-8'); ?></span>
                    </p>
                </div>

                <div class="sig-actions" style="display:flex; gap:0.5rem; align-items:center;">
                    <?php if($encodedHtml): ?>
                    <textarea id="source-<?php echo $sig['id']; ?>" class="visually-hidden"><?php echo $encodedHtml; ?></textarea>
                    <button onclick="openModal(<?php echo $sig['id']; ?>)" class="btn btn-sm btn-secondary" style="background:white; border:1px solid #cbd5e1;" title="Preview"><i class="fas fa-eye"></i></button>
                    <?php endif; ?>
                    <a href="download.php?id=<?php echo $sig['id']; ?>" class="btn btn-sm btn-primary" title="Download"><i class="fas fa-download"></i></a>
                    <a href="all_signatures.php?delete=<?php echo $sig['id']; ?>&user_id=<?php echo $target_user_id; ?>&search=<?php echo urlencode($search); ?>&csrf_token=<?php echo $csrf; ?>"
                       class="btn btn-sm btn-danger" onclick="return confirm('Delete?')" title="Delete"><i class="fas fa-trash"></i></a>
                </div>
            </div>
        </div>
    </div>
    <?php
}

// ---------------------------------------------------------
// 2. LOGIC & DATA FETCHING
// ---------------------------------------------------------
if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
$current_user_id = $_SESSION['user_id'];
$is_admin = isAdmin(); // Wichtig für die Button-Anzeige später
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
$search = trim($_GET['search'] ?? '');
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
if ($page < 1) $page = 1;
$limit = 10;
$offset = ($page - 1) * $limit;

$params = [];
$whereClauses = [];
if ($target_user_id !== 'all') { $whereClauses[] = "s.user_id = :uid"; $params[':uid'] = $target_user_id; }
if (!empty($search)) { $whereClauses[] = "(s.name LIKE :search OR s.email LIKE :search OR s.role LIKE :search)"; $params[':search'] = '%' . $search . '%'; }
$whereSQL = !empty($whereClauses) ? "WHERE " . implode(' AND ', $whereClauses) : "";

// Count
$stmtCount = $db->prepare("SELECT COUNT(*) as total FROM user_signatures s $whereSQL");
foreach ($params as $k => $v) $stmtCount->bindValue($k, $v, is_int($v) ? SQLITE3_INTEGER : SQLITE3_TEXT);
$totalSignatures = $stmtCount->execute()->fetchArray(SQLITE3_ASSOC)['total'];

// Fetch
$stmt = $db->prepare("SELECT s.*, u.username FROM user_signatures s LEFT JOIN users u ON s.user_id = u.id $whereSQL ORDER BY s.created_at DESC LIMIT :limit OFFSET :offset");
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
if ($_SERVER['REQUEST_METHOD'] === 'POST' || isset($_GET['delete'])) {
    $token = $_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], $token)) die("Security Error: Invalid CSRF Token");

    // DELETE SINGLE
    if (isset($_GET['delete'])) {
        $del_id = (int)$_GET['delete'];
        $sql = "DELETE FROM user_signatures WHERE id = :id";
        if ($target_user_id !== 'all') $sql .= " AND user_id = :uid";
        $stmtDel = $db->prepare($sql);
        $stmtDel->bindValue(':id', $del_id, SQLITE3_INTEGER);
        if ($target_user_id !== 'all') $stmtDel->bindValue(':uid', $target_user_id, SQLITE3_INTEGER);
        $stmtDel->execute();
        header("Location: all_signatures.php?user_id=$target_user_id&search=" . urlencode($search) . "&success=deleted_one");
        exit;
    }

    // DELETE ALL
    if (isset($_POST['action']) && $_POST['action'] === 'delete_all') {
        if ($target_user_id === 'all') { if (!$is_admin) die("Unauthorized"); $db->exec("DELETE FROM user_signatures"); }
        else { $s=$db->prepare("DELETE FROM user_signatures WHERE user_id=?"); $s->bindValue(1, $target_user_id, SQLITE3_INTEGER); $s->execute(); }
        header("Location: all_signatures.php?user_id=$target_user_id&success=deleted_all");
        exit;
    }

    // DELETE SELECTED (BULK)
    if (isset($_POST['action']) && $_POST['action'] === 'delete_selected') {
        $ids = is_array($_POST['ids']) ? $_POST['ids'] : explode(',', $_POST['ids']);
        $count = 0;
        foreach($ids as $id) {
            $id = (int)$id; // Security: Force Integer
            if($id > 0) {
                $sql = "DELETE FROM user_signatures WHERE id = :id";
                if (!$is_admin) $sql .= " AND user_id = :uid";
                $stmt = $db->prepare($sql);
                $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
                if (!$is_admin) $stmt->bindValue(':uid', $current_user_id, SQLITE3_INTEGER);
                if($stmt->execute()) $count++;
            }
        }
        header("Location: all_signatures.php?user_id=$target_user_id&success=deleted_batch&count=$count");
        exit;
    }
}

if (isset($_GET['success'])) {
    if ($_GET['success'] == 'deleted_all') $message = "All signatures deleted!";
    if ($_GET['success'] == 'deleted_one') $message = "Signature deleted.";
    if ($_GET['success'] == 'deleted_batch') $message = (int)$_GET['count'] . " signatures deleted.";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>All Signatures - SubSignature</title>
<link rel="stylesheet" href="css/style.css">
<link rel="stylesheet" href="css/all.min.css">
<style>
    .visually-hidden { position: absolute; left: -9999px; opacity: 0; }
    .alert { padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; display: flex; gap: 0.75rem; align-items: center; }
    .alert-success { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
    .empty-state { text-align: center; padding: 4rem 1rem; color: #94a3b8; }

    /* MODAL STYLES */
    .modal-overlay { 
        position: fixed; top: 0; left: 0; width: 100%; height: 100%; 
        background: rgba(0,0,0,0.5); z-index: 9999; 
        display: none; justify-content: center; align-items: center; 
        backdrop-filter: blur(3px); 
    }
    .modal-box { 
        background: white; width: 90%; max-width: 700px; 
        border-radius: 12px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.1); 
        overflow: hidden; 
        display: flex; flex-direction: column;
        animation: popIn 0.2s ease-out; 
    }
    @keyframes popIn { from {transform: scale(0.95); opacity: 0;} to {transform: scale(1); opacity: 1;} }

    .modal-header { padding: 1rem 1.5rem; border-bottom: 1px solid #e2e8f0; display: flex; justify-content: space-between; align-items: center; background: #f8fafc; }
    .modal-body { padding: 0; height: 350px; background: white; }
    .modal-iframe { width: 100%; height: 100%; border: none; display: block; }
    .modal-footer { padding: 1rem; text-align: right; border-top: 1px solid #e2e8f0; background: #f8fafc; }

    /* FIX: Style für den "X" Button */
    .close-modal-btn { 
        background: none; 
        border: none; 
        font-size: 1.5rem; 
        cursor: pointer; 
        color: #64748b; 
        padding: 0 10px;
        line-height: 1;
    }
    .close-modal-btn:hover { color: #333; }

    .filter-bar { background: white; padding: 1rem; border-radius: 8px; border: 1px solid var(--border); margin-bottom: 1.5rem; display: flex; gap: 1rem; flex-wrap: wrap; align-items: center; }

    /* MODERNES DROPDOWN */
    .user-select {
        appearance: none; 
        -webkit-appearance: none;
        -moz-appearance: none;
        background-color: #ffffff;
        color: #334155;
        padding: 0.6rem 2.5rem 0.6rem 1rem;
        border: 1px solid #cbd5e1;
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
    .user-select:focus { border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1); }
    .user-select:hover { border-color: #94a3b8; }

    .search-input { flex: 1; padding: 0.6rem; border: 1px solid #e2e8f0; border-radius: 6px; }
    .count-badge { background-color: #eff6ff; color: #2563eb; font-size: 0.9rem; padding: 0.3rem 0.8rem; border-radius: 999px; font-weight: 700; margin-left: 10px; border: 1px solid #dbeafe; }

    .infinite-spinner { text-align: center; padding: 2rem; display: none; color: var(--text-muted); }
    .end-of-results { text-align: center; padding: 2rem; display: none; color: #94a3b8; font-size: 0.9rem; font-style: italic; }
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
        <div class="user-profile">
            <div class="avatar"><?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?></div>
            <div class="user-info"><div><?php echo htmlspecialchars($_SESSION['username']); ?></div><span>Administrator</span></div>
        </div>
        <a href="logout.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> <span>Sign Out</span></a>
    </div>
</aside>

<main class="main-content">
    <header class="page-header">
        <h2>Signature Management</h2>
        <p>View, search and manage existing signatures.</p>
    </header>

    <?php if ($message): ?>
    <div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($message); ?></div>
    <?php endif; ?>

    <section class="card">
        <div class="card-header">
            <div style="display: flex; align-items: center;">
                <h3 style="margin:0;"><i class="fas fa-list"></i> Signatures</h3>
                <span class="count-badge"><?php echo $totalSignatures; ?></span>
            </div>

            <div class="header-actions">
                <?php if (!empty($signatures)): ?>
                
                <?php if ($is_admin): ?>
                <button id="btnSendSelected" onclick="sendBulkEmail()" class="btn btn-sm btn-primary btn-header btn-disabled">
                    <i class="fas fa-paper-plane"></i> Send Selected
                </button>
                <?php endif; ?>
                
                <button id="btnDeleteSelected" onclick="deleteSelectedItems()" class="btn btn-sm btn-danger btn-header btn-disabled">
                    <i class="fas fa-trash"></i> Delete Selected
                </button>

                <div style="width:1px; height:20px; background:#cbd5e1; margin:0 5px;"></div>

                <button onclick="confirmDeleteAll()" class="btn btn-sm btn-danger btn-header">
                    <i class="fas fa-trash-alt"></i> Delete All
                </button>
                <?php endif; ?>
            </div>
        </div>

        <div class="filter-bar">
            <form method="GET" action="all_signatures.php" style="display:flex; gap:10px; width:100%; flex-wrap:wrap;">
                <?php if ($is_admin): ?>
                <div style="flex-shrink:0;">
                    <select name="user_id" class="user-select" onchange="this.form.submit()">
                        <option value="all" <?php echo ($target_user_id === 'all') ? 'selected' : ''; ?>>All Users</option>
                        <?php foreach ($users_list as $u): ?>
                        <option value="<?php echo $u['id']; ?>" <?php echo ($u['id'] == $target_user_id) ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($u['username']); ?>
                        </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <?php endif; ?>
                <input type="text" name="search" class="search-input" placeholder="Search..." value="<?php echo htmlspecialchars($search); ?>">
                <button type="submit" class="btn btn-primary">Search</button>
                <?php if (!empty($search)): ?><a href="all_signatures.php?user_id=<?php echo $target_user_id; ?>" class="btn btn-secondary">Clear</a><?php endif; ?>
            </form>
        </div>

        <div style="padding: 10px 15px; background: #f8fafc; border-bottom: 1px solid #e2e8f0; display:flex; align-items:center; gap: 10px;">
            <input type="checkbox" id="selectAll" class="sig-checkbox" onchange="toggleSelectAll(this)">
            <label for="selectAll" style="font-weight:600; font-size:0.9rem; cursor:pointer; color:#475569;">Select All visible</label>
        </div>

        <div class="signature-list" id="signatureListContainer">
            <?php if (empty($signatures)): ?>
            <div class="empty-state"><i class="fas fa-folder-open empty-icon"></i><p>No signatures found.</p></div>
            <?php else: ?>
            <?php foreach ($signatures as $sig) renderSignatureItem($sig, $target_user_id, $search, ($target_user_id === 'all')); ?>
            <?php endif; ?>
        </div>

        <div class="infinite-spinner" id="infiniteLoader"><i class="fas fa-spinner fa-spin fa-2x"></i><div style="margin-top:10px">Loading more...</div></div>
        <div id="sentinel"></div>
        <div class="end-of-results" id="endOfResults">All signatures loaded.</div>
    </section>
</main>

<div id="previewModal" class="modal-overlay">
    <div class="modal-box">
        <div class="modal-header"><h3 style="margin:0">Preview</h3><button class="close-modal-btn" onclick="closeModal()">&times;</button></div>
        <div class="modal-body"><iframe id="modalFrame" class="modal-iframe" sandbox="allow-same-origin"></iframe></div>
        <div class="modal-footer"><button class="btn btn-sm btn-secondary" onclick="closeModal()">Close</button></div>
    </div>
</div>

<form id="deleteAllForm" method="POST" action="all_signatures.php?user_id=<?php echo $target_user_id; ?>" style="display:none;">
    <input type="hidden" name="action" value="delete_all">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
</form>

<form id="deleteSelectedForm" method="POST" action="all_signatures.php?user_id=<?php echo $target_user_id; ?>" style="display:none;">
    <input type="hidden" name="action" value="delete_selected">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
</form>

<script>
const CSRF_TOKEN = "<?php echo $_SESSION['csrf_token']; ?>";

// --- BUTTON ENABLE/DISABLE LOGIC ---
function updateBulkButtons() {
    const checkboxes = document.querySelectorAll('.sig-checkbox:not(#selectAll)');
    const selectedCount = Array.from(checkboxes).filter(cb => cb.checked).length;

    const btnSend = document.getElementById('btnSendSelected');
    const btnDel = document.getElementById('btnDeleteSelected');

    // Button Send Logic (Admin only)
    if (btnSend) {
        if (selectedCount > 0) {
            btnSend.classList.remove('btn-disabled');
            btnSend.innerHTML = `<i class="fas fa-paper-plane"></i> Send Selected (${selectedCount})`;
        } else {
            btnSend.classList.add('btn-disabled');
            btnSend.innerHTML = `<i class="fas fa-paper-plane"></i> Send Selected`;
        }
    }

    // Button Delete Logic
    if (btnDel) {
        if (selectedCount > 0) {
            btnDel.classList.remove('btn-disabled');
            btnDel.innerHTML = `<i class="fas fa-trash"></i> Delete Selected (${selectedCount})`;
        } else {
            btnDel.classList.add('btn-disabled');
            btnDel.innerHTML = `<i class="fas fa-trash"></i> Delete Selected`;
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
    if (!confirm(`Delete ${ids.length} signatures?`)) return;

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

// --- SEND MAIL (ADMIN) ---
function sendBulkEmail() {
    const checkboxes = document.querySelectorAll('.sig-checkbox:not(#selectAll):checked');
    const ids = Array.from(checkboxes).map(cb => cb.value);
    if (ids.length === 0) return;
    if (!confirm(`Send email to ${ids.length} users?`)) return;

    const btn = document.getElementById('btnSendSelected');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';
    btn.classList.add('btn-disabled');

    const formData = new FormData();
    formData.append('csrf_token', CSRF_TOKEN);
    ids.forEach(id => formData.append('ids[]', id));

    fetch('send_signature.php', { method: 'POST', body: formData })
    .then(r => r.json())
    .then(data => {
        btn.innerHTML = originalText;
        btn.classList.remove('btn-disabled');
        if (data.status === 'success') {
            const s = data.data;
            alert(`Result:\n✅ Sent: ${s.success}\n❌ Failed: ${s.failed}\n${s.details.join('\n')}`);
            document.querySelectorAll('.sig-checkbox').forEach(cb => cb.checked = false);
            document.getElementById('selectAll').checked = false;
            updateBulkButtons();
        } else {
            alert('Error: ' + data.message);
        }
    })
    .catch(e => {
        btn.innerHTML = originalText;
        btn.classList.remove('btn-disabled');
        alert('System Error.');
    });
}

// --- MODAL ---
const modal = document.getElementById('previewModal');
const modalFrame = document.getElementById('modalFrame');

function openModal(id) {
    const source = document.getElementById('source-' + id);
    if(source) {
        // Exakter CSS Reset aus generator.php
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
function closeModal() { modal.style.display = 'none'; modalFrame.srcdoc=''; }
window.onclick = e => { if(e.target == modal) closeModal(); }

// --- DELETE ALL ---
function confirmDeleteAll() {
    if(confirm('Delete ALL signatures displayed in this list?')) document.getElementById('deleteAllForm').submit();
}

// --- SCROLLING ---
document.addEventListener('DOMContentLoaded', function() {
    let page = 1; let loading = false; let more = true;
    const uid = "<?php echo $target_user_id; ?>";
    const search = "<?php echo urlencode($search); ?>";
    const loader = document.getElementById('infiniteLoader');
    const cont = document.getElementById('signatureListContainer');
    const sentinel = document.getElementById('sentinel');

    if (cont.querySelector('.empty-state')) { more = false; sentinel.style.display = 'none'; }

    const loadMore = () => {
        if (loading || !more) return;
        loading = true; loader.style.display = 'block'; page++;
        fetch(`all_signatures.php?ajax=1&page=${page}&user_id=${uid}&search=${search}`)
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
