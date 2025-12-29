<?php
// all_signatures.php

require_once 'includes/config.php';
requireLogin();

// ---------------------------------------------------------
// 1. HELPER FUNCTION: RENDER ITEM
// ---------------------------------------------------------
function renderSignatureItem($sig, $target_user_id, $search, $show_owner_name = false) {
    // Template path determination
    $tplPath = 'templates/' . basename($sig['template']);
    $encodedHtml = "";
    
    // Load Template
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
    
    $csrf = $_SESSION['csrf_token'];
    ?>
    <div class="signature-item" style="flex-wrap: wrap;">
        <div style="display:flex; justify-content:space-between; width:100%; align-items:center;">
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
                <button onclick="togglePreview(<?php echo $sig['id']; ?>)" class="btn btn-sm btn-secondary" title="Show Preview" style="background:white; border:1px solid #e2e8f0;">
                    <i class="fas fa-eye"></i>
                </button>
                <?php endif; ?>
                
                <a href="download.php?id=<?php echo $sig['id']; ?>" class="btn btn-sm btn-primary" title="Download">
                    <i class="fas fa-download"></i>
                </a>
                
                <a href="all_signatures.php?delete=<?php echo $sig['id']; ?>&user_id=<?php echo $target_user_id; ?>&search=<?php echo urlencode($search); ?>&csrf_token=<?php echo $csrf; ?>" 
                   class="btn btn-sm btn-danger"
                   onclick="return confirm('Really delete this signature?')" title="Delete">
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
    <?php
}
// ---------------------------------------------------------

// 2. Setup & Security
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$current_user_id = $_SESSION['user_id'];
$is_admin = isAdmin();
$message = '';

// 3. ADMIN LOGIC: User Selection
$target_user_id = $current_user_id; 
$users_list = [];

if ($is_admin) {
    if (isset($_GET['user_id'])) {
        if ($_GET['user_id'] === 'all') {
            $target_user_id = 'all';
        } elseif (is_numeric($_GET['user_id'])) {
            $target_user_id = (int)$_GET['user_id'];
        }
    }
    
    // Fetch users for dropdown (only if not AJAX)
    if (!isset($_GET['ajax'])) {
        $stmtUsers = $db->prepare("SELECT id, username, full_name FROM users ORDER BY username ASC");
        $resUsers = $stmtUsers->execute();
        while ($u = $resUsers->fetchArray(SQLITE3_ASSOC)) {
            $users_list[] = $u;
        }
    }
} else {
    $target_user_id = $current_user_id;
}

// 4. QUERY PARAMETERS
$search = trim($_GET['search'] ?? '');
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
if ($page < 1) $page = 1;
$limit = 10; 
$offset = ($page - 1) * $limit;

// Build Query Logic
$params = [];
$whereClauses = [];

// A. User Filter
if ($target_user_id !== 'all') {
    $whereClauses[] = "s.user_id = :uid";
    $params[':uid'] = $target_user_id;
}

// B. Search Filter
if (!empty($search)) {
    $whereClauses[] = "(s.name LIKE :search OR s.email LIKE :search OR s.role LIKE :search)";
    $params[':search'] = '%' . $search . '%';
}

$whereSQL = "";
if (!empty($whereClauses)) {
    $whereSQL = "WHERE " . implode(' AND ', $whereClauses);
}

// 4a. Count Total
$countSql = "SELECT COUNT(*) as total FROM user_signatures s $whereSQL";
$stmtCount = $db->prepare($countSql);
foreach ($params as $key => $val) {
    $stmtCount->bindValue($key, $val, is_int($val) ? SQLITE3_INTEGER : SQLITE3_TEXT);
}
$totalResult = $stmtCount->execute();
$totalRow = $totalResult->fetchArray(SQLITE3_ASSOC);
$totalSignatures = $totalRow['total'];

// 4b. Fetch Data
$dataSql = "SELECT s.*, u.username 
            FROM user_signatures s 
            LEFT JOIN users u ON s.user_id = u.id 
            $whereSQL 
            ORDER BY s.created_at DESC 
            LIMIT :limit OFFSET :offset";

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

// 5. AJAX HANDLER
if (isset($_GET['ajax'])) {
    if (empty($signatures)) {
        exit; 
    }
    foreach ($signatures as $sig) {
        renderSignatureItem($sig, $target_user_id, $search, ($target_user_id === 'all'));
    }
    exit;
}

// 6. DELETE LOGIC (The critical part)
if ($_SERVER['REQUEST_METHOD'] === 'POST' || isset($_GET['delete'])) {
    $token = $_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], $token)) die("Security Error: Invalid CSRF Token");

    // Case A: Delete Single Item
    if (isset($_GET['delete'])) {
        $del_id = (int)$_GET['delete'];
        
        $sql = "DELETE FROM user_signatures WHERE id = :id";
        if ($target_user_id !== 'all') {
            $sql .= " AND user_id = :uid";
        }

        $stmtDel = $db->prepare($sql);
        $stmtDel->bindValue(':id', $del_id, SQLITE3_INTEGER);
        if ($target_user_id !== 'all') {
            $stmtDel->bindValue(':uid', $target_user_id, SQLITE3_INTEGER);
        }
        $stmtDel->execute();
        
        header("Location: all_signatures.php?user_id=$target_user_id&search=" . urlencode($search) . "&success=deleted_one");
        exit;
    }
    
    // Case B: Delete ALL (Unlocked)
    if (isset($_POST['action']) && $_POST['action'] === 'delete_all') {
        
        if ($target_user_id === 'all') {
            // ADMIN MODE: DELETE EVERYTHING FROM DB
            // (Ignoring search filter to be robust and prevent alias SQL errors)
            if (!$is_admin) die("Unauthorized"); // Extra check
            
            $stmtDel = $db->prepare("DELETE FROM user_signatures");
            $stmtDel->execute();
            
        } else {
            // USER MODE: DELETE ALL FOR THIS USER
            $stmtDel = $db->prepare("DELETE FROM user_signatures WHERE user_id = ?");
            $stmtDel->bindValue(1, $target_user_id, SQLITE3_INTEGER);
            $stmtDel->execute();
        }
        
        header("Location: all_signatures.php?user_id=$target_user_id&success=deleted_all");
        exit;
    }
}

if (isset($_GET['success'])) {
    if ($_GET['success'] == 'deleted_all') $message = "All signatures in this selection deleted!";
    if ($_GET['success'] == 'deleted_one') $message = "Signature deleted successfully.";
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
        .alert { padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; display: flex; gap: 0.75rem; align-items: center; }
        .alert-success { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
        .empty-state { text-align: center; padding: 4rem 1rem; color: #94a3b8; }
        .empty-icon { font-size: 3rem; margin-bottom: 1rem; opacity: 0.5; }
        .sig-preview-container { display: none; margin-top: 1rem; border: 1px dashed #e2e8f0; background: #f8fafc; padding: 10px; border-radius: 8px; width: 100%; }
        .preview-iframe { width: 100%; height: 180px; border: none; background: white; border-radius: 4px; }
        .filter-bar { background: white; padding: 1rem; border-radius: 8px; border: 1px solid var(--border); margin-bottom: 1.5rem; display: flex; gap: 1rem; flex-wrap: wrap; align-items: center; }
        .user-select { padding: 0.6rem; border: 1px solid #cbd5e1; border-radius: 6px; min-width: 200px; font-weight: 500; }
        .search-input { flex: 1; padding: 0.6rem; border: 1px solid #cbd5e1; border-radius: 6px; }
        .count-badge { background-color: #eff6ff; color: #2563eb; font-size: 0.9rem; padding: 0.3rem 0.8rem; border-radius: 999px; font-weight: 700; margin-left: 10px; border: 1px solid #dbeafe; vertical-align: middle; }
        .infinite-spinner { text-align: center; padding: 2rem; display: none; color: var(--text-muted); }
        #sentinel { height: 20px; width: 100%; }
        .end-of-results { text-align: center; padding: 2rem; display: none; color: #94a3b8; font-size: 0.9rem; font-style: italic; }
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
            <h2>Signature Management</h2>
            <p>View, search and manage existing signatures.</p>
        </header>

        <?php if ($message): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>

        <section class="card">
            <div class="card-header">
                <div style="display: flex; align-items: center;">
                    <h3 style="margin:0;">
                        <i class="fas fa-list"></i> 
                        <?php echo ($target_user_id === 'all') ? 'All User Signatures' : ($is_admin ? 'User Signatures' : 'My Signatures'); ?>
                    </h3>
                    <span class="count-badge">
                        <?php echo $totalSignatures; ?> found
                    </span>
                </div>
                
                <?php if (!empty($signatures) && empty($search)): ?>
                    <button onclick="confirmDeleteAll()" class="btn btn-sm btn-danger">
                        <i class="fas fa-trash-alt"></i> Delete All displayed
                    </button>
                <?php endif; ?>
            </div>

            <div class="filter-bar">
                <form method="GET" action="all_signatures.php" style="display:flex; gap:10px; width:100%; flex-wrap:wrap;">
                    
                    <?php if ($is_admin): ?>
                    <div style="flex-shrink:0;">
                        <select name="user_id" class="user-select" onchange="this.form.submit()">
                            <option value="all" <?php echo ($target_user_id === 'all') ? 'selected' : ''; ?>>-- All Users --</option>
                            <?php foreach ($users_list as $u): ?>
                                <option value="<?php echo $u['id']; ?>" <?php echo ($u['id'] == $target_user_id) ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($u['username']); ?> 
                                    (<?php echo htmlspecialchars($u['full_name'] ?: 'No Name'); ?>)
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <?php endif; ?>

                    <input type="text" name="search" class="search-input" 
                           placeholder="Search by name, email or role..." 
                           value="<?php echo htmlspecialchars($search, ENT_QUOTES, 'UTF-8'); ?>">
                    
                    <button type="submit" class="btn btn-primary"><i class="fas fa-search"></i> Search</button>
                    
                    <?php if (!empty($search)): ?>
                        <a href="all_signatures.php?user_id=<?php echo $target_user_id; ?>" class="btn btn-secondary" style="border:1px solid #ccc; color:#333">Clear</a>
                    <?php endif; ?>
                </form>
            </div>

            <div class="signature-list" id="signatureListContainer">
                <?php if (empty($signatures)): ?>
                    <div class="empty-state">
                        <i class="fas fa-folder-open empty-icon"></i>
                        <p>No signatures found.</p>
                    </div>
                <?php else: ?>
                    <?php foreach ($signatures as $sig): ?>
                        <?php renderSignatureItem($sig, $target_user_id, $search, ($target_user_id === 'all')); ?>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>

            <div class="infinite-spinner" id="infiniteLoader">
                <i class="fas fa-spinner fa-spin fa-2x"></i>
                <div style="margin-top:10px">Loading more...</div>
            </div>

            <div id="sentinel"></div>
            
            <div class="end-of-results" id="endOfResults">
                All signatures loaded.
            </div>

        </section>

    </main>

    <form id="deleteAllForm" method="POST" action="all_signatures.php?user_id=<?php echo $target_user_id; ?>" style="display:none;">
        <input type="hidden" name="action" value="delete_all">
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    </form>

    <script>
        function togglePreview(id) {
            const el = document.getElementById('preview-' + id);
            const icon = el.parentElement.querySelector('.btn-secondary i');
            el.style.display = (el.style.display === 'block') ? 'none' : 'block';
            icon.className = (el.style.display === 'block') ? 'fas fa-eye-slash' : 'fas fa-eye';
        }
        
        function confirmDeleteAll() {
            var warning = 'Are you sure you want to delete ALL signatures displayed?';
            <?php if($target_user_id === 'all'): ?>
                warning = 'WARNING: You are about to delete ALL signatures for ALL USERS in the entire database! This cannot be undone. Are you absolutely sure?';
            <?php endif; ?>
            
            if(confirm(warning)) {
                document.getElementById('deleteAllForm').submit();
            }
        }

        document.addEventListener('DOMContentLoaded', function() {
            let currentPage = 1;
            let isLoading = false;
            let hasMore = true;

            const userId = "<?php echo $target_user_id; ?>";
            const searchTerm = "<?php echo urlencode($search); ?>";
            
            const loader = document.getElementById('infiniteLoader');
            const endMsg = document.getElementById('endOfResults');
            const container = document.getElementById('signatureListContainer');
            const sentinel = document.getElementById('sentinel');

            if (container.querySelector('.empty-state')) {
                hasMore = false;
                sentinel.style.display = 'none';
            }

            const loadMore = () => {
                if (isLoading || !hasMore) return;
                isLoading = true;
                loader.style.display = 'block';
                currentPage++;
                
                const url = `all_signatures.php?ajax=1&page=${currentPage}&user_id=${userId}&search=${searchTerm}`;

                fetch(url)
                    .then(response => response.text())
                    .then(html => {
                        loader.style.display = 'none';
                        if (html.trim() === '') {
                            hasMore = false;
                            sentinel.style.display = 'none';
                            endMsg.style.display = 'block';
                        } else {
                            container.insertAdjacentHTML('beforeend', html);
                            isLoading = false;
                        }
                    })
                    .catch(err => {
                        console.error('Error loading items:', err);
                        loader.style.display = 'none';
                        isLoading = false;
                    });
            };

            const observerOptions = { root: null, rootMargin: '100px', threshold: 0.1 };
            const observer = new IntersectionObserver((entries) => {
                if (entries[0].isIntersecting && hasMore && !isLoading) {
                    loadMore();
                }
            }, observerOptions);

            if (hasMore) {
                observer.observe(sentinel);
            }
        });
    </script>
</body>
</html>
