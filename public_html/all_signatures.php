<?php
// all_signatures.php

require_once 'includes/config.php';
requireLogin();

// ---------------------------------------------------------
// 1. HELPERS
// ---------------------------------------------------------

/** Query string that carries the complete filter state (only non-default values). */
function sigQuery(array $f, array $override = []): string
{
    $f = array_merge($f, $override);
    $q = ['user_id' => (string)$f['user_id']];
    foreach (['search', 'template', 'source', 'tag'] as $k) {
        if ((string)$f[$k] !== '') $q[$k] = (string)$f[$k];
    }
    if ($f['sort'] !== 'newest') $q['sort'] = $f['sort'];
    return http_build_query($q, '', '&', PHP_QUERY_RFC3986);
}

function sourceLabel(?string $source): string
{
    if ($source === 'ldap') return t('LDAP import');
    if ($source === 'csv') return t('CSV import');
    return t('Manual');
}

function renderSignatureItem($sig, array $f, array $tags, $show_owner_name = false, array $deviceRows = [], $freshnessHours = 6) {
    // Final, sanitised HTML of the signature for the preview textarea.
    $html = renderStoredSignature($sig);
    $encodedHtml = e($html);
    $deleteUrl = 'all_signatures.php?' . sigQuery($f);
    $source = in_array($sig['source'] ?? '', ['ldap', 'csv'], true) ? $sig['source'] : 'manual';

    // Same value as signatureHtmlSha256() / the API's html_sha256 (same render
    // function), computed from the HTML that is rendered here anyway.
    $currentSha = hash('sha256', $html);
    $sync = summarizeSyncStatus($deviceRows, $currentSha, $sig['updated_at'] ?? null, (int)$freshnessHours);

    // Tooltip: one line per device, most recent report first.
    $syncTooltipLines = [$sync['label']];
    if (!$sync['devices']) {
        $syncTooltipLines[] = t('No agent has reported syncing this signature yet.');
    }
    foreach ($sync['devices'] as $dev) {
        $ts = strtotime($dev['synced_at'] . ' UTC');
        $line = t('{device}: {state}, last report {time}', [
            'device' => $dev['device_id'],
            'state'  => $dev['label'],
            'time'   => $ts ? gmdate('Y-m-d H:i', $ts) . ' UTC' : $dev['synced_at'],
        ]);
        if ($dev['agent_version'] !== '') $line .= ' (' . t('agent {version}', ['version' => $dev['agent_version']]) . ')';
        if ($dev['message'] !== '') $line .= ' - ' . $dev['message'];
        $syncTooltipLines[] = $line;
    }
    $syncTooltip = implode("\n", $syncTooltipLines);

    // Same information for the details dialog (click on the badge; tooltips do
    // not exist on touch screens). Inserted with textContent by the script.
    $syncData = ['name' => (string)$sig['name'], 'level' => $sync['level'], 'label' => $sync['label'], 'devices' => []];
    foreach ($sync['devices'] as $dev) {
        $ts = strtotime($dev['synced_at'] . ' UTC');
        $syncData['devices'][] = [
            'device'  => $dev['device_id'],
            'state'   => $dev['state'],
            'label'   => $dev['label'],
            'time'    => $ts ? gmdate('Y-m-d H:i', $ts) . ' UTC' : $dev['synced_at'],
            'version' => $dev['agent_version'],
            'message' => $dev['message'],
        ];
    }

    // Data for the edit modal. Rendered as JSON inside a <script type="application/json">
    // block (never interpreted as HTML/JS), so no field needs separate JS-string escaping.
    // JSON_HEX_TAG also keeps a "</script" in any field from breaking out of the block.
    $editData = [
        'id'       => (int)$sig['id'],
        'name'     => (string)$sig['name'],
        'role'     => (string)$sig['role'],
        'email'    => (string)$sig['email'],
        'phone'    => (string)$sig['phone'],
        'template' => resolveTemplateName((string)($sig['template'] ?? '')),
        'source'   => $source,
        'tagIds'   => array_map(function ($t) { return (int)$t['id']; }, $tags),
    ];
    ?>
    <script type="application/json" class="edit-data" id="edit-data-<?php echo (int)$sig['id']; ?>"><?php echo json_encode($editData, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE); ?></script>
    <script type="application/json" class="sync-data" id="sync-data-<?php echo (int)$sig['id']; ?>"><?php echo json_encode($syncData, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE); ?></script>
    <div class="signature-item" style="flex-wrap: nowrap; gap: 15px;">
        <div style="display:flex; align-items:center; padding-left:5px;">
            <input type="checkbox" class="sig-checkbox" value="<?php echo (int)$sig['id']; ?>" onchange="updateBulkButtons()">
        </div>

        <div style="flex-grow: 1;">
            <div style="display:flex; justify-content:space-between; width:100%; align-items:center; flex-wrap:wrap;">
                <div class="sig-details">
                    <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
                        <h4><?php echo e($sig['name']); ?></h4>
                        <?php if ($show_owner_name && !empty($sig['username'])): ?>
                        <span style="background:var(--info-bg); color:var(--info-text); font-size:0.7rem; padding:2px 6px; border-radius:4px; border:1px solid var(--info-border);">
                            <i class="fas fa-user"></i> <?php echo e($sig['username']); ?>
                        </span>
                        <?php endif; ?>
                        <button type="button" class="sync-badge sync-<?php echo e($sync['level']); ?>" title="<?php echo e($syncTooltip); ?>" onclick="openSyncModal(<?php echo (int)$sig['id']; ?>)">
                            <span class="sync-dot"></span><?php echo e($sync['label']); ?>
                        </button>
                        <?php foreach ($tags as $tg): ?>
                        <a class="sig-tag tag-c-<?php echo e(normalizeTagColor($tg['color'])); ?>" href="all_signatures.php?<?php echo e(sigQuery($f, ['tag' => (string)(int)$tg['id']])); ?>" title="<?= et('Filter by this tag') ?>"><?php echo e($tg['name']); ?></a>
                        <?php endforeach; ?>
                    </div>
                    <p><?php echo e($sig['role']); ?> &bull; <?php echo e($sig['email']); ?></p>
                    <p style="font-size:0.75rem; color:var(--text-faint); margin-top:0.25rem">
                        <i class="far fa-clock"></i> <?php echo e(date('M d, Y', strtotime($sig['created_at']) ?: time())); ?>
                        &bull; <a class="meta-chip" href="all_signatures.php?<?php echo e(sigQuery($f, ['template' => (string)$sig['template']])); ?>" title="<?php echo e($sig['template']); ?>"><i class="fas fa-file-code"></i> <?php echo e(templateDisplayName((string)$sig['template'])); ?></a>
                        <a class="meta-chip" href="all_signatures.php?<?php echo e(sigQuery($f, ['source' => $source])); ?>"><?php echo e(sourceLabel($source)); ?></a>
                    </p>
                </div>

                <div class="sig-actions" style="display:flex; gap:0.5rem; align-items:center;">
                    <?php if ($encodedHtml !== ''): ?>
                    <textarea id="source-<?php echo (int)$sig['id']; ?>" class="visually-hidden"><?php echo $encodedHtml; ?></textarea>
                    <button type="button" onclick="openModal(<?php echo (int)$sig['id']; ?>)" class="btn btn-sm btn-secondary" style="background:var(--bg-white); border:1px solid var(--border-strong);" title="<?= et('Preview') ?>"><i class="fas fa-eye"></i></button>
                    <?php endif; ?>
                    <a href="download.php?id=<?php echo (int)$sig['id']; ?>" class="btn btn-sm btn-primary" title="<?= et('Download') ?>"><i class="fas fa-download"></i></a>
                    <button type="button" onclick="openEditModal(<?php echo (int)$sig['id']; ?>)" class="btn btn-sm btn-secondary" style="background:var(--bg-white); border:1px solid var(--border-strong);" title="<?= et('Edit') ?>"><i class="fas fa-pen"></i></button>
                    <button type="button" data-post="<?php echo e($deleteUrl); ?>" data-params='{"action":"delete_one","id":"<?php echo (int)$sig['id']; ?>"}'
                       data-confirm="<?= et('Delete?') ?>" class="btn btn-sm btn-danger" title="<?= et('Delete') ?>"><i class="fas fa-trash"></i></button>
                </div>
            </div>
        </div>
    </div>
    <?php
}

/** Tags of the given signatures: [signature_id => [[id,name,color], ...]] */
function loadSignatureTags(SQLite3 $db, array $signatures): array
{
    $ids = array_values(array_filter(array_map(function ($s) { return (int)$s['id']; }, $signatures)));
    if (!$ids) return [];
    $marks = implode(',', array_fill(0, count($ids), '?'));
    $st = $db->prepare("SELECT m.signature_id, t.id, t.name, t.color FROM signature_tag_map m
                        JOIN signature_tags t ON t.id = m.tag_id
                        WHERE m.signature_id IN ($marks) ORDER BY t.name COLLATE NOCASE");
    foreach ($ids as $i => $id) $st->bindValue($i + 1, $id, SQLITE3_INTEGER);
    $res = $st->execute();
    $map = [];
    while ($r = $res->fetchArray(SQLITE3_ASSOC)) $map[(int)$r['signature_id']][] = $r;
    return $map;
}

/**
 * Agent device reports of the given signatures, limited to the retention
 * window: [signature_id => [row, row, ...]] (one row per device).
 */
function loadSignatureDeviceStatus(SQLite3 $db, array $signatures): array
{
    $ids = array_values(array_filter(array_map(function ($s) { return (int)$s['id']; }, $signatures)));
    if (!$ids) return [];
    $marks = implode(',', array_fill(0, count($ids), '?'));
    $st = $db->prepare("SELECT * FROM signature_device_status
                        WHERE signature_id IN ($marks) AND synced_at >= datetime('now', ?)");
    foreach ($ids as $i => $id) $st->bindValue($i + 1, $id, SQLITE3_INTEGER);
    $st->bindValue(count($ids) + 1, '-' . statusDeviceRetentionDays($db) . ' days', SQLITE3_TEXT);
    $res = $st->execute();
    $map = [];
    while ($r = $res->fetchArray(SQLITE3_ASSOC)) $map[(int)$r['signature_id']][] = $r;
    return $map;
}

// ---------------------------------------------------------
// 2. LOGIC & DATA FETCHING
// ---------------------------------------------------------
$current_user_id = (int)$_SESSION['user_id'];
$is_admin = isStaff(); // administrators and technicians work with all signatures
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
}

// Filters (everything is validated; values are only ever bound as parameters)
$sortOptions = [
    'newest'   => ['label' => t('Newest first'),       'sql' => 's.created_at DESC, s.id DESC'],
    'oldest'   => ['label' => t('Oldest first'),       'sql' => 's.created_at ASC, s.id ASC'],
    'name'     => ['label' => t('Name (A-Z)'),         'sql' => 's.name COLLATE NOCASE ASC, s.id ASC'],
    'email'    => ['label' => t('Email (A-Z)'),        'sql' => 's.email COLLATE NOCASE ASC, s.id ASC'],
    'template' => ['label' => t('Template'),           'sql' => 's.template ASC, s.name COLLATE NOCASE ASC, s.id ASC'],
];
$rawSort = (string)($_GET['sort'] ?? 'newest');
$rawTag  = (string)($_GET['tag'] ?? '');
$rawSrc  = (string)($_GET['source'] ?? '');
$f = [
    'user_id'  => $target_user_id,
    'search'   => cleanText($_GET['search'] ?? '', 100),
    'template' => cleanText($_GET['template'] ?? '', 120),
    'source'   => in_array($rawSrc, ['manual', 'csv', 'ldap'], true) ? $rawSrc : '',
    'tag'      => ($rawTag === 'none' || preg_match('/^[1-9]\d{0,9}$/', $rawTag)) ? $rawTag : '',
    'sort'     => isset($sortOptions[$rawSort]) ? $rawSort : 'newest',
];
$search = $f['search'];
$filterQS = sigQuery($f);
$filtersActive = ($f['search'] !== '' || $f['template'] !== '' || $f['source'] !== '' || $f['tag'] !== '');

$page = max(1, min(100000, (int)($_GET['page'] ?? 1)));
$limit = 10;
$offset = ($page - 1) * $limit;

$params = [];
$whereClauses = [];
if ($target_user_id !== 'all') { $whereClauses[] = "s.user_id = :uid"; $params[':uid'] = $target_user_id; }
if ($f['search'] !== '') { $whereClauses[] = "(s.name LIKE :search ESCAPE '\\' OR s.email LIKE :search ESCAPE '\\' OR s.role LIKE :search ESCAPE '\\')"; $params[':search'] = '%' . addcslashes($f['search'], '%_\\') . '%'; }
if ($f['template'] !== '') { $whereClauses[] = "s.template = :tpl"; $params[':tpl'] = $f['template']; }
if ($f['source'] === 'manual') { $whereClauses[] = "(s.source IS NULL OR s.source = 'manual')"; }
elseif ($f['source'] !== '') { $whereClauses[] = "s.source = :src"; $params[':src'] = $f['source']; }
if ($f['tag'] === 'none') { $whereClauses[] = "NOT EXISTS (SELECT 1 FROM signature_tag_map m WHERE m.signature_id = s.id)"; }
elseif ($f['tag'] !== '') { $whereClauses[] = "EXISTS (SELECT 1 FROM signature_tag_map m WHERE m.signature_id = s.id AND m.tag_id = :tag)"; $params[':tag'] = (int)$f['tag']; }
$whereSQL = !empty($whereClauses) ? "WHERE " . implode(' AND ', $whereClauses) : "";

function bindParams(SQLite3Stmt $st, array $params): void
{
    foreach ($params as $k => $v) $st->bindValue($k, $v, is_int($v) ? SQLITE3_INTEGER : SQLITE3_TEXT);
}

// Count
$stmtCount = $db->prepare("SELECT COUNT(*) as total FROM user_signatures s $whereSQL");
bindParams($stmtCount, $params);
$totalSignatures = (int)$stmtCount->execute()->fetchArray(SQLITE3_ASSOC)['total'];

// Fetch
$orderSQL = $sortOptions[$f['sort']]['sql']; // whitelisted above, never user text
$stmt = $db->prepare("SELECT s.*, u.username FROM user_signatures s LEFT JOIN users u ON s.user_id = u.id $whereSQL ORDER BY $orderSQL LIMIT :limit OFFSET :offset");
bindParams($stmt, $params);
$stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
$stmt->bindValue(':offset', $offset, SQLITE3_INTEGER);
$result = $stmt->execute();
$signatures = [];
while ($row = $result->fetchArray(SQLITE3_ASSOC)) $signatures[] = $row;
$sigTags = loadSignatureTags($db, $signatures);
$sigDeviceStatus = loadSignatureDeviceStatus($db, $signatures);
$statusFreshnessHours = (int)getSetting($db, 'status_freshness_hours', '6');

// AJAX Handler (infinite scroll)
if (isset($_GET['ajax'])) {
    if (empty($signatures)) exit;
    foreach ($signatures as $sig) renderSignatureItem($sig, $f, $sigTags[(int)$sig['id']] ?? [], ($target_user_id === 'all'), $sigDeviceStatus[(int)$sig['id']] ?? [], $statusFreshnessHours);
    exit;
}

// Facets for the filter dropdowns (scope = selected user, ignoring the other filters)
$scopeSQL = ($target_user_id !== 'all') ? 'WHERE s.user_id = :uid' : '';
$facetTemplates = [];
$st = $db->prepare("SELECT s.template AS template, COUNT(*) AS c FROM user_signatures s $scopeSQL GROUP BY s.template ORDER BY s.template");
if ($target_user_id !== 'all') $st->bindValue(':uid', $target_user_id, SQLITE3_INTEGER);
$res = $st->execute();
while ($r = $res->fetchArray(SQLITE3_ASSOC)) $facetTemplates[] = $r;

$facetTags = [];
$scopeJoin = ($target_user_id !== 'all') ? 'AND s.user_id = :uid' : '';
$st = $db->prepare("SELECT t.id, t.name, t.color, COUNT(s.id) AS c FROM signature_tags t
                    LEFT JOIN signature_tag_map m ON m.tag_id = t.id
                    LEFT JOIN user_signatures s ON s.id = m.signature_id $scopeJoin
                    GROUP BY t.id " . ($is_admin ? '' : 'HAVING c > 0 ') . "ORDER BY t.name COLLATE NOCASE");
if ($target_user_id !== 'all') $st->bindValue(':uid', $target_user_id, SQLITE3_INTEGER);
$res = $st->execute();
while ($r = $res->fetchArray(SQLITE3_ASSOC)) $facetTags[] = $r;

$allTemplates = listSignatureTemplates();

// ---------------------------------------------------------
// 3. ACTION HANDLERS
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    requireCsrf();
    $action = $_POST['action'] ?? '';
    $redirect = 'all_signatures.php?' . $filterQS;

    /** Signature ids from a bulk form: unique, positive, capped. */
    $postedIds = function (): array {
        $rawIds = $_POST['ids'] ?? [];
        $ids = is_array($rawIds) ? $rawIds : explode(',', (string)$rawIds);
        return array_values(array_slice(array_unique(array_filter(array_map('intval', $ids), function ($v) { return $v > 0; })), 0, 1000));
    };

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

    // EDIT SINGLE (admins may edit any signature of the selected scope, users only their own)
    if ($action === 'update_one') {
        $id = (int)($_POST['id'] ?? 0);

        $ownerSql = 'SELECT user_id FROM user_signatures WHERE id = :id';
        if ($target_user_id !== 'all') $ownerSql .= ' AND user_id = :uid';
        $ownerSt = $db->prepare($ownerSql);
        $ownerSt->bindValue(':id', $id, SQLITE3_INTEGER);
        if ($target_user_id !== 'all') $ownerSt->bindValue(':uid', $target_user_id, SQLITE3_INTEGER);
        $owner = $ownerSt->execute()->fetchArray(SQLITE3_ASSOC);

        if (!$owner) {
            setFlash('error', t('Signature not found.'));
            header('Location: ' . $redirect);
            exit;
        }

        [$fields, $errors] = validateSignatureFields($_POST, true);

        if ($errors) {
            setFlash('error', implode(' ', $errors));
            header('Location: ' . $redirect);
            exit;
        }

        $tpl = resolveTemplateName((string)($_POST['template'] ?? ''));

        $db->exec('BEGIN');
        // Ownership was already checked above (ownerSql); the same condition is
        // repeated directly on this UPDATE too, so the actual write is never
        // broader than what was verified - the same belt-and-suspenders pattern
        // delete_one uses, not only a check-then-act without a second gate.
        $updSql = "UPDATE user_signatures SET name = :name, role = :role, email = :email, phone = :phone, template = :tpl, updated_at = datetime('now') WHERE id = :id";
        if ($target_user_id !== 'all') $updSql .= ' AND user_id = :uid';
        $upd = $db->prepare($updSql);
        $upd->bindValue(':name', $fields['name'], SQLITE3_TEXT);
        $upd->bindValue(':role', $fields['role'], SQLITE3_TEXT);
        $upd->bindValue(':email', $fields['email'], SQLITE3_TEXT);
        $upd->bindValue(':phone', $fields['phone'], SQLITE3_TEXT);
        $upd->bindValue(':tpl', $tpl, SQLITE3_TEXT);
        $upd->bindValue(':id', $id, SQLITE3_INTEGER);
        if ($target_user_id !== 'all') $upd->bindValue(':uid', $target_user_id, SQLITE3_INTEGER);
        $upd->execute();
        if ($db->changes() === 0) {
            // Ownership changed between the check above and here (or the row was
            // deleted meanwhile) - stop, do not touch tags, do not log a success.
            $db->exec('ROLLBACK');
            setFlash('error', t('Signature not found.'));
            header('Location: ' . $redirect);
            exit;
        }

        // Tags: administrators and technicians only (matches the create_tag/delete_tag/bulk_tag boundary below).
        if ($is_admin) {
            $rawTagIds = $_POST['tags'] ?? [];
            $tagIds = is_array($rawTagIds)
                ? array_values(array_unique(array_filter(array_map('intval', $rawTagIds), function ($v) { return $v > 0; })))
                : [];
            $delTags = $db->prepare('DELETE FROM signature_tag_map WHERE signature_id = :id');
            $delTags->bindValue(':id', $id, SQLITE3_INTEGER);
            $delTags->execute();
            foreach ($tagIds as $tagId) {
                // Inserts only for tags that really exist.
                $insTag = $db->prepare('INSERT OR IGNORE INTO signature_tag_map (signature_id, tag_id) SELECT :id, id FROM signature_tags WHERE id = :tag');
                $insTag->bindValue(':id', $id, SQLITE3_INTEGER);
                $insTag->bindValue(':tag', $tagId, SQLITE3_INTEGER);
                $insTag->execute();
            }
        }
        $db->exec('COMMIT');

        if ($is_admin) {
            logSecurityEventToDB($db, 'SIGNATURE_EDITED', $current_user_id, 'id ' . $id . ' (user ' . (int)$owner['user_id'] . ')');
        }
        setFlash('success', t('Signature updated.'));
        header('Location: ' . $redirect);
        exit;
    }

    // DELETE ALL signatures matching the current filter (exactly what the list shows)
    if ($action === 'delete_all') {
        $del = $db->prepare("DELETE FROM user_signatures WHERE id IN (SELECT s.id FROM user_signatures s $whereSQL)");
        bindParams($del, $params);
        $del->execute();
        $deleted = $db->changes();
        if ($is_admin) {
            logSecurityEventToDB($db, 'SIGNATURES_DELETED_ALL', $current_user_id, 'Scope: ' . ($target_user_id === 'all' ? 'all users' : 'user ' . $target_user_id) . ($filtersActive ? ' (filtered)' : '') . ', ' . $deleted . ' signatures');
        }
        setFlash('success', t('All signatures deleted!'));
        header('Location: ' . $redirect);
        exit;
    }

    // DELETE SELECTED (bulk, capped)
    if ($action === 'delete_selected') {
        $ids = $postedIds();
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
        if ($is_admin) logSecurityEventToDB($db, 'SIGNATURES_DELETED_SELECTED', $current_user_id, $count . ' signatures');
        setFlash('success', t('{count} signatures deleted.', ['count' => $count]));
        header('Location: ' . $redirect);
        exit;
    }

    // CHANGE TEMPLATE of the selected signatures (staff: any, users: their own)
    if ($action === 'bulk_template') {
        $tpl = (string)($_POST['template'] ?? '');
        $ids = $postedIds();
        if (!in_array($tpl, $allTemplates, true)) {
            setFlash('error', t('Please choose a valid template.'));
        } elseif (!$ids) {
            setFlash('error', t('No signatures selected.'));
        } else {
            $count = 0;
            $db->exec('BEGIN');
            foreach ($ids as $id) {
                $sql = "UPDATE user_signatures SET template = :t, updated_at = datetime('now') WHERE id = :id";
                if (!$is_admin) $sql .= ' AND user_id = :uid';
                $st = $db->prepare($sql);
                $st->bindValue(':t', $tpl, SQLITE3_TEXT);
                $st->bindValue(':id', $id, SQLITE3_INTEGER);
                if (!$is_admin) $st->bindValue(':uid', $current_user_id, SQLITE3_INTEGER);
                $st->execute();
                $count += $db->changes();
            }
            $db->exec('COMMIT');
            if ($is_admin) logSecurityEventToDB($db, 'SIGNATURES_TEMPLATE_CHANGED', $current_user_id, $tpl . ': ' . $count . ' signatures');
            setFlash('success', t('Template changed for {count} signatures.', ['count' => $count]));
        }
        header('Location: ' . $redirect);
        exit;
    }

    // ---- Tags: administrators and technicians only ---------------------
    if (in_array($action, ['create_tag', 'delete_tag', 'bulk_tag'], true) && !$is_admin) {
        http_response_code(403);
        exit(t('Access denied.'));
    }

    if ($action === 'create_tag') {
        $name = normalizeTagName($_POST['name'] ?? '');
        $color = normalizeTagColor($_POST['color'] ?? '');
        if ($name === '') {
            setFlash('error', t('Invalid tag name. Use 1-32 letters, numbers, spaces or . _ - / &'));
        } elseif ((int)$db->querySingle('SELECT COUNT(*) FROM signature_tags') >= MAX_SIGNATURE_TAGS) {
            setFlash('error', t('Too many tags.'));
        } else {
            $st = $db->prepare('INSERT OR IGNORE INTO signature_tags (name, color) VALUES (?, ?)');
            $st->bindValue(1, $name, SQLITE3_TEXT);
            $st->bindValue(2, $color, SQLITE3_TEXT);
            $st->execute();
            if ($db->changes() > 0) {
                logSecurityEventToDB($db, 'SIGNATURE_TAG_CREATED', $current_user_id, $name);
                setFlash('success', t('Tag created.'));
            } else {
                setFlash('error', t('A tag with this name already exists.'));
            }
        }
        header('Location: ' . $redirect);
        exit;
    }

    if ($action === 'delete_tag') {
        $st = $db->prepare('DELETE FROM signature_tags WHERE id = ?');
        $st->bindValue(1, (int)($_POST['tag_id'] ?? 0), SQLITE3_INTEGER);
        $st->execute();
        if ($db->changes() > 0) {
            logSecurityEventToDB($db, 'SIGNATURE_TAG_DELETED', $current_user_id, 'id ' . (int)($_POST['tag_id'] ?? 0));
            setFlash('success', t('Tag deleted.'));
        }
        // A filter on the deleted tag would show an empty list.
        if ($f['tag'] === (string)(int)($_POST['tag_id'] ?? 0)) $redirect = 'all_signatures.php?' . sigQuery($f, ['tag' => '']);
        header('Location: ' . $redirect);
        exit;
    }

    if ($action === 'bulk_tag') {
        $tagId = (int)($_POST['tag_id'] ?? 0);
        $mode = ($_POST['mode'] ?? '') === 'remove' ? 'remove' : 'add';
        $ids = $postedIds();
        $exists = $tagId > 0 && $db->querySingle('SELECT COUNT(*) FROM signature_tags WHERE id = ' . $tagId);
        if (!$exists) {
            setFlash('error', t('Please choose a tag.'));
        } elseif (!$ids) {
            setFlash('error', t('No signatures selected.'));
        } else {
            $count = 0;
            $db->exec('BEGIN');
            foreach ($ids as $id) {
                if ($mode === 'add') {
                    // Inserts only for signatures that really exist.
                    $st = $db->prepare('INSERT OR IGNORE INTO signature_tag_map (signature_id, tag_id) SELECT id, :tag FROM user_signatures WHERE id = :id');
                } else {
                    $st = $db->prepare('DELETE FROM signature_tag_map WHERE signature_id = :id AND tag_id = :tag');
                }
                $st->bindValue(':tag', $tagId, SQLITE3_INTEGER);
                $st->bindValue(':id', $id, SQLITE3_INTEGER);
                $st->execute();
                $count += $db->changes();
            }
            $db->exec('COMMIT');
            setFlash('success', $mode === 'add'
                ? t('Tag added to {count} signatures.', ['count' => $count])
                : t('Tag removed from {count} signatures.', ['count' => $count]));
        }
        header('Location: ' . $redirect);
        exit;
    }
}

$message = popFlash('success');
$errorMessage = popFlash('error');
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
    /* Plain text field with the same look as .user-select, but without the dropdown arrow */
    .edit-input {
        background-color: var(--bg-white);
        color: var(--text-main);
        padding: 0.6rem 1rem;
        border: 1px solid var(--border-strong);
        border-radius: 6px;
        font-size: 0.95rem;
        outline: none;
        transition: all 0.2s ease-in-out;
        box-sizing: border-box;
    }
    .edit-input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1); }
    .edit-input:hover { border-color: var(--text-faint); }

    .search-input { flex: 1; padding: 0.6rem; border: 1px solid var(--border); border-radius: 6px; }
    .count-badge { background-color: var(--bg-hover); color: var(--primary); font-size: 0.9rem; padding: 0.3rem 0.8rem; border-radius: 999px; font-weight: 700; margin-left: 10px; border: 1px solid var(--info-border); }

    .infinite-spinner { text-align: center; padding: 2rem; display: none; color: var(--text-muted); }
    .end-of-results { text-align: center; padding: 2rem; display: none; color: var(--text-faint); font-size: 0.9rem; font-style: italic; }
    .sig-checkbox { width: 18px; height: 18px; cursor: pointer; }

    /* HEADER ACTION BUTTONS */
    .header-actions { display: flex; gap: 8px; align-items: center; }
    .btn-header { display: flex; align-items: center; gap: 6px; padding: 0.5rem 0.8rem; font-size: 0.85rem; }
    .btn-disabled { opacity: 0.5; pointer-events: none; cursor: not-allowed; }
    .alert-error { background: var(--danger-bg); color: var(--danger-text); border: 1px solid var(--danger-border); }

    /* FILTERS */
    .filter-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px; width: 100%; }
    .filter-grid .user-select { min-width: 0; width: 100%; }
    .filter-row { display: flex; gap: 10px; width: 100%; flex-wrap: wrap; align-items: center; }

    /* TAGS (colour classes only; no free-form CSS ever reaches the page) */
    .sig-tag { --tc: #2563eb; display: inline-flex; align-items: center; font-size: 0.7rem; font-weight: 600; padding: 2px 8px; border-radius: 999px; text-decoration: none;
               color: var(--tc); border: 1px solid var(--tc); background: transparent; }
    @supports (background: color-mix(in srgb, red 10%, transparent)) {
        .sig-tag { border-color: color-mix(in srgb, var(--tc) 45%, transparent); background: color-mix(in srgb, var(--tc) 12%, transparent); }
    }
    .sig-tag:hover { filter: brightness(0.9); }
    .tag-c-blue { --tc: #2563eb; } .tag-c-green { --tc: #15803d; } .tag-c-amber { --tc: #b45309; } .tag-c-red { --tc: #dc2626; }
    .tag-c-purple { --tc: #7c3aed; } .tag-c-teal { --tc: #0f766e; } .tag-c-pink { --tc: #be185d; } .tag-c-gray { --tc: #475569; }
    :root[data-theme="dark"] .tag-c-blue { --tc: #7aa2f7; } :root[data-theme="dark"] .tag-c-green { --tc: #4ade80; }
    :root[data-theme="dark"] .tag-c-amber { --tc: #fbbf24; } :root[data-theme="dark"] .tag-c-red { --tc: #f87171; }
    :root[data-theme="dark"] .tag-c-purple { --tc: #a78bfa; } :root[data-theme="dark"] .tag-c-teal { --tc: #2dd4bf; }
    :root[data-theme="dark"] .tag-c-pink { --tc: #f472b6; } :root[data-theme="dark"] .tag-c-gray { --tc: #94a3b8; }
    .meta-chip { background: var(--bg-subtle); padding: 2px 6px; border-radius: 4px; color: inherit; text-decoration: none; margin-inline-start: 4px; }
    .meta-chip:hover { color: var(--primary); }

    /* SYNC STATUS BADGE - whether/when an agent last reported applying this signature */
    .sync-badge { --sc: #94a3b8; display: inline-flex; align-items: center; gap: 5px; font-size: 0.7rem; font-weight: 600;
                   padding: 2px 8px; border-radius: 999px; color: var(--sc); border: 1px solid var(--sc); background: transparent; cursor: pointer;
                   font-family: inherit; line-height: 1.4; }
    .sync-badge:focus-visible { outline: 2px solid var(--primary); outline-offset: 2px; }
    .sync-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    .sync-table th, .sync-table td { text-align: start; padding: 0.5rem 0.6rem; border-bottom: 1px solid var(--border); vertical-align: top; }
    .sync-table th { color: var(--text-muted); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.03em; }
    .sync-table .sync-msg { color: var(--text-muted); font-size: 0.8rem; margin-top: 0.15rem; }
    @supports (background: color-mix(in srgb, red 10%, transparent)) {
        .sync-badge { border-color: color-mix(in srgb, var(--sc) 45%, transparent); background: color-mix(in srgb, var(--sc) 12%, transparent); }
    }
    .sync-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--sc); flex-shrink: 0; }
    .sync-grey   { --sc: #94a3b8; }
    .sync-green  { --sc: #16a34a; }
    .sync-yellow { --sc: #d97706; }
    .sync-red    { --sc: #dc2626; }
    :root[data-theme="dark"] .sync-grey   { --sc: #94a3b8; }
    :root[data-theme="dark"] .sync-green  { --sc: #4ade80; }
    :root[data-theme="dark"] .sync-yellow { --sc: #fbbf24; }
    :root[data-theme="dark"] .sync-red    { --sc: #f87171; }

    /* BULK BAR + TAG MANAGER */
    .bulk-bar { display: none; gap: 10px; align-items: center; flex-wrap: wrap; padding: 10px 15px; background: var(--info-bg); border-bottom: 1px solid var(--info-border); }
    .bulk-bar.visible { display: flex; }
    .bulk-bar select { padding: 0.4rem 0.6rem; border: 1px solid var(--border-strong); border-radius: 6px; background: var(--bg-white); color: var(--text-main); }
    .tag-manager { padding: 12px 15px; border-bottom: 1px solid var(--border); }
    .tag-manager summary { cursor: pointer; font-weight: 600; color: var(--text-muted); }
    .tag-manager-body { display: flex; flex-wrap: wrap; gap: 8px 16px; align-items: center; margin-top: 10px; }
    .tag-manager .tag-item { display: inline-flex; align-items: center; gap: 4px; }
    .tag-del { background: none; border: none; cursor: pointer; color: var(--text-faint); padding: 0 2px; font-size: 0.8rem; }
    .tag-del:hover { color: var(--danger-text); }
    .tag-create { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
    .tag-create input[type=text], .tag-create select { padding: 0.4rem 0.6rem; border: 1px solid var(--border-strong); border-radius: 6px; background: var(--bg-white); color: var(--text-main); }
</style>
</head>
<body>

<aside class="sidebar">
    <?php if (file_exists('includes/navbar.php')) include 'includes/navbar.php'; ?>
    <div class="sidebar-footer">
        <?= langSwitcher() ?>
        <div class="user-profile">
            <div class="avatar"><?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?></div>
            <div class="user-info"><div><?php echo e($_SESSION['username']); ?></div><span><?= eRoleLabel() ?></span></div>
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
    <?php if ($errorMessage): ?>
    <div class="alert alert-error"><i class="fas fa-exclamation-circle"></i> <?php echo e($errorMessage); ?></div>
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

        <?php if ($is_admin): ?>
        <details class="tag-manager">
            <summary><i class="fas fa-tags"></i> <?= et('Manage tags') ?></summary>
            <div class="tag-manager-body">
                <?php foreach ($facetTags as $tg): ?>
                <span class="tag-item">
                    <span class="sig-tag tag-c-<?php echo e(normalizeTagColor($tg['color'])); ?>"><?php echo e($tg['name']); ?></span>
                    <button type="button" class="tag-del" data-post="all_signatures.php?<?php echo e($filterQS); ?>" data-params='{"action":"delete_tag","tag_id":"<?php echo (int)$tg['id']; ?>"}'
                            data-confirm="<?= et('Delete this tag? It is removed from all signatures, the signatures themselves are kept.') ?>" title="<?= et('Delete') ?>"><i class="fas fa-times"></i></button>
                </span>
                <?php endforeach; ?>
                <?php if (empty($facetTags)): ?><span style="color:var(--text-faint); font-size:0.85rem;"><?= et('No tags yet.') ?></span><?php endif; ?>
                <form method="POST" action="all_signatures.php?<?php echo e($filterQS); ?>" class="tag-create">
                    <?php echo csrfField(); ?>
                    <input type="hidden" name="action" value="create_tag">
                    <input type="text" name="name" maxlength="32" required placeholder="<?= et('New tag') ?>" autocomplete="off">
                    <select name="color" aria-label="<?= et('Colour') ?>">
                        <?php foreach (signatureTagColors() as $c): ?>
                        <option value="<?php echo e($c); ?>"><?php echo e(signatureTagColorLabel($c)); ?></option>
                        <?php endforeach; ?>
                    </select>
                    <button type="submit" class="btn btn-sm btn-primary"><i class="fas fa-plus"></i> <?= et('Create tag') ?></button>
                </form>
            </div>
        </details>
        <?php endif; ?>

        <div class="filter-bar">
            <form method="GET" action="all_signatures.php" style="display:flex; flex-direction:column; gap:10px; width:100%;">
                <div class="filter-row">
                    <input type="text" name="search" class="search-input" placeholder="<?= et('Search...') ?>" value="<?php echo e($search); ?>">
                    <button type="submit" class="btn btn-primary"><?= et('Search') ?></button>
                    <?php if ($filtersActive || $f['sort'] !== 'newest'): ?><a href="all_signatures.php?user_id=<?php echo e(rawurlencode((string)$target_user_id)); ?>" class="btn btn-secondary"><?= et('Reset filters') ?></a><?php endif; ?>
                </div>
                <div class="filter-grid">
                    <?php if ($is_admin): ?>
                    <select name="user_id" class="user-select" aria-label="<?= et('User') ?>" onchange="this.form.submit()">
                        <option value="all" <?php echo ($target_user_id === 'all') ? 'selected' : ''; ?>><?= et('All Users') ?></option>
                        <?php foreach ($users_list as $u): ?>
                        <option value="<?php echo (int)$u['id']; ?>" <?php echo ($u['id'] == $target_user_id) ? 'selected' : ''; ?>><?php echo e($u['username']); ?></option>
                        <?php endforeach; ?>
                    </select>
                    <?php else: ?>
                    <input type="hidden" name="user_id" value="<?php echo (int)$target_user_id; ?>">
                    <?php endif; ?>

                    <select name="template" class="user-select" aria-label="<?= et('Template') ?>" onchange="this.form.submit()">
                        <option value=""><?= et('All templates') ?></option>
                        <?php $tplKnown = false; foreach ($facetTemplates as $ft): if ((string)$ft['template'] === $f['template']) $tplKnown = true; ?>
                        <option value="<?php echo e($ft['template']); ?>" <?php echo ((string)$ft['template'] === $f['template']) ? 'selected' : ''; ?>><?php echo e(templateDisplayName((string)$ft['template'])); ?> (<?php echo (int)$ft['c']; ?>)</option>
                        <?php endforeach; ?>
                        <?php if ($f['template'] !== '' && !$tplKnown): ?><option value="<?php echo e($f['template']); ?>" selected><?php echo e(templateDisplayName($f['template'])); ?> (0)</option><?php endif; ?>
                    </select>

                    <select name="tag" class="user-select" aria-label="<?= et('Tag') ?>" onchange="this.form.submit()">
                        <option value=""><?= et('All tags') ?></option>
                        <option value="none" <?php echo $f['tag'] === 'none' ? 'selected' : ''; ?>><?= et('Without tag') ?></option>
                        <?php foreach ($facetTags as $tg): ?>
                        <option value="<?php echo (int)$tg['id']; ?>" <?php echo ($f['tag'] === (string)$tg['id']) ? 'selected' : ''; ?>><?php echo e($tg['name']); ?> (<?php echo (int)$tg['c']; ?>)</option>
                        <?php endforeach; ?>
                    </select>

                    <select name="source" class="user-select" aria-label="<?= et('Source') ?>" onchange="this.form.submit()">
                        <option value=""><?= et('All sources') ?></option>
                        <option value="manual" <?php echo $f['source'] === 'manual' ? 'selected' : ''; ?>><?= et('Manual') ?></option>
                        <option value="csv" <?php echo $f['source'] === 'csv' ? 'selected' : ''; ?>><?= et('CSV import') ?></option>
                        <option value="ldap" <?php echo $f['source'] === 'ldap' ? 'selected' : ''; ?>><?= et('LDAP import') ?></option>
                    </select>

                    <select name="sort" class="user-select" aria-label="<?= et('Sort by') ?>" onchange="this.form.submit()">
                        <?php foreach ($sortOptions as $key => $opt): ?>
                        <option value="<?php echo e($key); ?>" <?php echo $f['sort'] === $key ? 'selected' : ''; ?>><?php echo e($opt['label']); ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
            </form>
        </div>

        <div style="padding: 10px 15px; background: var(--bg-subtle); border-bottom: 1px solid var(--border); display:flex; align-items:center; gap: 10px;">
            <input type="checkbox" id="selectAll" class="sig-checkbox" onchange="toggleSelectAll(this)">
            <label for="selectAll" style="font-weight:600; font-size:0.9rem; cursor:pointer; color:var(--text-muted);"><?= et('Select All visible') ?></label>
        </div>

        <form id="bulkBar" class="bulk-bar" method="POST" action="all_signatures.php?<?php echo e($filterQS); ?>">
            <?php echo csrfField(); ?>
            <input type="hidden" name="action" id="bulkAction" value="">
            <strong id="bulkCount" style="font-size:0.9rem;"></strong>
            <select name="template" id="bulkTemplate" aria-label="<?= et('Template') ?>">
                <?php foreach ($allTemplates as $tpl): ?>
                <option value="<?php echo e($tpl); ?>"><?php echo e(templateDisplayName($tpl)); ?></option>
                <?php endforeach; ?>
            </select>
            <button type="button" class="btn btn-sm btn-secondary" data-bulk="bulk_template" data-confirm="<?= et('Change the template of the selected signatures?') ?>"><i class="fas fa-file-code"></i> <?= et('Change template') ?></button>
            <?php if ($is_admin): ?>
            <span style="width:1px; height:20px; background:var(--border-strong);"></span>
            <select name="tag_id" id="bulkTag" aria-label="<?= et('Tag') ?>">
                <option value=""><?= et('Choose a tag') ?></option>
                <?php foreach ($facetTags as $tg): ?>
                <option value="<?php echo (int)$tg['id']; ?>"><?php echo e($tg['name']); ?></option>
                <?php endforeach; ?>
            </select>
            <input type="hidden" name="mode" id="bulkMode" value="add">
            <button type="button" class="btn btn-sm btn-secondary" data-bulk="bulk_tag" data-mode="add"><i class="fas fa-tag"></i> <?= et('Add tag') ?></button>
            <button type="button" class="btn btn-sm btn-secondary" data-bulk="bulk_tag" data-mode="remove"><i class="fas fa-eraser"></i> <?= et('Remove tag') ?></button>
            <?php endif; ?>
        </form>

        <div class="signature-list" id="signatureListContainer">
            <?php if (empty($signatures)): ?>
            <div class="empty-state"><i class="fas fa-folder-open empty-icon"></i><p><?= et('No signatures found.') ?></p></div>
            <?php else: ?>
            <?php foreach ($signatures as $sig) renderSignatureItem($sig, $f, $sigTags[(int)$sig['id']] ?? [], ($target_user_id === 'all'), $sigDeviceStatus[(int)$sig['id']] ?? [], $statusFreshnessHours); ?>
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

<div id="syncModal" class="modal-overlay">
    <div class="modal-box" style="max-width: 680px; height: auto; max-height: 90vh;">
        <div class="modal-header"><h3 style="margin:0"><i class="fas fa-rotate"></i> <?= et('Sync status') ?>: <span id="syncModalName"></span></h3><button class="close-modal-btn" onclick="closeSyncModal()">&times;</button></div>
        <div class="modal-body" style="height:auto; max-height:calc(90vh - 80px); overflow-y:auto; padding:1.25rem 1.5rem;">
            <p id="syncModalSummary" style="margin:0 0 1rem;"></p>
            <p id="syncModalEmpty" style="display:none; color:var(--text-muted);"><?= et('No agent has reported syncing this signature yet.') ?></p>
            <table class="sync-table" id="syncModalTable">
                <thead><tr><th><?= et('Device') ?></th><th><?= et('Status') ?></th><th><?= et('Last report') ?></th><th><?= et('Agent') ?></th></tr></thead>
                <tbody></tbody>
            </table>
            <p style="margin:1rem 0 0; font-size:0.8rem; color:var(--text-muted);"><?= et('"Out of date" means the signature, its template or the company details changed after this device last applied it. The device catches up on its next agent run.') ?></p>
        </div>
    </div>
</div>

<div id="editModal" class="modal-overlay">
    <div class="modal-box" style="max-width: 560px; height: auto; max-height: 90vh;">
        <div class="modal-header"><h3 style="margin:0"><i class="fas fa-pen"></i> <?= et('Edit signature') ?></h3><button class="close-modal-btn" onclick="closeEditModal()">&times;</button></div>
        <form id="editForm" method="POST" action="all_signatures.php?<?php echo e($filterQS); ?>">
            <?php echo csrfField(); ?>
            <input type="hidden" name="action" value="update_one">
            <input type="hidden" name="id" id="edit_id" value="">
            <div class="modal-body" style="height:auto; max-height:calc(90vh - 130px); overflow-y:auto; padding:1.25rem 1.5rem;">
                <div id="editLdapWarning" style="display:none; background:var(--warning-bg); color:var(--warning-text); border:1px solid var(--warning-border); border-radius:8px; padding:0.6rem 0.9rem; font-size:0.85rem; margin-bottom:1rem;">
                    <i class="fas fa-triangle-exclamation"></i> <?= et('This signature came from an LDAP import. The next import may overwrite your changes if this field is still mapped there.') ?>
                </div>
                <div style="display:flex; flex-direction:column; gap:0.9rem;">
                    <label>
                        <span style="font-weight:600; font-size:0.85rem;"><?= et('Name') ?></span>
                        <input type="text" name="name" id="edit_name" maxlength="100" required class="edit-input" style="width:100%; margin-top:0.25rem;">
                    </label>
                    <label>
                        <span style="font-weight:600; font-size:0.85rem;"><?= et('Role') ?></span>
                        <input type="text" name="role" id="edit_role" maxlength="100" class="edit-input" style="width:100%; margin-top:0.25rem;">
                    </label>
                    <label>
                        <span style="font-weight:600; font-size:0.85rem;"><?= et('Email') ?></span>
                        <input type="email" name="email" id="edit_email" maxlength="254" required class="edit-input" style="width:100%; margin-top:0.25rem;">
                    </label>
                    <label>
                        <span style="font-weight:600; font-size:0.85rem;"><?= et('Phone') ?></span>
                        <input type="text" name="phone" id="edit_phone" maxlength="30" class="edit-input" style="width:100%; margin-top:0.25rem;">
                    </label>
                    <label>
                        <span style="font-weight:600; font-size:0.85rem;"><?= et('Template') ?></span>
                        <select name="template" id="edit_template" class="user-select" style="width:100%; margin-top:0.25rem;">
                            <?php foreach ($allTemplates as $tpl): ?>
                            <option value="<?php echo e($tpl); ?>"><?php echo e(templateDisplayName($tpl)); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </label>
                    <?php if ($is_admin): ?>
                    <div>
                        <span style="font-weight:600; font-size:0.85rem;"><?= et('Tags') ?></span>
                        <div style="display:flex; flex-wrap:wrap; gap:0.5rem; margin-top:0.4rem;">
                            <?php foreach ($facetTags as $tg): ?>
                            <label style="display:flex; align-items:center; gap:0.3rem; font-size:0.8rem; background:var(--bg-subtle); border:1px solid var(--border); border-radius:6px; padding:0.25rem 0.5rem; cursor:pointer;">
                                <input type="checkbox" name="tags[]" class="edit-tag-check" value="<?php echo (int)$tg['id']; ?>">
                                <?php echo e($tg['name']); ?>
                            </label>
                            <?php endforeach; ?>
                            <?php if (empty($facetTags)): ?><span style="color:var(--text-faint); font-size:0.8rem;"><?= et('No tags yet.') ?></span><?php endif; ?>
                        </div>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
            <div class="modal-footer" style="display:flex; justify-content:flex-end; gap:0.5rem;">
                <button type="button" class="btn btn-sm btn-secondary" onclick="closeEditModal()"><?= et('Cancel') ?></button>
                <button type="submit" class="btn btn-sm btn-primary"><i class="fas fa-save"></i> <?= et('Save') ?></button>
            </div>
        </form>
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

<form id="deleteAllForm" method="POST" action="all_signatures.php?<?php echo e($filterQS); ?>" style="display:none;">
    <input type="hidden" name="action" value="delete_all">
    <?php echo csrfField(); ?>
</form>

<form id="deleteSelectedForm" method="POST" action="all_signatures.php?<?php echo e($filterQS); ?>" style="display:none;">
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

    const bar = document.getElementById('bulkBar');
    if (bar) {
        bar.classList.toggle('visible', selectedCount > 0);
        document.getElementById('bulkCount').textContent = <?= tj('{count} selected') ?>.replace('{count}', selectedCount);
    }
}

// --- BULK ACTIONS (change template, add/remove tag) ---
document.addEventListener('click', function (ev) {
    const btn = ev.target.closest('[data-bulk]');
    if (!btn) return;
    const form = document.getElementById('bulkBar');
    const ids = Array.from(document.querySelectorAll('.sig-checkbox:not(#selectAll):checked')).map(cb => cb.value);
    if (ids.length === 0) return;
    const confirmText = btn.getAttribute('data-confirm');
    if (confirmText && !confirm(confirmText + ' (' + ids.length + ')')) return;
    form.querySelectorAll('input[name="ids[]"]').forEach(n => n.remove());
    ids.forEach(id => {
        const input = document.createElement('input');
        input.type = 'hidden'; input.name = 'ids[]'; input.value = id;
        form.appendChild(input);
    });
    document.getElementById('bulkAction').value = btn.getAttribute('data-bulk');
    const mode = document.getElementById('bulkMode');
    if (mode) mode.value = btn.getAttribute('data-mode') || 'add';
    form.submit();
});

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

// --- EDIT MODAL ---
const editModal = document.getElementById('editModal');
const editForm = document.getElementById('editForm');

function openEditModal(id) {
    const dataEl = document.getElementById('edit-data-' + id);
    if (!dataEl) return;
    let data;
    try { data = JSON.parse(dataEl.textContent); } catch (e) { return; }

    document.getElementById('edit_id').value = data.id;
    document.getElementById('edit_name').value = data.name || '';
    document.getElementById('edit_role').value = data.role || '';
    document.getElementById('edit_email').value = data.email || '';
    document.getElementById('edit_phone').value = data.phone || '';
    const tplSelect = document.getElementById('edit_template');
    if (tplSelect) tplSelect.value = data.template || tplSelect.value;

    document.querySelectorAll('.edit-tag-check').forEach(cb => {
        cb.checked = Array.isArray(data.tagIds) && data.tagIds.includes(parseInt(cb.value, 10));
    });

    const warning = document.getElementById('editLdapWarning');
    if (warning) warning.style.display = (data.source === 'ldap') ? 'block' : 'none';

    editModal.style.display = 'flex';
}
function closeEditModal() { editModal.style.display = 'none'; }

// --- SYNC DETAILS (click on a sync badge) ---
// Values come from a JSON block and are inserted with textContent only.
const syncModal = document.getElementById('syncModal');
function openSyncModal(id) {
    const el = document.getElementById('sync-data-' + id);
    if (!el) return;
    let d;
    try { d = JSON.parse(el.textContent); } catch (e) { return; }
    document.getElementById('syncModalName').textContent = d.name || '';
    const summary = document.getElementById('syncModalSummary');
    summary.textContent = '';
    const badge = document.createElement('span');
    badge.className = 'sync-badge sync-' + (['grey','green','yellow','red'].includes(d.level) ? d.level : 'grey');
    const dot = document.createElement('span'); dot.className = 'sync-dot';
    badge.appendChild(dot); badge.appendChild(document.createTextNode(d.label || ''));
    summary.appendChild(badge);

    const tbody = document.querySelector('#syncModalTable tbody');
    tbody.textContent = '';
    const devices = Array.isArray(d.devices) ? d.devices : [];
    document.getElementById('syncModalEmpty').style.display = devices.length ? 'none' : 'block';
    document.getElementById('syncModalTable').style.display = devices.length ? '' : 'none';
    const stateLevel = { current: 'green', outdated: 'yellow', stale: 'yellow', warn: 'yellow', error: 'red' };
    devices.forEach(dev => {
        const tr = document.createElement('tr');
        const tdDev = document.createElement('td'); tdDev.textContent = dev.device || '';
        const tdState = document.createElement('td');
        const b = document.createElement('span');
        b.className = 'sync-badge sync-' + (stateLevel[dev.state] || 'grey');
        const bd = document.createElement('span'); bd.className = 'sync-dot';
        b.appendChild(bd); b.appendChild(document.createTextNode(dev.label || ''));
        tdState.appendChild(b);
        if (dev.message) { const m = document.createElement('div'); m.className = 'sync-msg'; m.textContent = dev.message; tdState.appendChild(m); }
        const tdTime = document.createElement('td'); tdTime.textContent = dev.time || '';
        const tdVer = document.createElement('td'); tdVer.textContent = dev.version || '–';
        tr.append(tdDev, tdState, tdTime, tdVer);
        tbody.appendChild(tr);
    });
    syncModal.style.display = 'flex';
}
function closeSyncModal() { syncModal.style.display = 'none'; }
window.addEventListener('click', e => { if (e.target == syncModal) closeSyncModal(); });
window.addEventListener('click', e => { if (e.target == editModal) closeEditModal(); });

// --- DELETE ALL ---
function confirmDeleteAll() {
    if(confirm(<?= tj('Delete ALL signatures displayed in this list?') ?> + ' (' + <?php echo (int)$totalSignatures; ?> + ')')) document.getElementById('deleteAllForm').submit();
}

// --- SCROLLING ---
document.addEventListener('DOMContentLoaded', function() {
    let page = 1; let loading = false; let more = true;
    const filterQS = <?php echo json_encode($filterQS); ?>;
    const loader = document.getElementById('infiniteLoader');
    const cont = document.getElementById('signatureListContainer');
    const sentinel = document.getElementById('sentinel');

    if (cont.querySelector('.empty-state')) { more = false; sentinel.style.display = 'none'; }

    const loadMore = () => {
        if (loading || !more) return;
        loading = true; loader.style.display = 'block'; page++;
        fetch(`all_signatures.php?ajax=1&page=${page}&${filterQS}`, {credentials: 'same-origin'})
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
