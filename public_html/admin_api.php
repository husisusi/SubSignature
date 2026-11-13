<?php
/**
 * admin_api.php - management of API tokens for the read-only signature API
 * (api/v1/). Intended for the planned desktop agent (Outlook / Thunderbird).
 *
 * Only the SHA-256 hash of a token is stored. The clear-text token is shown
 * exactly once, right after it was created.
 */
require_once 'includes/config.php';
requireStaff();

$admin_id = (int)$_SESSION['user_id'];
$message = popFlash('success');
$error = popFlash('error');
$new_token = popFlash('new_token');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    requireCsrf();
    $action = $_POST['action'] ?? '';

    if ($action === 'create') {
        $label = cleanText($_POST['label'] ?? '', 80);
        $days = (int)($_POST['expires_days'] ?? 0);
        $rawScopes = is_array($_POST['scope'] ?? null) ? $_POST['scope'] : [];
        $scopes = array_values(array_intersect($rawScopes, array_keys(apiScopeLabels())));
        if ($label === '') {
            setFlash('error', t('Please enter a label (for example the machine or deployment name).'));
        } elseif (!in_array($days, [0, 30, 90, 365], true)) {
            setFlash('error', t('Invalid expiry.'));
        } elseif (!$scopes) {
            setFlash('error', t('Please choose at least one permission.'));
        } else {
            // 256 bits of entropy: a fast hash is sufficient for lookup.
            $token = 'ssg_' . bin2hex(random_bytes(32));
            $stmt = $db->prepare('INSERT INTO api_tokens (label, token_hash, token_prefix, scope, created_by, expires_at) VALUES (?, ?, ?, ?, ?, ?)');
            $stmt->bindValue(1, $label, SQLITE3_TEXT);
            $stmt->bindValue(2, hash('sha256', $token), SQLITE3_TEXT);
            $stmt->bindValue(3, substr($token, 0, 10), SQLITE3_TEXT);
            $stmt->bindValue(4, implode(',', $scopes), SQLITE3_TEXT);
            $stmt->bindValue(5, $admin_id, SQLITE3_INTEGER);
            if ($days > 0) {
                $stmt->bindValue(6, gmdate('Y-m-d H:i:s', time() + $days * 86400), SQLITE3_TEXT);
            } else {
                $stmt->bindValue(6, null, SQLITE3_NULL);
            }
            $stmt->execute();
            logSecurityEventToDB($db, 'API_TOKEN_CREATED', $admin_id, 'Label: ' . $label . ', scope: ' . implode(',', $scopes));
            setFlash('success', t('Token created. Copy it now, it will not be shown again.'));
            setFlash('new_token', $token);
        }
    } elseif ($action === 'revoke' || $action === 'delete') {
        $id = (int)($_POST['token_id'] ?? 0);
        if ($action === 'revoke') {
            $stmt = $db->prepare("UPDATE api_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE id = ? AND revoked_at IS NULL");
        } else {
            $stmt = $db->prepare('DELETE FROM api_tokens WHERE id = ?');
        }
        $stmt->bindValue(1, $id, SQLITE3_INTEGER);
        $stmt->execute();
        if ($db->changes() > 0) {
            logSecurityEventToDB($db, $action === 'revoke' ? 'API_TOKEN_REVOKED' : 'API_TOKEN_DELETED', $admin_id, 'Token ID: ' . $id);
            setFlash('success', $action === 'revoke' ? t('Token revoked.') : t('Token deleted.'));
        }
    }
    header('Location: admin_api.php');
    exit;
}

$tokens = [];
$res = $db->query('SELECT id, label, token_prefix, scope, created_at, expires_at, last_used_at, last_used_ip, revoked_at FROM api_tokens ORDER BY id DESC');
while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
    $tokens[] = $row;
}

$scheme = isHttpsRequest() ? 'https' : 'http';
$host = preg_match('/^[A-Za-z0-9.\-:\[\]]+$/', $_SERVER['HTTP_HOST'] ?? '') ? $_SERVER['HTTP_HOST'] : 'your-server';
$basePath = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/');
$api_url = $scheme . '://' . $host . $basePath . '/api/v1/';
?>
<!DOCTYPE html>
<html lang="<?= e(currentLang()) ?>" dir="<?= e(langDir()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <?php echo csrfMeta(); ?>
    <title><?= et('API Tokens') ?> - SubSignature</title>
    <?= i18nHead() ?>
    <script src="<?= assetUrl('js/theme.js') ?>"></script>
    <link rel="stylesheet" href="<?= assetUrl('css/theme.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/style.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/all.min.css') ?>">
    <style>
        .form-label { display: block; font-size: 0.85rem; font-weight: 600; color: var(--text-muted); margin-bottom: 0.4rem; }
        .form-input { width: 100%; padding: 0.6rem; border: 1px solid var(--border-strong); border-radius: 6px; font-size: 0.95rem; }
        .create-row { display: grid; grid-template-columns: 2fr 1fr auto; gap: 1rem; align-items: end; padding: 1.5rem 1.5rem 0.5rem; }
        .scope-row { display: flex; gap: 1.5rem; flex-wrap: wrap; padding: 0 1.5rem 1.5rem; }
        .scope-check { display: flex; align-items: center; gap: 0.4rem; font-size: 0.9rem; }
        .scope-badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.72rem; font-weight: 600; background: var(--bg-subtle); border: 1px solid var(--border-strong); margin: 1px; white-space: nowrap; }
        .token-box { background: #0f172a; color: #e2e8f0; font-family: monospace; padding: 1rem; border-radius: 8px; word-break: break-all; margin: 1rem 0; user-select: all; }
        .tok-table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
        .tok-table th, .tok-table td { text-align: left; padding: 0.7rem; border-bottom: 1px solid var(--border); }
        .tag { padding: 2px 8px; border-radius: 12px; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; }
        .tag-ok { background: var(--success-bg); color: var(--success-text); }
        .tag-off { background: var(--danger-bg); color: var(--danger-text); }
        .tag-exp { background: var(--warning-bg); color: var(--warning-text); }
        code { background: var(--bg-subtle); padding: 1px 6px; border-radius: 4px; }
    </style>
    <script src="<?= assetUrl('js/post-action.js') ?>" defer></script>
</head>
<body>

    <aside class="sidebar">
        <?php include 'includes/navbar.php'; ?>
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
            <h2><?= et('API Tokens') ?></h2>
            <p><?= et('Access for the SubSignature desktop agent (Outlook / Thunderbird): reading signatures and/or reporting sync status.') ?></p>
        </header>

        <?= flashAlerts($message, $error) ?>

        <?php if ($new_token !== ''): ?>
        <section class="card" style="margin-bottom:1.5rem;">
            <div style="padding:1.5rem;">
                <h3 style="margin-bottom:0.5rem;"><i class="fas fa-key"></i> <?= et('Your new token') ?></h3>
                <p style="color:var(--text-muted);"><?= et('Store it in the agent\'s configuration now. Only a hash is kept on the server.') ?></p>
                <div class="token-box"><?php echo e($new_token); ?></div>
            </div>
        </section>
        <?php endif; ?>

        <section class="card" style="margin-bottom:1.5rem;">
            <div class="card-header"><h3><i class="fas fa-plus-circle"></i> <?= et('Create token') ?></h3></div>
            <form method="POST" action="admin_api.php">
                <?php echo csrfField(); ?>
                <input type="hidden" name="action" value="create">
                <div class="create-row">
                    <div>
                        <label class="form-label" for="label"><?= et('Label') ?></label>
                        <input type="text" id="label" name="label" class="form-input" maxlength="80" required placeholder="<?= et('e.g. Windows rollout') ?>">
                    </div>
                    <div>
                        <label class="form-label" for="expires_days"><?= et('Expires') ?></label>
                        <select id="expires_days" name="expires_days" class="form-input">
                            <option value="90"><?= et('in 90 days') ?></option>
                            <option value="30"><?= et('in 30 days') ?></option>
                            <option value="365"><?= et('in 1 year') ?></option>
                            <option value="0"><?= et('never') ?></option>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-primary"><i class="fas fa-key"></i> <?= et('Generate') ?></button>
                </div>
                <div class="scope-row">
                    <span class="form-label" style="margin:0;"><?= et('Permissions') ?>:</span>
                    <?php foreach (apiScopeLabels() as $value => $label): ?>
                    <label class="scope-check">
                        <input type="checkbox" name="scope[]" value="<?= e($value) ?>" <?= $value === 'signatures:read' ? 'checked' : '' ?>>
                        <?= e($label) ?>
                    </label>
                    <?php endforeach; ?>
                </div>
            </form>
            <p style="padding:0 1.5rem 1.5rem; color:var(--text-muted); font-size:0.85rem;">
                <?= eth('API base URL: {url}.', ['url' => '<code>' . e($api_url) . '</code>']) ?>
                <?= eth('Send the token as {header}. The API is only served over HTTPS.', ['header' => '<code>Authorization: Bearer &lt;token&gt;</code>']) ?>
                <?= et('"Read signatures" lets the agent fetch signature content. "Report sync status" lets it report back whether it applied a signature - it can never change a signature\'s content with this permission. The recommended setup is one token per rollout group with both permissions.') ?>
                <?= eth('See {file}.', ['file' => '<code>docs/API.md</code>']) ?>
            </p>
        </section>

        <section class="card">
            <div class="card-header"><h3><i class="fas fa-list"></i> <?= et('Tokens') ?></h3></div>
            <div style="overflow-x:auto; padding:0 1rem 1rem;">
                <table class="tok-table">
                    <thead><tr><th><?= et('Label') ?></th><th><?= et('Token') ?></th><th><?= et('Scope') ?></th><th><?= et('Created') ?></th><th><?= et('Expires') ?></th><th><?= et('Last used') ?></th><th><?= et('Status') ?></th><th></th></tr></thead>
                    <tbody>
                    <?php if (!$tokens): ?>
                        <tr><td colspan="8" style="text-align:center; color:var(--text-muted);"><?= et('No tokens yet.') ?></td></tr>
                    <?php endif; ?>
                    <?php foreach ($tokens as $t):
                        $expired = $t['expires_at'] && strtotime($t['expires_at'] . ' UTC') < time();
                        $revoked = !empty($t['revoked_at']);
                    ?>
                        <tr>
                            <td><?php echo e($t['label']); ?></td>
                            <td><code><?php echo e($t['token_prefix']); ?>…</code></td>
                            <td><?php foreach (explode(',', $t['scope']) as $s): $s = trim($s); if ($s === '') continue; ?><span class="scope-badge"><?php echo e(apiScopeLabels()[$s] ?? $s); ?></span><?php endforeach; ?></td>
                            <td><?php echo e($t['created_at']); ?></td>
                            <td><?php echo $t['expires_at'] ? e($t['expires_at']) : 'never'; ?></td>
                            <td><?php echo $t['last_used_at'] ? e($t['last_used_at'] . ' (' . $t['last_used_ip'] . ')') : '–'; ?></td>
                            <td>
                                <?php if ($revoked): ?><span class="tag tag-off"><?= et('revoked') ?></span>
                                <?php elseif ($expired): ?><span class="tag tag-exp"><?= et('expired') ?></span>
                                <?php else: ?><span class="tag tag-ok"><?= et('active') ?></span><?php endif; ?>
                            </td>
                            <td style="white-space:nowrap;">
                                <?php if (!$revoked): ?>
                                <button type="button" class="btn btn-secondary btn-sm"
                                        data-post="admin_api.php"
                                        data-params='<?php echo e(json_encode(['action' => 'revoke', 'token_id' => (int)$t['id']])); ?>'
                                        data-confirm="<?= et('Revoke this token? Agents using it lose access immediately.') ?>"><?= et('Revoke') ?></button>
                                <?php endif; ?>
                                <button type="button" class="btn btn-secondary btn-sm"
                                        data-post="admin_api.php"
                                        data-params='<?php echo e(json_encode(['action' => 'delete', 'token_id' => (int)$t['id']])); ?>'
                                        data-confirm="<?= et('Delete this token entry?') ?>"><?= et('Delete') ?></button>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </section>
    </main>
</body>
</html>
