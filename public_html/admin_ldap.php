<?php
/**
 * admin_ldap.php - LDAP / Active Directory IMPORT of signatures (read-only, no LDAP login).
 *
 * Workflow: configure -> test connection -> preview -> choose entries, target user
 * and template -> import. Only signatures are created; no user accounts.
 * Nothing is written before the administrator has seen the preview.
 */
require_once 'includes/config.php';
require_once 'includes/LdapService.php';
require_once 'includes/LdapImporter.php';
require_once 'includes/tag_picker.php';
requireAdmin();

$admin_id = (int)$_SESSION['user_id'];
$ldap_available = function_exists('ldap_connect');
$message = popFlash('success');
$error = popFlash('error');
$importResult = json_decode(popFlash('ldap_result'), true); // summary of the last import (green panel)
if (!is_array($importResult)) $importResult = null;
$plan_token = '';

$cfg = LdapConfig::load($db);

// ---------------------------------------------------------------------
// Plan files (preview results) live in the private tmp directory, bound to
// the administrator that created them, and expire after 30 minutes. They
// contain the validated directory rows only; target user, template and the
// selection are chosen on the preview page.
// ---------------------------------------------------------------------
function ldapPlanPath(string $token): ?string
{
    return preg_match('/^[a-f0-9]{32}$/', $token) ? TMP_DIR . '/ldap_plan_' . $token . '.json' : null;
}

function ldapLoadPlan(string $token, int $adminId): ?array
{
    $path = ldapPlanPath($token);
    if ($path === null || !is_file($path)) {
        return null;
    }
    $data = json_decode((string)file_get_contents($path), true);
    if (!is_array($data) || (int)($data['admin_id'] ?? 0) !== $adminId || time() - (int)($data['created'] ?? 0) > 1800
        || !isset($data['plan']['rows']) || !is_array($data['plan']['rows'])) {
        @unlink($path);
        return null;
    }
    return $data['plan'];
}

/** "3,7,12" -> [3, 7, 12] (one field instead of one input per row: max_input_vars!) */
function ldapParseSelection($raw): array
{
    if (!is_string($raw) || !preg_match('/^\d+(,\d+)*$/', $raw)) {
        return [];
    }
    return array_values(array_unique(array_map('intval', explode(',', $raw))));
}

// Remove abandoned preview files (older than one hour).
foreach (glob(TMP_DIR . '/ldap_plan_*.json') ?: [] as $stale) {
    if (is_file($stale) && time() - (int)filemtime($stale) > 3600) {
        @unlink($stale);
    }
}

// Active users the signatures can be assigned to.
$assignableUsers = [];
$res = $db->query("SELECT id, username, full_name FROM users WHERE is_active = 1 ORDER BY LOWER(COALESCE(NULLIF(full_name, ''), username)), username");
while ($u = $res->fetchArray(SQLITE3_ASSOC)) {
    $assignableUsers[(int)$u['id']] = trim((string)$u['full_name']) !== '' && $u['full_name'] !== $u['username']
        ? $u['full_name'] . ' (' . $u['username'] . ')' : $u['username'];
}

// What the preview page shows (filled by the actions below).
$view = null; // ['rows','counts','truncated','target','template','apply_template','selected']

/** Builds the data for the preview page from stored rows and the chosen settings. */
function ldapBuildView(LdapImporter $importer, array $stored, array $in, array $cfg, int $adminId, ?array $selection): array
{
    $target = $importer->normalizeTarget((string)($in['target'] ?? ''));
    if ($target === null) {
        $target = $importer->normalizeTarget((string)$cfg['target']) ?? (string)$adminId;
    }
    $template = isValidTemplateName($in['template'] ?? '') ? $in['template'] : '';
    $applyTemplate = ($in['apply_template'] ?? '0') === '1';

    $ev = $importer->evaluate($stored['rows'], $target, $template, $applyTemplate);
    if ($selection === null) { // default: everything that would change something
        $selection = [];
        foreach ($ev['rows'] as $r) {
            if ($r['action'] === LdapImporter::ACTION_CREATE || $r['action'] === LdapImporter::ACTION_UPDATE) {
                $selection[] = $r['idx'];
            }
        }
    }
    return [
        'rows' => $ev['rows'], 'counts' => $ev['counts'], 'truncated' => !empty($stored['truncated']),
        'target' => $target, 'template' => $template, 'apply_template' => $applyTemplate, 'selected' => $selection,
        'tag' => resolveImportTagChoice($GLOBALS['db'], $in),
    ];
}

// ---------------------------------------------------------------------
// POST actions
// ---------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    requireCsrf();
    $action = $_POST['action'] ?? '';

    if ($action === 'save') {
        [$newCfg, $errors] = LdapConfig::fromInput($_POST, $cfg['bind_pass']);
        if ($errors) {
            $error = implode(' ', $errors);
            $cfg = $newCfg; // show what was entered
        } else {
            LdapConfig::save($db, $newCfg);
            logSecurityEventToDB($db, 'LDAP_CONFIG_SAVED', $admin_id, 'Host: ' . $newCfg['host']);
            setFlash('success', t('LDAP settings saved.'));
            header('Location: admin_ldap.php');
            exit;
        }
    } elseif (in_array($action, ['test', 'preview'], true)) {
        if (!$ldap_available) {
            $error = t('The PHP "ldap" extension is not installed on this server.');
        } elseif (!checkRateLimit('ldap_run', 20, 600, 'uid:' . $admin_id)) {
            $error = t('Too many LDAP requests. Please wait a few minutes.');
        } elseif ($cfg['host'] === '' || $cfg['base_dn'] === '') {
            $error = t('Please save the connection settings first.');
        } else {
            try {
                $service = new LdapService($cfg);
                $importer = new LdapImporter($db, $cfg);

                if ($action === 'test') {
                    $sample = $service->search($cfg['base_dn'], $cfg['user_filter'], $importer->requestedAttributes(), 5);
                    $message = t('Connection successful. The filter returned entries (sample of up to 5 read: {count}).', ['count' => count($sample)]);
                } else {
                    $stored = $importer->fetchRows($service);
                    $plan_token = bin2hex(random_bytes(16));
                    file_put_contents(ldapPlanPath($plan_token), json_encode([
                        'admin_id' => $admin_id,
                        'created'  => time(),
                        'plan'     => $stored,
                    ], JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX);
                    @chmod(ldapPlanPath($plan_token), 0600);
                    $view = ldapBuildView($importer, $stored, [], $cfg, $admin_id, null);
                    logSecurityEventToDB($db, 'LDAP_PREVIEW', $admin_id, 'Entries: ' . $view['counts']['total']);
                }
            } catch (Exception $e) {
                error_log(t('LDAP error: {message}', ['message' => $e->getMessage()]));
                $error = 'LDAP error: ' . $e->getMessage();
            }
        }
    } elseif ($action === 'retarget' || $action === 'apply') {
        // Both work on the stored preview rows; the directory is not queried again.
        $plan_token = (string)($_POST['plan_token'] ?? '');
        $stored = ldapLoadPlan($plan_token, $admin_id);
        if ($stored === null) {
            setFlash('error', t('The preview has expired. Please run the preview again.'));
            header('Location: admin_ldap.php');
            exit;
        }
        $importer = new LdapImporter($db, $cfg);
        $selection = ldapParseSelection($_POST['selected'] ?? '');
        $view = ldapBuildView($importer, $stored, $_POST, $cfg, $admin_id, $selection);

        if ($action === 'apply') {
            // Only rows that are really importable can be selected.
            $importable = [];
            foreach ($view['rows'] as $r) {
                if ($r['action'] !== LdapImporter::ACTION_SKIP) {
                    $importable[$r['idx']] = true;
                }
            }
            $selection = array_values(array_filter($selection, function ($i) use ($importable) { return isset($importable[$i]); }));
            $view['selected'] = $selection;

            if ($view['tag']['error'] !== '') {
                $error = $view['tag']['error'];
            } elseif (!$selection) {
                $error = t('No entries selected.');
            } else {
                try {
                    $tagId = applyImportTagChoice($db, $view['tag']);
                    $result = $importer->applyPlan($stored['rows'], $view['target'], $view['template'], $view['apply_template'], $selection, $tagId);
                    @unlink(ldapPlanPath($plan_token));
                    logSecurityEventToDB($db, 'LDAP_IMPORT', $admin_id, json_encode($result + ['target' => $view['target'], 'tag' => $tagId]));
                    setFlash('ldap_result', json_encode($result + ['tag_name' => importTagName($db, $tagId)], JSON_UNESCAPED_UNICODE));
                    header('Location: admin_ldap.php');
                    exit;
                } catch (Exception $e) {
                    error_log('LDAP import failed: ' . $e->getMessage());
                    $error = t('The import failed and was rolled back. See the PHP error log.');
                }
            }
        }
    } elseif ($action === 'cancel') {
        $path = ldapPlanPath((string)($_POST['plan_token'] ?? ''));
        if ($path !== null && is_file($path)) {
            @unlink($path);
        }
        header('Location: admin_ldap.php');
        exit;
    }
}

$templates = listSignatureTemplates();
$presetsJson = json_encode(LdapConfig::PRESETS, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
?>
<!DOCTYPE html>
<html lang="<?= e(currentLang()) ?>" dir="<?= e(langDir()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= et('LDAP Import') ?> - SubSignature</title>
    <?= i18nHead() ?>
    <script src="<?= assetUrl('js/theme.js') ?>"></script>
    <link rel="stylesheet" href="<?= assetUrl('css/theme.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/style.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/all.min.css') ?>">
    <style>
        .config-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(380px, 1fr)); gap: 1.5rem; }
        .config-card { background: var(--bg-white); border: 1px solid var(--border); border-radius: 12px; padding: 2rem; }
        .config-card h3 { font-size: 1.1rem; margin-bottom: 1.5rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem; }
        .config-item { display: flex; justify-content: space-between; align-items: center; padding: 0.9rem 0; border-bottom: 1px solid var(--border); gap: 1rem; }
        .config-item:last-child { border-bottom: none; }
        .form-group-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem; }
        .form-label { display: block; font-size: 0.85rem; font-weight: 600; color: var(--text-muted); margin-bottom: 0.4rem; }
        .form-input { width: 100%; padding: 0.6rem; border: 1px solid var(--border-strong); border-radius: 6px; font-size: 0.95rem; }
        .form-hint { color: var(--text-muted); font-size: 0.78rem; margin-top: 0.25rem; display: block; }
        .switch { position: relative; display: inline-block; width: 40px; height: 22px; flex-shrink: 0; }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: var(--border-strong); transition: .4s; border-radius: 34px; }
        .slider:before { position: absolute; content: ""; height: 16px; width: 16px; left: 3px; bottom: 3px; background-color: var(--bg-white); transition: .4s; border-radius: 50%; }
        input:checked + .slider { background-color: var(--primary); }
        input:checked + .slider:before { transform: translateX(18px); }
        .actions-row { display: flex; gap: 0.75rem; flex-wrap: wrap; margin-top: 1.5rem; }
        .stat-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
        .stat-box { background: var(--bg-subtle); border: 1px solid var(--border); border-radius: 10px; padding: 1rem; text-align: center; }
        .stat-box strong { display: block; font-size: 1.6rem; }
        .stat-box span { font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; }
        .plan-table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
        .plan-table th, .plan-table td { text-align: left; padding: 0.55rem 0.7rem; border-bottom: 1px solid var(--border); }
        .tag { padding: 2px 8px; border-radius: 12px; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; }
        .tag-create { background: var(--success-bg); color: var(--success-text); }
        .tag-update { background: var(--info-bg); color: var(--info-text); }
        .tag-unchanged { background: var(--bg-subtle); color: var(--text-muted); }
        .tag-skip { background: var(--danger-bg); color: var(--danger-text); }
        .plan-toolbar { display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; margin: 1rem 0 0.75rem; }
        .btn-sm { padding: 0.4rem 0.8rem; font-size: 0.82rem; }
        .alert { padding: 1rem 1.25rem; border-radius: 10px; margin-bottom: 1.5rem; display: flex; gap: 0.75rem; align-items: center; }
        .alert-success { background: var(--success-bg); color: var(--success-text); border: 1px solid var(--success-border); }
        .alert-error { background: var(--danger-bg); color: var(--danger-text); border: 1px solid var(--danger-border); }
        .import-success { background: var(--success-bg); border: 1px solid var(--success-border); border-radius: 12px; padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; }
        .import-success h3 { color: var(--success-text); font-size: 1.15rem; display: flex; gap: 0.6rem; align-items: center; margin: 0 0 1rem; }
        .import-success .stat-box { background: var(--bg-white); }
        .import-success a { color: var(--success-text); font-weight: 600; }
        .import-success p { margin: 0.75rem 0 0; color: var(--success-text); font-size: 0.88rem; }
        .plan-table th .sort-btn { background: none; border: none; font: inherit; font-weight: 700; color: inherit; cursor: pointer; padding: 0; display: inline-flex; gap: 0.35rem; align-items: center; }
        .plan-table th .sort-btn:hover { color: var(--primary); }
        .plan-table th .sort-ind { font-size: 0.7rem; opacity: 0.35; }
        .plan-table th[aria-sort] .sort-ind { opacity: 1; color: var(--primary); }
        .tag-picker { display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; }
        .tag-picker .form-input { width: auto; min-width: 150px; }
        .warn-box { background: var(--warning-bg); border: 1px solid var(--warning-border); color: var(--warning-text); padding: 0.9rem 1rem; border-radius: 8px; margin-bottom: 1.5rem; font-size: 0.9rem; }
    </style>
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
                    <span><?= et('Administrator') ?></span>
                </div>
            </div>
            <a href="logout.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> <span><?= et('Sign Out') ?></span></a>
        </div>
    </aside>

    <main class="main-content">
        <header class="page-header">
            <h2><?= et('LDAP / Active Directory Import') ?></h2>
            <p><?= et('Create signatures from your directory data (name, role, email, phone) and assign them to a user. No user accounts are created.') ?></p>
        </header>

        <?php if ($importResult !== null): ?>
            <div class="import-success" role="status">
                <h3><i class="fas fa-check-circle"></i> <?= et('Import successful') ?></h3>
                <div class="stat-row" style="margin-bottom:0;">
                    <div class="stat-box"><strong style="color:var(--success-text);"><?php echo (int)($importResult['created'] ?? 0); ?></strong><span><?= et('Signatures created') ?></span></div>
                    <div class="stat-box"><strong style="color:var(--info-text);"><?php echo (int)($importResult['updated'] ?? 0); ?></strong><span><?= et('Updated') ?></span></div>
                    <div class="stat-box"><strong><?php echo (int)($importResult['unchanged'] ?? 0); ?></strong><span><?= et('Unchanged') ?></span></div>
                    <?php if ((string)($importResult['tag_name'] ?? '') !== ''): ?>
                    <div class="stat-box"><strong><?php echo (int)($importResult['tagged'] ?? 0); ?></strong><span><?= et('Tagged') ?>: <?php echo e((string)$importResult['tag_name']); ?></span></div>
                    <?php endif; ?>
                </div>
                <p><a href="all_signatures.php?source=ldap"><i class="fas fa-list-ul"></i> <?= et('View Signatures') ?></a></p>
            </div>
        <?php endif; ?>
        <?php if ($message): ?>
            <div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo e($message); ?></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="alert alert-error"><i class="fas fa-exclamation-circle"></i> <?php echo e($error); ?></div>
        <?php endif; ?>
        <?php if (!$ldap_available): ?>
            <div class="warn-box"><i class="fas fa-exclamation-triangle"></i>
                <?= eth('The PHP {ext} extension is not installed. You can edit and save the settings, but test and import are disabled (Debian/Ubuntu: {cmd}).', ['ext' => '<code>ldap</code>', 'cmd' => '<code>apt install php-ldap</code>']) ?>
            </div>
        <?php endif; ?>

        <?php if ($view !== null): ?>
        <section class="card" style="margin-bottom:1.5rem;">
            <div class="card-header"><h3><i class="fas fa-clipboard-list"></i> <?= et('Import Preview') ?></h3></div>
            <div style="padding:1.5rem;">
                <div class="stat-row">
                    <div class="stat-box"><strong><?php echo (int)$view['counts']['total']; ?></strong><span><?= et('Directory entries') ?></span></div>
                    <div class="stat-box"><strong style="color:var(--success-text);"><?php echo (int)$view['counts']['create']; ?></strong><span><?= et('New signatures') ?></span></div>
                    <div class="stat-box"><strong style="color:var(--info-text);"><?php echo (int)$view['counts']['update']; ?></strong><span><?= et('To update') ?></span></div>
                    <div class="stat-box"><strong><?php echo (int)$view['counts']['unchanged']; ?></strong><span><?= et('Unchanged') ?></span></div>
                    <div class="stat-box"><strong style="color:var(--danger-text);"><?php echo (int)$view['counts']['skip']; ?></strong><span><?= et('Skipped') ?></span></div>
                </div>

                <?php if ($view['truncated']): ?>
                    <div class="warn-box"><?= et('Only the first {max} directory entries are shown. Narrow the user filter or the base DN to reach the others.', ['max' => LdapImporter::MAX_ENTRIES]) ?></div>
                <?php endif; ?>

                <form method="POST" action="admin_ldap.php" id="planForm">
                    <?php echo csrfField(); ?>
                    <input type="hidden" name="plan_token" value="<?php echo e($plan_token); ?>">
                    <input type="hidden" name="selected" id="selectedField" value="">

                    <div class="form-group-grid" style="align-items:start;">
                        <div>
                            <label class="form-label" for="planTarget"><?= et('Assign signatures to') ?></label>
                            <select name="target" id="planTarget" class="form-input">
                                <option value="auto" <?php echo $view['target'] === 'auto' ? 'selected' : ''; ?>><?= et('Automatically by email address') ?></option>
                                <?php foreach ($assignableUsers as $uid => $label): ?>
                                    <option value="<?php echo (int)$uid; ?>" <?php echo $view['target'] === (string)$uid ? 'selected' : ''; ?>><?php echo e($label); ?></option>
                                <?php endforeach; ?>
                            </select>
                            <span class="form-hint"><?= et('Automatic: each signature goes to the user with the same email address; entries without a matching user are skipped.') ?></span>
                        </div>
                        <div>
                            <label class="form-label" for="planTemplate"><?= et('Template') ?></label>
                            <select name="template" id="planTemplate" class="form-input">
                                <option value=""><?= et('System default') ?></option>
                                <?php foreach ($templates as $t): ?>
                                    <option value="<?php echo e($t); ?>" <?php echo $view['template'] === $t ? 'selected' : ''; ?>><?php echo e(templateDisplayName($t)); ?></option>
                                <?php endforeach; ?>
                            </select>
                            <label style="display:flex; gap:0.5rem; align-items:center; margin-top:0.5rem; font-size:0.85rem;">
                                <input type="hidden" name="apply_template" value="0">
                                <input type="checkbox" name="apply_template" value="1" id="planApplyTemplate" <?php echo $view['apply_template'] ? 'checked' : ''; ?>>
                                <?= et('Also apply the template to signatures that already exist') ?>
                            </label>
                        </div>
                    </div>

                    <div style="margin-bottom:1rem;">
                        <label class="form-label"><?= et('Tag for imported signatures') ?></label>
                        <?php echo renderTagPicker($db, $view['tag'], 'form-input'); ?>
                        <span class="form-hint"><?= et('Optional. Put a tag on every imported signature so you can filter them later.') ?></span>
                    </div>

                    <div class="plan-toolbar">
                        <input type="search" id="planFilter" class="form-input" style="max-width:260px;" placeholder="<?= et('Filter by name or email') ?>" autocomplete="off">
                        <button type="button" class="btn btn-secondary btn-sm" data-select="all"><?= et('Select all') ?></button>
                        <button type="button" class="btn btn-secondary btn-sm" data-select="changes"><?= et('Only new and changed') ?></button>
                        <button type="button" class="btn btn-secondary btn-sm" data-select="none"><?= et('Select none') ?></button>
                        <span class="form-hint" id="selectedCount" style="margin:0 0 0 auto;"></span>
                    </div>

                    <div style="overflow-x:auto; max-height:460px; overflow-y:auto;">
                        <table class="plan-table" id="planTable">
                            <thead><tr>
                                <th style="width:34px;"></th><th aria-sort="none" data-col="1"><button type="button" class="sort-btn" data-sort-col="1"><?= et('Status') ?> <span class="sort-ind" aria-hidden="true">&#8693;</span></button></th><th aria-sort="none" data-col="2"><button type="button" class="sort-btn" data-sort-col="2"><?= et('Name') ?> <span class="sort-ind" aria-hidden="true">&#8693;</span></button></th><th aria-sort="none" data-col="3"><button type="button" class="sort-btn" data-sort-col="3"><?= et('Email') ?> <span class="sort-ind" aria-hidden="true">&#8693;</span></button></th><th aria-sort="none" data-col="4"><button type="button" class="sort-btn" data-sort-col="4"><?= et('Role') ?> <span class="sort-ind" aria-hidden="true">&#8693;</span></button></th><th aria-sort="none" data-col="5"><button type="button" class="sort-btn" data-sort-col="5"><?= et('Phone') ?> <span class="sort-ind" aria-hidden="true">&#8693;</span></button></th><th aria-sort="none" data-col="6"><button type="button" class="sort-btn" data-sort-col="6"><?= et('Assigned to') ?> <span class="sort-ind" aria-hidden="true">&#8693;</span></button></th><th><?= et('Note') ?></th>
                            </tr></thead>
                            <tbody>
                            <?php
                                $selectedSet = array_flip($view['selected']);
                                $actionLabel = [
                                    'create' => t('New'), 'update' => t('To update'), 'unchanged' => t('Unchanged'), 'skip' => t('Skipped'),
                                ];
                            ?>
                            <?php foreach ($view['rows'] as $r): ?>
                                <tr data-idx="<?php echo (int)$r['idx']; ?>" data-action="<?php echo e($r['action']); ?>"
                                    data-search="<?php echo e(mb_strtolower($r['name'] . ' ' . $r['email'] . ' ' . $r['username'], 'UTF-8')); ?>">
                                    <td><input type="checkbox" class="row-check" <?php echo $r['action'] === 'skip' ? 'disabled' : (isset($selectedSet[$r['idx']]) ? 'checked' : ''); ?> aria-label="<?= et('Select') ?>"></td>
                                    <td><span class="tag tag-<?php echo e($r['action']); ?>"><?php echo e($actionLabel[$r['action']] ?? $r['action']); ?></span></td>
                                    <td><?php echo e($r['name']); ?></td>
                                    <td dir="ltr" style="text-align:start;"><?php echo e($r['email']); ?></td>
                                    <td><?php echo e($r['role']); ?></td>
                                    <td dir="ltr" style="text-align:start;"><?php echo e($r['phone']); ?></td>
                                    <td><?php echo e($r['user']); ?></td>
                                    <td style="color:var(--danger-text);"><?php echo e($r['reason']); ?></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>

                    <div class="actions-row">
                        <button type="submit" name="action" value="apply" class="btn btn-primary" id="applyBtn"
                                data-confirm="<?= et('Import the selected signatures now?') ?>"><i class="fas fa-check"></i> <?= et('Import selected') ?></button>
                        <button type="submit" name="action" value="retarget" class="btn btn-secondary"><i class="fas fa-sync-alt"></i> <?= et('Update preview') ?></button>
                        <button type="submit" name="action" value="cancel" class="btn btn-secondary"><?= et('Cancel') ?></button>
                    </div>
                </form>
            </div>
        </section>
        <?php endif; ?>

        <form method="POST" action="admin_ldap.php" id="ldapForm">
            <?php echo csrfField(); ?>

            <div class="config-grid">
                <section class="config-card">
                    <h3><i class="fas fa-network-wired"></i> <?= et('Connection') ?></h3>

                    <div class="form-group-grid">
                        <div>
                            <label class="form-label" for="preset"><?= et('Directory type') ?></label>
                            <select name="preset" id="preset" class="form-input">
                                <?php foreach (LdapConfig::PRESETS as $key => $p): ?>
                                    <option value="<?php echo e($key); ?>" <?php echo $cfg['preset'] === $key ? 'selected' : ''; ?>><?php echo e($p['label']); ?></option>
                                <?php endforeach; ?>
                                <option value="custom" <?php echo $cfg['preset'] === 'custom' ? 'selected' : ''; ?>><?= et('Custom') ?></option>
                            </select>
                        </div>
                        <div>
                            <label class="form-label" for="encryption"><?= et('Encryption') ?></label>
                            <select name="encryption" id="encryption" class="form-input">
                                <option value="ldaps" <?php echo $cfg['encryption'] === 'ldaps' ? 'selected' : ''; ?>><?= et('LDAPS (TLS, recommended)') ?></option>
                                <option value="starttls" <?php echo $cfg['encryption'] === 'starttls' ? 'selected' : ''; ?>>STARTTLS</option>
                                <option value="none" <?php echo $cfg['encryption'] === 'none' ? 'selected' : ''; ?>><?= et('None (not recommended)') ?></option>
                            </select>
                        </div>
                    </div>

                    <div class="form-group-grid">
                        <div>
                            <label class="form-label" for="host"><?= et('Host') ?></label>
                            <input type="text" name="host" id="host" class="form-input" placeholder="<?= et('dc01.example.com') ?>" maxlength="255" value="<?php echo e($cfg['host']); ?>">
                        </div>
                        <div>
                            <label class="form-label" for="port"><?= et('Port') ?></label>
                            <input type="number" name="port" id="port" class="form-input" min="1" max="65535" value="<?php echo (int)$cfg['port']; ?>">
                        </div>
                    </div>

                    <div class="form-group-grid">
                        <div>
                            <label class="form-label" for="verify_cert"><?= et('Server certificate') ?></label>
                            <select name="verify_cert" id="verify_cert" class="form-input">
                                <option value="1" <?php echo $cfg['verify_cert'] ? 'selected' : ''; ?>><?= et('Verify (recommended)') ?></option>
                                <option value="0" <?php echo !$cfg['verify_cert'] ? 'selected' : ''; ?>><?= et('Do not verify (insecure)') ?></option>
                            </select>
                        </div>
                        <div>
                            <label class="form-label" for="ca_file"><?= et('CA file (optional)') ?></label>
                            <input type="text" name="ca_file" id="ca_file" class="form-input" placeholder="<?= et('/etc/ssl/certs/corp-ca.pem') ?>" maxlength="255" value="<?php echo e($cfg['ca_file']); ?>">
                        </div>
                    </div>

                    <div class="form-group-grid">
                        <div>
                            <label class="form-label" for="bind_dn"><?= et('Bind DN / user principal') ?></label>
                            <input type="text" name="bind_dn" id="bind_dn" class="form-input" autocomplete="off" placeholder="svc-subsig@example.com" maxlength="512" value="<?php echo e($cfg['bind_dn']); ?>">
                        </div>
                        <div>
                            <label class="form-label" for="bind_pass"><?= et('Bind password') ?></label>
                            <input type="password" name="bind_pass" id="bind_pass" class="form-input" autocomplete="new-password"
                                   placeholder="<?php echo $cfg['bind_pass'] !== '' ? '•••••••• (unchanged)' : ''; ?>">
                        </div>
                    </div>
                    <span class="form-hint"><?= et('Use a read-only service account. The password is stored encrypted.') ?></span>

                    <div style="margin-top:1rem;">
                        <label class="form-label" for="base_dn"><?= et('Base DN') ?></label>
                        <input type="text" name="base_dn" id="base_dn" class="form-input" placeholder="<?= et('OU=Staff,DC=example,DC=com') ?>" maxlength="512" value="<?php echo e($cfg['base_dn']); ?>">
                    </div>
                </section>

                <section class="config-card">
                    <h3><i class="fas fa-filter"></i> <?= et('Search & attribute mapping') ?></h3>

                    <div style="margin-bottom:1rem;">
                        <label class="form-label" for="user_filter"><?= et('User filter') ?></label>
                        <input type="text" name="user_filter" id="user_filter" class="form-input" maxlength="2000" value="<?php echo e($cfg['user_filter']); ?>">
                        <span class="form-hint"><?= et('The default for Active Directory skips disabled accounts.') ?></span>
                    </div>

                    <div class="form-group-grid">
                        <div>
                            <label class="form-label" for="attr_username"><?= et('Username attribute') ?></label>
                            <input type="text" name="attr_username" id="attr_username" class="form-input" maxlength="70" value="<?php echo e($cfg['attr_username']); ?>">
                        </div>
                        <div>
                            <label class="form-label" for="attr_email"><?= et('Email attribute') ?></label>
                            <input type="text" name="attr_email" id="attr_email" class="form-input" maxlength="70" value="<?php echo e($cfg['attr_email']); ?>">
                        </div>
                        <div>
                            <label class="form-label" for="attr_name"><?= et('Full name attribute') ?></label>
                            <input type="text" name="attr_name" id="attr_name" class="form-input" maxlength="70" value="<?php echo e($cfg['attr_name']); ?>">
                        </div>
                        <div>
                            <label class="form-label" for="attr_id"><?= et('Unique ID attribute') ?></label>
                            <input type="text" name="attr_id" id="attr_id" class="form-input" maxlength="70" value="<?php echo e($cfg['attr_id']); ?>">
                        </div>
                        <div>
                            <label class="form-label" for="attr_role"><?= et('Role / title attribute') ?></label>
                            <input type="text" name="attr_role" id="attr_role" class="form-input" maxlength="70" placeholder="<?= et('title') ?>" value="<?php echo e($cfg['attr_role']); ?>">
                        </div>
                        <div>
                            <label class="form-label" for="attr_phone"><?= et('Phone attribute') ?></label>
                            <input type="text" name="attr_phone" id="attr_phone" class="form-input" maxlength="70" placeholder="<?= et('telephoneNumber') ?>" value="<?php echo e($cfg['attr_phone']); ?>">
                        </div>
                    </div>
                    <span class="form-hint"><?= eth('Any directory attribute can be mapped (e.g. {examples}). The unique ID keeps imported signatures linked to their directory entry (the DN is used if it is empty).', ['examples' => '<code>mobile</code>, <code>department</code>, <code>co</code>']) ?></span>
                </section>

                <section class="config-card">
                    <h3><i class="fas fa-sliders-h"></i> <?= et('Import options') ?></h3>

                    <div class="config-item">
                        <div>
                            <h4 style="margin:0; font-size:0.95rem;"><?= et('Assign signatures to') ?></h4>
                            <p style="margin:0; color:var(--text-muted); font-size:0.8rem;"><?= et('Preselected in the preview, where it can be changed.') ?></p>
                        </div>
                        <select name="target" class="form-input" style="max-width:240px;">
                            <option value="auto" <?php echo $cfg['target'] === 'auto' ? 'selected' : ''; ?>><?= et('Automatically by email address') ?></option>
                            <?php foreach ($assignableUsers as $uid => $label): ?>
                                <option value="<?php echo (int)$uid; ?>" <?php echo ($cfg['target'] === (string)$uid || ($cfg['target'] === '' && $uid === $admin_id)) ? 'selected' : ''; ?>><?php echo e($label); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div class="config-item">
                        <div>
                            <h4 style="margin:0; font-size:0.95rem;"><?= et('Template for new signatures') ?></h4>
                        </div>
                        <select name="template" class="form-input" style="max-width:240px;">
                            <option value=""><?= et('System default') ?></option>
                            <?php foreach ($templates as $t): ?>
                                <option value="<?php echo e($t); ?>" <?php echo $cfg['template'] === $t ? 'selected' : ''; ?>><?php echo e(templateDisplayName($t)); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <p class="form-hint" style="margin-top:1rem;">
                        <?= et('Signatures that were created manually are never changed. Imported signatures are recognised by their directory ID and updated on the next import.') ?>
                    </p>
                </section>
            </div>

            <div class="actions-row">
                <button type="submit" name="action" value="save" class="btn btn-primary"><i class="fas fa-save"></i> <?= et('Save settings') ?></button>
                <button type="submit" name="action" value="test" class="btn btn-secondary" <?php echo $ldap_available ? '' : 'disabled'; ?>><i class="fas fa-plug"></i> <?= et('Test connection') ?></button>
                <button type="submit" name="action" value="preview" class="btn btn-success" <?php echo $ldap_available ? '' : 'disabled'; ?>><i class="fas fa-search"></i> <?= et('Preview import') ?></button>
            </div>
            <span class="form-hint"><?= eth('Test and preview use the {saved} settings. Save first after making changes.', ['saved' => '<em>' . et('saved') . '</em>']) ?></span>
        </form>
    </main>

    <script>
        (function () {
            var presets = <?php echo $presetsJson; ?>;
            var map = {
                user_filter: 'user_filter', attr_username: 'attr_username', attr_email: 'attr_email',
                attr_name: 'attr_name', attr_role: 'attr_role', attr_phone: 'attr_phone', attr_id: 'attr_id'
            };

            // Selecting a directory type fills filter and attribute names.
            document.getElementById('preset').addEventListener('change', function () {
                var p = presets[this.value];
                if (!p) { return; }
                Object.keys(map).forEach(function (key) {
                    var el = document.getElementById(map[key]);
                    if (el && p[key] !== undefined) { el.value = p[key]; }
                });
            });

            // Typical port per encryption mode (only if the port still has the other default).
            document.getElementById('encryption').addEventListener('change', function () {
                var port = document.getElementById('port');
                if (this.value === 'ldaps' && port.value === '389') { port.value = '636'; }
                if (this.value !== 'ldaps' && port.value === '636') { port.value = '389'; }
            });


            // ---- Preview: selection, filter, assignment --------------------
            var planForm = document.getElementById('planForm');
            if (planForm) {
                var rows = Array.prototype.slice.call(document.querySelectorAll('#planTable tbody tr'));
                var counter = document.getElementById('selectedCount');
                var field = document.getElementById('selectedField');
                var tplLabel = <?= tj('{selected} of {total} selected') ?>;

                function checks() { return rows.map(function (r) { return r.querySelector('.row-check'); }); }
                function refresh() {
                    var n = 0, ids = [];
                    rows.forEach(function (r) {
                        var c = r.querySelector('.row-check');
                        if (c && c.checked && !c.disabled) { n++; ids.push(r.getAttribute('data-idx')); }
                    });
                    field.value = ids.join(',');
                    counter.textContent = tplLabel.replace('{selected}', n).replace('{total}', rows.length);
                }
                function visible(r) { return r.style.display !== 'none'; }

                planForm.addEventListener('change', function (e) {
                    if (e.target.classList.contains('row-check')) { refresh(); }
                });
                planForm.querySelectorAll('[data-select]').forEach(function (btn) {
                    btn.addEventListener('click', function () {
                        var mode = btn.getAttribute('data-select');
                        rows.forEach(function (r) {
                            var c = r.querySelector('.row-check');
                            if (!c || c.disabled || !visible(r)) { return; }
                            var a = r.getAttribute('data-action');
                            c.checked = mode === 'all' ? true : (mode === 'none' ? false : (a === 'create' || a === 'update'));
                        });
                        refresh();
                    });
                });
                document.getElementById('planFilter').addEventListener('input', function () {
                    var q = this.value.trim().toLowerCase();
                    rows.forEach(function (r) {
                        r.style.display = (q === '' || r.getAttribute('data-search').indexOf(q) !== -1) ? '' : 'none';
                    });
                });
                // The status column depends on the target user and template: re-evaluate on change.
                ['planTarget', 'planTemplate', 'planApplyTemplate'].forEach(function (id) {
                    document.getElementById(id).addEventListener('change', function () {
                        refresh();
                        var h = document.createElement('input');
                        h.type = 'hidden'; h.name = 'action'; h.value = 'retarget';
                        planForm.appendChild(h);
                        planForm.submit();
                    });
                });
                planForm.addEventListener('submit', refresh);
                refresh();

                // Sortable columns (client side; row selection is tied to data-idx and survives sorting).
                var table = document.getElementById('planTable');
                var tbody = table.querySelector('tbody');
                var statusOrder = { create: 0, update: 1, unchanged: 2, skip: 3 };
                var collator = (window.Intl && Intl.Collator) ? new Intl.Collator(document.documentElement.lang || undefined, { numeric: true, sensitivity: 'base' }) : null;
                function cellValue(tr, col) {
                    if (col === 1) { var a = tr.getAttribute('data-action'); return statusOrder.hasOwnProperty(a) ? statusOrder[a] : 9; }
                    return (tr.cells[col].textContent || '').trim();
                }
                table.querySelectorAll('[data-sort-col]').forEach(function (btn) {
                    btn.addEventListener('click', function () {
                        var col = parseInt(btn.getAttribute('data-sort-col'), 10);
                        var th = btn.closest('th');
                        var dir = th.getAttribute('aria-sort') === 'ascending' ? -1 : 1;
                        table.querySelectorAll('th[data-col]').forEach(function (h) {
                            h.setAttribute('aria-sort', 'none');
                            h.querySelector('.sort-ind').innerHTML = '&#8693;';
                        });
                        th.setAttribute('aria-sort', dir === 1 ? 'ascending' : 'descending');
                        th.querySelector('.sort-ind').innerHTML = dir === 1 ? '&#9650;' : '&#9660;';
                        var list = Array.prototype.slice.call(tbody.rows);
                        var keyed = list.map(function (tr, i) { return { tr: tr, v: cellValue(tr, col), i: i }; });
                        keyed.sort(function (x, y) {
                            var c;
                            if (typeof x.v === 'number' && typeof y.v === 'number') { c = x.v - y.v; }
                            else if (x.v === '' && y.v !== '') { return 1; }   // empty values always last
                            else if (y.v === '' && x.v !== '') { return -1; }
                            else { c = collator ? collator.compare(String(x.v), String(y.v)) : String(x.v).localeCompare(String(y.v)); }
                            return c !== 0 ? c * dir : x.i - y.i;
                        });
                        keyed.forEach(function (k) { tbody.appendChild(k.tr); });
                    });
                });
            }

            // Confirmation for buttons with data-confirm inside forms.
            document.querySelectorAll('button[data-confirm]').forEach(function (btn) {
                btn.addEventListener('click', function (event) {
                    if (!window.confirm(btn.getAttribute('data-confirm'))) { event.preventDefault(); }
                });
            });
        })();
    </script>
</body>
</html>
