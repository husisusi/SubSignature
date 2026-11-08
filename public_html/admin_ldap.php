<?php
/**
 * admin_ldap.php - LDAP / Active Directory IMPORT (read-only, no LDAP login).
 *
 * Workflow: configure -> test connection -> preview -> confirm import.
 * Nothing is written before the administrator has seen the preview.
 */
require_once 'includes/config.php';
require_once 'includes/LdapService.php';
require_once 'includes/LdapImporter.php';
requireAdmin();

$admin_id = (int)$_SESSION['user_id'];
$ldap_available = function_exists('ldap_connect');
$message = popFlash('success');
$error = popFlash('error');
$plan = null;
$plan_token = '';

$cfg = LdapConfig::load($db);

// ---------------------------------------------------------------------
// Plan files (preview results) live in the private tmp directory, bound to
// the administrator that created them, and expire after 30 minutes.
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
    if (!is_array($data) || (int)($data['admin_id'] ?? 0) !== $adminId || time() - (int)($data['created'] ?? 0) > 1800) {
        @unlink($path);
        return null;
    }
    return $data['plan'] ?? null;
}

// Remove abandoned preview files (older than one hour).
foreach (glob(TMP_DIR . '/ldap_plan_*.json') ?: [] as $stale) {
    if (is_file($stale) && time() - (int)filemtime($stale) > 3600) {
        @unlink($stale);
    }
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
            setFlash('success', 'LDAP settings saved.');
            header('Location: admin_ldap.php');
            exit;
        }
    } elseif (in_array($action, ['test', 'preview'], true)) {
        if (!$ldap_available) {
            $error = 'The PHP "ldap" extension is not installed on this server.';
        } elseif (!checkRateLimit('ldap_run', 20, 600, 'uid:' . $admin_id)) {
            $error = 'Too many LDAP requests. Please wait a few minutes.';
        } elseif ($cfg['host'] === '' || $cfg['base_dn'] === '') {
            $error = 'Please save the connection settings first.';
        } else {
            try {
                $service = new LdapService($cfg);
                $importer = new LdapImporter($db, $cfg);

                if ($action === 'test') {
                    $sample = $service->search($cfg['base_dn'], $cfg['user_filter'], $importer->requestedAttributes(), 5);
                    $message = 'Connection successful. The filter returned entries (sample of up to 5 read: ' . count($sample) . ').';
                } else {
                    $plan = $importer->buildPlan($service);
                    $plan_token = bin2hex(random_bytes(16));
                    file_put_contents(ldapPlanPath($plan_token), json_encode([
                        'admin_id' => $admin_id,
                        'created'  => time(),
                        'plan'     => $plan,
                    ], JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX);
                    @chmod(ldapPlanPath($plan_token), 0600);
                    logSecurityEventToDB($db, 'LDAP_PREVIEW', $admin_id, 'Entries: ' . $plan['counts']['total']);
                }
            } catch (Exception $e) {
                error_log('LDAP error: ' . $e->getMessage());
                $error = 'LDAP error: ' . $e->getMessage();
            }
        }
    } elseif ($action === 'apply') {
        $token = (string)($_POST['plan_token'] ?? '');
        $stored = ldapLoadPlan($token, $admin_id);
        if ($stored === null) {
            setFlash('error', 'The preview has expired. Please run the preview again.');
        } else {
            try {
                $importer = new LdapImporter($db, $cfg);
                $result = $importer->applyPlan($stored);
                @unlink(ldapPlanPath($token));
                logSecurityEventToDB($db, 'LDAP_IMPORT', $admin_id, json_encode($result));
                setFlash('success', sprintf(
                    'Import finished: %d created, %d updated, %d signatures written, %d deactivated, %d skipped.',
                    $result['created'], $result['updated'], $result['signatures'], $result['deactivated'], $result['skipped']
                ));
            } catch (Exception $e) {
                error_log('LDAP import failed: ' . $e->getMessage());
                setFlash('error', 'The import failed and was rolled back. See the PHP error log.');
            }
        }
        header('Location: admin_ldap.php');
        exit;
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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LDAP Import - SubSignature</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/all.min.css">
    <style>
        .config-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(380px, 1fr)); gap: 1.5rem; }
        .config-card { background: white; border: 1px solid var(--border); border-radius: 12px; padding: 2rem; }
        .config-card h3 { font-size: 1.1rem; margin-bottom: 1.5rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem; }
        .config-item { display: flex; justify-content: space-between; align-items: center; padding: 0.9rem 0; border-bottom: 1px solid var(--border); gap: 1rem; }
        .config-item:last-child { border-bottom: none; }
        .form-group-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem; }
        .form-label { display: block; font-size: 0.85rem; font-weight: 600; color: #64748b; margin-bottom: 0.4rem; }
        .form-input { width: 100%; padding: 0.6rem; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 0.95rem; }
        .form-hint { color: #64748b; font-size: 0.78rem; margin-top: 0.25rem; display: block; }
        .switch { position: relative; display: inline-block; width: 40px; height: 22px; flex-shrink: 0; }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #cbd5e1; transition: .4s; border-radius: 34px; }
        .slider:before { position: absolute; content: ""; height: 16px; width: 16px; left: 3px; bottom: 3px; background-color: white; transition: .4s; border-radius: 50%; }
        input:checked + .slider { background-color: var(--primary); }
        input:checked + .slider:before { transform: translateX(18px); }
        .actions-row { display: flex; gap: 0.75rem; flex-wrap: wrap; margin-top: 1.5rem; }
        .stat-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
        .stat-box { background: #f8fafc; border: 1px solid var(--border); border-radius: 10px; padding: 1rem; text-align: center; }
        .stat-box strong { display: block; font-size: 1.6rem; }
        .stat-box span { font-size: 0.75rem; text-transform: uppercase; color: #64748b; font-weight: 600; }
        .plan-table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
        .plan-table th, .plan-table td { text-align: left; padding: 0.55rem 0.7rem; border-bottom: 1px solid var(--border); }
        .tag { padding: 2px 8px; border-radius: 12px; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; }
        .tag-create { background: #dcfce7; color: #166534; }
        .tag-update { background: #e0f2fe; color: #0369a1; }
        .tag-unchanged { background: #f1f5f9; color: #64748b; }
        .tag-skip { background: #fee2e2; color: #991b1b; }
        .warn-box { background: #fffbeb; border: 1px solid #fde68a; color: #92400e; padding: 0.9rem 1rem; border-radius: 8px; margin-bottom: 1.5rem; font-size: 0.9rem; }
    </style>
</head>
<body>

    <aside class="sidebar">
        <?php include 'includes/navbar.php'; ?>
        <div class="sidebar-footer">
            <div class="user-profile">
                <div class="avatar"><?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?></div>
                <div class="user-info">
                    <div><?php echo e($_SESSION['username']); ?></div>
                    <span>Administrator</span>
                </div>
            </div>
            <a href="logout.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> <span>Sign Out</span></a>
        </div>
    </aside>

    <main class="main-content">
        <header class="page-header">
            <h2>LDAP / Active Directory Import</h2>
            <p>Import users, email addresses and other attributes from your directory. Directory accounts cannot log in to SubSignature.</p>
        </header>

        <?php if ($message): ?>
            <div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo e($message); ?></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="alert alert-error"><i class="fas fa-exclamation-circle"></i> <?php echo e($error); ?></div>
        <?php endif; ?>
        <?php if (!$ldap_available): ?>
            <div class="warn-box"><i class="fas fa-exclamation-triangle"></i>
                The PHP <code>ldap</code> extension is not installed. You can edit and save the settings, but test and import are disabled
                (Debian/Ubuntu: <code>apt install php-ldap</code>).
            </div>
        <?php endif; ?>

        <?php if ($plan !== null): ?>
        <section class="card" style="margin-bottom:1.5rem;">
            <div class="card-header"><h3><i class="fas fa-clipboard-list"></i> Import Preview</h3></div>
            <div style="padding:1.5rem;">
                <div class="stat-row">
                    <div class="stat-box"><strong><?php echo (int)$plan['counts']['total']; ?></strong><span>Directory entries</span></div>
                    <div class="stat-box"><strong style="color:#16a34a;"><?php echo (int)$plan['counts']['create']; ?></strong><span>To create</span></div>
                    <div class="stat-box"><strong style="color:#0369a1;"><?php echo (int)$plan['counts']['update']; ?></strong><span>To update</span></div>
                    <div class="stat-box"><strong><?php echo (int)$plan['counts']['unchanged']; ?></strong><span>Unchanged</span></div>
                    <div class="stat-box"><strong style="color:#dc2626;"><?php echo (int)$plan['counts']['skip']; ?></strong><span>Skipped</span></div>
                    <div class="stat-box"><strong style="color:#d97706;"><?php echo (int)$plan['counts']['deactivate']; ?></strong><span>To deactivate</span></div>
                </div>

                <?php
                    // Changes and problems first, unchanged rows last; the table is capped for large directories.
                    $order = ['create' => 0, 'update' => 1, 'skip' => 2, 'unchanged' => 3];
                    $rowsView = $plan['rows'];
                    usort($rowsView, function ($a, $b) use ($order) { return $order[$a['action']] <=> $order[$b['action']]; });
                    $rowsShown = array_slice($rowsView, 0, 300);
                ?>
                <div style="overflow-x:auto; max-height:420px; overflow-y:auto;">
                    <table class="plan-table">
                        <thead><tr><th>Action</th><th>Username</th><th>Name</th><th>Email</th><th>Role</th><th>Phone</th><th>Note</th></tr></thead>
                        <tbody>
                        <?php foreach ($rowsShown as $r): ?>
                            <tr>
                                <td><span class="tag tag-<?php echo e($r['action']); ?>"><?php echo e($r['action']); ?></span></td>
                                <td><?php echo e($r['username']); ?></td>
                                <td><?php echo e($r['name']); ?></td>
                                <td><?php echo e($r['email']); ?></td>
                                <td><?php echo e($r['role']); ?></td>
                                <td><?php echo e($r['phone']); ?></td>
                                <td style="color:#991b1b;"><?php echo e($r['reason']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                <?php if (count($rowsView) > count($rowsShown)): ?>
                    <p class="form-hint">Showing the first <?php echo count($rowsShown); ?> of <?php echo count($rowsView); ?> entries. The import applies to all of them.</p>
                <?php endif; ?>

                <?php if ($plan['counts']['deactivate'] > 0): ?>
                    <div class="warn-box" style="margin-top:1rem;">
                        <?php echo (int)$plan['counts']['deactivate']; ?> previously imported account(s) are no longer in the directory result and will be deactivated.
                        Check the filter and base DN if this looks wrong.
                    </div>
                <?php endif; ?>

                <form method="POST" action="admin_ldap.php" class="actions-row">
                    <?php echo csrfField(); ?>
                    <input type="hidden" name="plan_token" value="<?php echo e($plan_token); ?>">
                    <button type="submit" name="action" value="apply" class="btn btn-primary"
                            data-confirm="Apply this import now?"><i class="fas fa-check"></i> Apply Import</button>
                    <button type="submit" name="action" value="cancel" class="btn btn-secondary">Cancel</button>
                </form>
            </div>
        </section>
        <?php endif; ?>

        <form method="POST" action="admin_ldap.php" id="ldapForm">
            <?php echo csrfField(); ?>

            <div class="config-grid">
                <section class="config-card">
                    <h3><i class="fas fa-network-wired"></i> Connection</h3>

                    <div class="form-group-grid">
                        <div>
                            <label class="form-label" for="preset">Directory type</label>
                            <select name="preset" id="preset" class="form-input">
                                <?php foreach (LdapConfig::PRESETS as $key => $p): ?>
                                    <option value="<?php echo e($key); ?>" <?php echo $cfg['preset'] === $key ? 'selected' : ''; ?>><?php echo e($p['label']); ?></option>
                                <?php endforeach; ?>
                                <option value="custom" <?php echo $cfg['preset'] === 'custom' ? 'selected' : ''; ?>>Custom</option>
                            </select>
                        </div>
                        <div>
                            <label class="form-label" for="encryption">Encryption</label>
                            <select name="encryption" id="encryption" class="form-input">
                                <option value="ldaps" <?php echo $cfg['encryption'] === 'ldaps' ? 'selected' : ''; ?>>LDAPS (TLS, recommended)</option>
                                <option value="starttls" <?php echo $cfg['encryption'] === 'starttls' ? 'selected' : ''; ?>>STARTTLS</option>
                                <option value="none" <?php echo $cfg['encryption'] === 'none' ? 'selected' : ''; ?>>None (not recommended)</option>
                            </select>
                        </div>
                    </div>

                    <div class="form-group-grid">
                        <div>
                            <label class="form-label" for="host">Host</label>
                            <input type="text" name="host" id="host" class="form-input" placeholder="dc01.example.com" maxlength="255" value="<?php echo e($cfg['host']); ?>">
                        </div>
                        <div>
                            <label class="form-label" for="port">Port</label>
                            <input type="number" name="port" id="port" class="form-input" min="1" max="65535" value="<?php echo (int)$cfg['port']; ?>">
                        </div>
                    </div>

                    <div class="form-group-grid">
                        <div>
                            <label class="form-label" for="verify_cert">Server certificate</label>
                            <select name="verify_cert" id="verify_cert" class="form-input">
                                <option value="1" <?php echo $cfg['verify_cert'] ? 'selected' : ''; ?>>Verify (recommended)</option>
                                <option value="0" <?php echo !$cfg['verify_cert'] ? 'selected' : ''; ?>>Do not verify (insecure)</option>
                            </select>
                        </div>
                        <div>
                            <label class="form-label" for="ca_file">CA file (optional)</label>
                            <input type="text" name="ca_file" id="ca_file" class="form-input" placeholder="/etc/ssl/certs/corp-ca.pem" maxlength="255" value="<?php echo e($cfg['ca_file']); ?>">
                        </div>
                    </div>

                    <div class="form-group-grid">
                        <div>
                            <label class="form-label" for="bind_dn">Bind DN / user principal</label>
                            <input type="text" name="bind_dn" id="bind_dn" class="form-input" autocomplete="off" placeholder="svc-subsig@example.com" maxlength="512" value="<?php echo e($cfg['bind_dn']); ?>">
                        </div>
                        <div>
                            <label class="form-label" for="bind_pass">Bind password</label>
                            <input type="password" name="bind_pass" id="bind_pass" class="form-input" autocomplete="new-password"
                                   placeholder="<?php echo $cfg['bind_pass'] !== '' ? '•••••••• (unchanged)' : ''; ?>">
                        </div>
                    </div>
                    <span class="form-hint">Use a read-only service account. The password is stored encrypted.</span>

                    <div style="margin-top:1rem;">
                        <label class="form-label" for="base_dn">Base DN</label>
                        <input type="text" name="base_dn" id="base_dn" class="form-input" placeholder="OU=Staff,DC=example,DC=com" maxlength="512" value="<?php echo e($cfg['base_dn']); ?>">
                    </div>
                </section>

                <section class="config-card">
                    <h3><i class="fas fa-filter"></i> Search &amp; attribute mapping</h3>

                    <div style="margin-bottom:1rem;">
                        <label class="form-label" for="user_filter">User filter</label>
                        <input type="text" name="user_filter" id="user_filter" class="form-input" maxlength="2000" value="<?php echo e($cfg['user_filter']); ?>">
                        <span class="form-hint">The default for Active Directory skips disabled accounts.</span>
                    </div>

                    <div class="form-group-grid">
                        <div>
                            <label class="form-label" for="attr_username">Username attribute</label>
                            <input type="text" name="attr_username" id="attr_username" class="form-input" maxlength="70" value="<?php echo e($cfg['attr_username']); ?>">
                        </div>
                        <div>
                            <label class="form-label" for="attr_email">Email attribute</label>
                            <input type="text" name="attr_email" id="attr_email" class="form-input" maxlength="70" value="<?php echo e($cfg['attr_email']); ?>">
                        </div>
                        <div>
                            <label class="form-label" for="attr_name">Full name attribute</label>
                            <input type="text" name="attr_name" id="attr_name" class="form-input" maxlength="70" value="<?php echo e($cfg['attr_name']); ?>">
                        </div>
                        <div>
                            <label class="form-label" for="attr_id">Unique ID attribute</label>
                            <input type="text" name="attr_id" id="attr_id" class="form-input" maxlength="70" value="<?php echo e($cfg['attr_id']); ?>">
                        </div>
                        <div>
                            <label class="form-label" for="attr_role">Role / title attribute</label>
                            <input type="text" name="attr_role" id="attr_role" class="form-input" maxlength="70" placeholder="title" value="<?php echo e($cfg['attr_role']); ?>">
                        </div>
                        <div>
                            <label class="form-label" for="attr_phone">Phone attribute</label>
                            <input type="text" name="attr_phone" id="attr_phone" class="form-input" maxlength="70" placeholder="telephoneNumber" value="<?php echo e($cfg['attr_phone']); ?>">
                        </div>
                    </div>
                    <span class="form-hint">Any directory attribute can be mapped (e.g. <code>mobile</code>, <code>department</code>, <code>co</code>). The unique ID keeps accounts linked when a username changes.</span>
                </section>

                <section class="config-card">
                    <h3><i class="fas fa-sliders-h"></i> Import options</h3>

                    <div class="config-item">
                        <div>
                            <h4 style="margin:0; font-size:0.95rem;">Create a signature for each user</h4>
                            <p style="margin:0; color:#64748b; font-size:0.8rem;">Uses name, role, email and phone from the directory.</p>
                        </div>
                        <label class="switch">
                            <input type="hidden" name="create_signatures" value="0">
                            <input type="checkbox" name="create_signatures" value="1" <?php echo $cfg['create_signatures'] ? 'checked' : ''; ?>>
                            <span class="slider"></span>
                        </label>
                    </div>

                    <div class="config-item">
                        <div>
                            <h4 style="margin:0; font-size:0.95rem;">Template for new signatures</h4>
                        </div>
                        <select name="template" class="form-input" style="max-width:220px;">
                            <option value="">System default</option>
                            <?php foreach ($templates as $t): ?>
                                <option value="<?php echo e($t); ?>" <?php echo $cfg['template'] === $t ? 'selected' : ''; ?>><?php echo e(templateDisplayName($t)); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div class="config-item">
                        <div>
                            <h4 style="margin:0; font-size:0.95rem;">New accounts are active</h4>
                            <p style="margin:0; color:#64748b; font-size:0.8rem;">Imported accounts always have the role "user".</p>
                        </div>
                        <label class="switch">
                            <input type="hidden" name="default_active" value="0">
                            <input type="checkbox" name="default_active" value="1" <?php echo $cfg['default_active'] ? 'checked' : ''; ?>>
                            <span class="slider"></span>
                        </label>
                    </div>

                    <div class="config-item">
                        <div>
                            <h4 style="margin:0; font-size:0.95rem;">Deactivate accounts missing in the directory</h4>
                            <p style="margin:0; color:#64748b; font-size:0.8rem;">Only previously imported accounts are affected.</p>
                        </div>
                        <label class="switch">
                            <input type="hidden" name="deactivate_missing" value="0">
                            <input type="checkbox" name="deactivate_missing" value="1" <?php echo $cfg['deactivate_missing'] ? 'checked' : ''; ?>>
                            <span class="slider"></span>
                        </label>
                    </div>

                    <p class="form-hint" style="margin-top:1rem;">
                        Local accounts are never modified: a directory entry with the same username or email as a local account is skipped.
                    </p>
                </section>
            </div>

            <div class="actions-row">
                <button type="submit" name="action" value="save" class="btn btn-primary"><i class="fas fa-save"></i> Save settings</button>
                <button type="submit" name="action" value="test" class="btn btn-secondary" <?php echo $ldap_available ? '' : 'disabled'; ?>><i class="fas fa-plug"></i> Test connection</button>
                <button type="submit" name="action" value="preview" class="btn btn-success" <?php echo $ldap_available ? '' : 'disabled'; ?>><i class="fas fa-search"></i> Preview import</button>
            </div>
            <span class="form-hint">Test and preview use the <em>saved</em> settings. Save first after making changes.</span>
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
