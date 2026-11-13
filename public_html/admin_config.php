<?php
// admin_config.php - system settings: registration, default account status, SMTP.

require_once 'includes/config.php';
requireAdmin();

// 1. Messages (flash data survives exactly one redirect)
$message = popFlash('success');
$error = popFlash('error');
$debug_log = popFlash('debug');

// ---------------------------------------------------------
// 2. HANDLE TEST EMAIL (POST -> REDIRECT)
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'test_email') {
    requireCsrf();
    require_once 'includes/MailHelper.php';

    $test_email = cleanText($_POST['test_recipient'] ?? '', 254);
    // SMTP debug output is only collected when the checkbox is ticked.
    $show_debug = ($_POST['show_debug_log'] ?? '') === '1';

    if (filter_var($test_email, FILTER_VALIDATE_EMAIL)) {
        $logHeader = '--- SMTP TEST STARTED AT ' . date('H:i:s') . " ---\n";

        $result = MailHelper::send(
            $test_email,
            'SMTP Test - SubSignature',
            '<h3>SMTP Test Successful ✅</h3><p>Your configuration works.</p>',
            'SMTP Test Successful',
            $show_debug
        );

        // Remove credentials from the log before it is stored in the session.
        $cleanLog = (string)$result['debug_log'];
        $cleanLog = preg_replace('/(PASS\s+)[^\s]+/', '$1 *****', $cleanLog);
        $cleanLog = preg_replace('/(auth\s+login\s+)[^\s]+/i', '$1 [HIDDEN]', $cleanLog);
        if ($cleanLog !== '') {
            setFlash('debug', $logHeader . $cleanLog);
        }

        if ($result['success']) {
            setFlash('success', t('Test email sent to {email}', ['email' => $test_email]));
        } else {
            setFlash('error', t('Test failed. See debug log.'));
        }
    } else {
        setFlash('error', t('Invalid email address.'));
    }

    header('Location: admin_config.php');
    exit;
}

// ---------------------------------------------------------
// 3. HANDLE SAVE CONFIG (POST -> REDIRECT)
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_config'])) {
    requireCsrf();

    $problems = [];

    // General settings (booleans are normalised to '0' / '1')
    setSetting($db, 'default_user_active', ($_POST['default_user_active'] ?? '1') === '1' ? '1' : '0');
    setSetting($db, 'allow_registration', ($_POST['allow_registration'] ?? '1') === '1' ? '1' : '0');

    // Default interface language (used when the browser sends no supported language)
    $default_language = (string)($_POST['default_language'] ?? 'en');
    setSetting($db, 'default_language', isSupportedLanguage($default_language) ? $default_language : 'en');

    // Agent sync status freshness window (All Signatures): how long a reported
    // "ok" counts as green before the badge turns yellow (stale).
    $status_freshness_hours = (int)($_POST['status_freshness_hours'] ?? 6);
    if ($status_freshness_hours < 1 || $status_freshness_hours > 168) {
        $problems[] = t('The sync freshness window must be between 1 and 168 hours.');
        $status_freshness_hours = 6;
    }
    setSetting($db, 'status_freshness_hours', (string)$status_freshness_hours);

    // Agent devices that stopped reporting are forgotten after this many days.
    $status_device_retention_days = (int)($_POST['status_device_retention_days'] ?? 30);
    if ($status_device_retention_days < 1 || $status_device_retention_days > 365) {
        $problems[] = t('The device retention must be between 1 and 365 days.');
        $status_device_retention_days = 30;
    }
    setSetting($db, 'status_device_retention_days', (string)$status_device_retention_days);

    // API request log (System Logs -> API Requests): what is logged and for how long.
    $api_log_mode = (string)($_POST['api_log_mode'] ?? 'all');
    if (!in_array($api_log_mode, ['all', 'errors', 'off'], true)) {
        $api_log_mode = 'all';
    }
    setSetting($db, 'api_log_mode', $api_log_mode);
    $api_log_retention_days = (int)($_POST['api_log_retention_days'] ?? 30);
    if ($api_log_retention_days < 1 || $api_log_retention_days > 365) {
        $problems[] = t('The API log retention must be between 1 and 365 days.');
        $api_log_retention_days = 30;
    }
    setSetting($db, 'api_log_retention_days', (string)$api_log_retention_days);

    // Hosts whose template images the API may fetch and deliver embedded
    // (Base64). Only plain host names are kept; anything else is reported.
    $image_hosts_raw = cleanMultilineText($_POST['image_embed_hosts'] ?? '', 3000);
    $image_hosts = parseImageEmbedHosts($image_hosts_raw);
    $entered = array_filter(preg_split('/[\s,;]+/', strtolower($image_hosts_raw)) ?: [], 'strlen');
    $dropped = array_diff(array_unique($entered), $image_hosts);
    if ($dropped) {
        $problems[] = t('Ignored image hosts (enter host names only, e.g. www.example.com): {hosts}', ['hosts' => implode(', ', array_slice($dropped, 0, 10))]) . '.';
    }
    setSetting($db, 'image_embed_hosts', implode("\n", $image_hosts));

    // Company-wide values for the {{COMPANY}}, {{WEBSITE}}, {{ADDRESS}}, {{DISCLAIMER}} placeholders
    $company_website = cleanText($_POST['company_website'] ?? '', 200);
    if ($company_website !== '' && !preg_match('#^https?://[^\s<>"\']+$#i', $company_website)) {
        $problems[] = t('The website must start with http:// or https://.');
        $company_website = '';
    }
    setSetting($db, 'company_company', cleanText($_POST['company_company'] ?? '', 100));
    setSetting($db, 'company_website', $company_website);
    setSetting($db, 'company_address', cleanMultilineText($_POST['company_address'] ?? '', 300));
    setSetting($db, 'company_disclaimer', cleanMultilineText($_POST['company_disclaimer'] ?? '', 1000));

    // SMTP settings with validation
    $smtp_host = cleanText($_POST['smtp_host'] ?? '', 255);
    if ($smtp_host !== '' && !preg_match('/^[A-Za-z0-9.\-]+$|^\[[0-9A-Fa-f:.]+\]$/', $smtp_host)) {
        $problems[] = t('Invalid SMTP host name.');
        $smtp_host = '';
    }
    $smtp_port = (int)($_POST['smtp_port'] ?? 587);
    if ($smtp_port < 1 || $smtp_port > 65535) {
        $problems[] = t('SMTP port must be between 1 and 65535.');
        $smtp_port = 587;
    }
    $smtp_secure = $_POST['smtp_secure'] ?? 'tls';
    if (!in_array($smtp_secure, ['tls', 'ssl', 'none'], true)) {
        $smtp_secure = 'tls';
    }
    $smtp_from_email = cleanText($_POST['smtp_from_email'] ?? '', 254);
    if ($smtp_from_email !== '' && !filter_var($smtp_from_email, FILTER_VALIDATE_EMAIL)) {
        $problems[] = t('Invalid sender email address.');
        $smtp_from_email = '';
    }

    setSetting($db, 'smtp_host', $smtp_host);
    setSetting($db, 'smtp_port', (string)$smtp_port);
    setSetting($db, 'smtp_auth', ($_POST['smtp_auth'] ?? '') === '1' ? '1' : '0');
    setSetting($db, 'smtp_user', cleanText($_POST['smtp_user'] ?? '', 255));
    setSetting($db, 'smtp_secure', $smtp_secure);
    setSetting($db, 'smtp_from_email', $smtp_from_email);
    setSetting($db, 'smtp_from_name', cleanText($_POST['smtp_from_name'] ?? '', 100));

    // The password is only replaced when a new one was entered, and it is stored encrypted.
    if (is_string($_POST['smtp_pass'] ?? null) && $_POST['smtp_pass'] !== '') {
        setSetting($db, 'smtp_pass', encryptSecret($_POST['smtp_pass']));
    }

    logSecurityEventToDB($db, 'CONFIG_CHANGED', (int)$_SESSION['user_id'], 'System / SMTP settings saved; image hosts: ' . ($image_hosts ? implode(', ', $image_hosts) : '-'));

    if ($problems) {
        setFlash('error', implode(' ', $problems) . ' ' . t('Other settings were saved.'));
    } else {
        setFlash('success', t('Configuration saved successfully.'));
    }
    header('Location: admin_config.php');
    exit;
}

// 4. Fetch Settings for View
$current_default_active = (int)getSetting($db, 'default_user_active', '1');
$smtp_host = getSetting($db, 'smtp_host', '');
$smtp_port = getSetting($db, 'smtp_port', '587');
$smtp_auth = getSetting($db, 'smtp_auth', '1');
$smtp_user = getSetting($db, 'smtp_user', '');
$smtp_secure = getSetting($db, 'smtp_secure', 'tls');
$smtp_from_email = getSetting($db, 'smtp_from_email', '');
$smtp_from_name = getSetting($db, 'smtp_from_name', 'Signature Admin');

$allow_registration = getSetting($db, 'allow_registration', '1') === '1';
$default_language = getSetting($db, 'default_language', 'en');
$status_freshness_hours = (int)getSetting($db, 'status_freshness_hours', '6');
$status_device_retention_days = statusDeviceRetentionDays($db);
$api_log_mode = apiLogMode($db);
$api_log_retention_days = apiLogRetentionDays($db);
$image_embed_hosts = imageEmbedHosts($db);
$company = companyFields();
$health = systemHealthChecks();
?>
<!DOCTYPE html>
<html lang="<?= e(currentLang()) ?>" dir="<?= e(langDir()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= et('System Configuration') ?> - SubSignature</title>
    <?= i18nHead() ?>
    <script src="<?= assetUrl('js/theme.js') ?>"></script>
    <link rel="stylesheet" href="<?= assetUrl('css/theme.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/style.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/all.min.css') ?>">
    <style>
        .config-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 1.5rem; }
        .config-card { background: var(--bg-white); border: 1px solid var(--border); border-radius: 12px; padding: 2rem; height: 100%; }
        .config-item { display: flex; justify-content: space-between; align-items: center; padding: 1rem 0; border-bottom: 1px solid var(--border); }
        .config-item:last-child { border-bottom: none; }
        .form-group-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem; }
        .form-label { display: block; font-size: 0.85rem; font-weight: 600; color: var(--text-muted); margin-bottom: 0.4rem; }
        .form-input { width: 100%; padding: 0.6rem; border: 1px solid var(--border-strong); border-radius: 6px; font-size: 0.95rem; }
        .switch { position: relative; display: inline-block; width: 40px; height: 22px; }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: var(--border-strong); transition: .4s; border-radius: 34px; }
        .slider:before { position: absolute; content: ""; height: 16px; width: 16px; left: 3px; bottom: 3px; background-color: var(--bg-white); transition: .4s; border-radius: 50%; }
        input:checked + .slider { background-color: var(--primary); }
        input:checked + .slider:before { transform: translateX(18px); }
        
        .health-table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
        .health-table td { padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); vertical-align: top; }
        .health-table tr:last-child td { border-bottom: none; }
        .health-status { width: 28px; text-align: center; }
        .health-ok { color: var(--success-text); }
        .health-warn { color: var(--warning-text); }
        .health-fail { color: var(--danger-text); }
        textarea.form-input { resize: vertical; font-family: inherit; }

        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: none; justify-content: center; align-items: center; z-index: 999; backdrop-filter: blur(2px); }
        .modal-box { background: var(--bg-white); padding: 2rem; border-radius: 12px; width: 90%; max-width: 450px; box-shadow: 0 20px 25px rgba(0,0,0,0.1); }
        
        .debug-console {
            background: #1e293b; color: #bef264; 
            padding: 1rem; border-radius: 8px; 
            margin-top: 1rem; margin-bottom: 1rem;
            font-family: monospace; font-size: 0.85rem;
            max-height: 300px; overflow-y: auto;
            white-space: pre-wrap; word-wrap: break-word;
            border: 1px solid #334155;
        }
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
            <h2><?= et('System Configuration') ?></h2>
            <p><?= et('Manage settings and integrations.') ?></p>
        </header>

        <?= flashAlerts($message, $error) ?>
        <?php if (!empty($debug_log)): ?>
            <?= alertBoxHtml($error ? 'error' : 'info', '<strong>' . et('SMTP Debug Log') . '</strong><div class="debug-console">' . e($debug_log) . '</div>') ?>
        <?php endif; ?>

        <form method="POST" action="admin_config.php">
            <?php echo csrfField(); ?>
            <input type="hidden" name="save_config" value="1">
            
            <div class="config-grid">
                
                <section class="config-card">
                    <h3 style="font-size:1.1rem; margin-bottom:1.5rem; border-bottom:1px solid var(--border); padding-bottom:1rem;">
                        <i class="fas fa-users-cog"></i> <?= et('General Settings') ?>
                    </h3>
                    <div class="config-item">
                        <div>
                            <h4 style="margin:0; font-size:0.95rem;"><?= et('Active by Default') ?></h4>
                            <p style="margin:0; color:var(--text-muted); font-size:0.8rem;"><?= et('New users are active immediately.') ?></p>
                        </div>
                        <label class="switch">
                            <input type="hidden" name="default_user_active" value="0">
                            <input type="checkbox" name="default_user_active" value="1" <?php echo ($current_default_active == 1) ? 'checked' : ''; ?>>
                            <span class="slider"></span>
                        </label>
                    </div>
                    <div class="config-item">
                        <div>
                            <h4 style="margin:0; font-size:0.95rem;"><?= et('Allow Self-Registration') ?></h4>
                            <p style="margin:0; color:var(--text-muted); font-size:0.8rem;"><?= et('Show the public registration page.') ?></p>
                        </div>
                        <label class="switch">
                            <input type="hidden" name="allow_registration" value="0">
                            <input type="checkbox" name="allow_registration" value="1" <?php echo $allow_registration ? 'checked' : ''; ?>>
                            <span class="slider"></span>
                        </label>
                    </div>
                    <div class="config-item">
                        <div>
                            <h4 style="margin:0; font-size:0.95rem;"><?= et('Default language') ?></h4>
                            <p style="margin:0; color:var(--text-muted); font-size:0.8rem;"><?= et('Used when the browser language is not available. Every user can choose their own.') ?></p>
                        </div>
                        <select name="default_language" class="form-input" style="width:auto; min-width:150px;">
                            <?php foreach (availableLanguages() as $code => $langName): ?>
                                <option value="<?php echo e($code); ?>" <?php echo $code === $default_language ? 'selected' : ''; ?>><?php echo e($langName); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="config-item">
                        <div>
                            <h4 style="margin:0; font-size:0.95rem;"><i class="fas fa-satellite-dish"></i> <?= et('Agent sync freshness window') ?></h4>
                            <p style="margin:0; color:var(--text-muted); font-size:0.8rem;"><?= et('How long a signature stays "green" in All Signatures after an agent reports it synced. Older reports turn the status yellow.') ?></p>
                        </div>
                        <div style="display:flex; align-items:center; gap:0.4rem;">
                            <input type="number" name="status_freshness_hours" class="form-input" style="width:80px;" min="1" max="168" value="<?php echo (int)$status_freshness_hours; ?>">
                            <span style="color:var(--text-muted); font-size:0.85rem;"><?= et('hours') ?></span>
                        </div>
                    </div>
                    <div class="config-item">
                        <div>
                            <h4 style="margin:0; font-size:0.95rem;"><i class="fas fa-laptop"></i> <?= et('Forget silent devices after') ?></h4>
                            <p style="margin:0; color:var(--text-muted); font-size:0.8rem;"><?= et('Devices (agent installations) that have not reported for this long are no longer counted in "2/3 up to date" and are removed - for example a replaced laptop.') ?></p>
                        </div>
                        <div style="display:flex; align-items:center; gap:0.4rem;">
                            <input type="number" name="status_device_retention_days" class="form-input" style="width:80px;" min="1" max="365" value="<?php echo (int)$status_device_retention_days; ?>">
                            <span style="color:var(--text-muted); font-size:0.85rem;"><?= et('days') ?></span>
                        </div>
                    </div>
                    <div class="config-item">
                        <div>
                            <h4 style="margin:0; font-size:0.95rem;"><i class="fas fa-plug"></i> <?= et('API request log') ?></h4>
                            <p style="margin:0; color:var(--text-muted); font-size:0.8rem;"><?= et('Which requests of the clients (desktop agent, Domino agent, scripts) appear under System Logs -> API Requests, and how many days they are kept.') ?></p>
                        </div>
                        <div style="display:flex; align-items:center; gap:0.4rem; flex-wrap:wrap; justify-content:flex-end;">
                            <select name="api_log_mode" class="form-input" style="width:auto;">
                                <option value="all" <?php echo $api_log_mode === 'all' ? 'selected' : ''; ?>><?= et('All requests') ?></option>
                                <option value="errors" <?php echo $api_log_mode === 'errors' ? 'selected' : ''; ?>><?= et('Only errors') ?></option>
                                <option value="off" <?php echo $api_log_mode === 'off' ? 'selected' : ''; ?>><?= et('Off') ?></option>
                            </select>
                            <input type="number" name="api_log_retention_days" class="form-input" style="width:80px;" min="1" max="365" value="<?php echo (int)$api_log_retention_days; ?>">
                            <span style="color:var(--text-muted); font-size:0.85rem;"><?= et('days') ?></span>
                        </div>
                    </div>
                    <div class="config-item" style="flex-direction:column; align-items:stretch; gap:0.6rem;">
                        <div>
                            <h4 style="margin:0; font-size:0.95rem;"><i class="fas fa-images"></i> <?= et('Image hosts for embedding') ?></h4>
                            <p style="margin:0; color:var(--text-muted); font-size:0.8rem;"><?= et('Clients that cannot load images themselves (e.g. HCL Notes/Domino) can receive the images of a signature embedded through the API. Images from Manage Images are always allowed; images on other servers only from the hosts listed here (one host name per line, https only). Empty = none.') ?></p>
                        </div>
                        <textarea name="image_embed_hosts" class="form-input" rows="3" spellcheck="false" placeholder="www.example.com" style="font-family:monospace; font-size:0.85rem;"><?php echo e(implode("\n", $image_embed_hosts)); ?></textarea>
                    </div>
                </section>

                <section class="config-card">
                    <h3 style="font-size:1.1rem; margin-bottom:0.5rem; border-bottom:1px solid var(--border); padding-bottom:1rem;">
                        <i class="fas fa-building"></i> <?= et('Company details') ?>
                    </h3>
                    <p style="color:var(--text-muted); font-size:0.8rem; margin:0 0 1rem;">
                        <?= eth('Available in every template as {placeholders}. Changes apply to all signatures at once.', ['placeholders' => '<code>{{COMPANY}}</code>, <code>{{WEBSITE}}</code>, <code>{{ADDRESS}}</code>, <code>{{DISCLAIMER}}</code>']) ?>
                    </p>
                    <div class="form-group-grid">
                        <div>
                            <label class="form-label"><?= et('Company name') ?></label>
                            <input type="text" name="company_company" class="form-input" maxlength="100" value="<?php echo e($company['company']); ?>">
                        </div>
                        <div>
                            <label class="form-label"><?= et('Website') ?></label>
                            <input type="url" name="company_website" class="form-input" maxlength="200" placeholder="https://example.com" value="<?php echo e($company['website']); ?>">
                        </div>
                    </div>
                    <div style="margin-bottom:1rem;">
                        <label class="form-label"><?= et('Address') ?></label>
                        <textarea name="company_address" class="form-input" rows="3" maxlength="300"><?php echo e($company['address']); ?></textarea>
                    </div>
                    <div>
                        <label class="form-label"><?= et('Legal notice / disclaimer') ?></label>
                        <textarea name="company_disclaimer" class="form-input" rows="4" maxlength="1000"><?php echo e($company['disclaimer']); ?></textarea>
                    </div>
                </section>

                <section class="config-card">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 1.5rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem;">
                        <h3 style="font-size:1.1rem; margin:0;"><i class="fas fa-envelope"></i> <?= et('SMTP Email Server') ?></h3>
                        <button type="button" onclick="openTestModal()" class="btn btn-sm btn-secondary">
                            <i class="fas fa-paper-plane"></i> <?= et('Test Email') ?>
                        </button>
                    </div>

                    <div class="form-group-grid">
                        <div>
                            <label class="form-label"><?= et('SMTP Host') ?></label>
                            <input type="text" name="smtp_host" class="form-input" placeholder="<?= et('smtp.example.com') ?>" value="<?php echo e($smtp_host); ?>">
                        </div>
                        <div>
                            <label class="form-label"><?= et('SMTP Port') ?></label>
                            <input type="number" name="smtp_port" class="form-input" placeholder="587" value="<?php echo e($smtp_port); ?>">
                        </div>
                    </div>

                    <div class="config-item" style="margin-bottom:1rem; border-bottom:none; padding:0.5rem 0;">
                        <div>
                            <label class="form-label" style="margin:0;"><?= et('SMTP Authentication') ?></label>
                            <p style="margin:0; color:var(--text-muted); font-size:0.75rem;"><?= et('Enable if server requires login.') ?></p>
                        </div>
                        <label class="switch">
                            <input type="hidden" name="smtp_auth" value="0">
                            <input type="checkbox" name="smtp_auth" value="1" <?php echo ($smtp_auth == 1) ? 'checked' : ''; ?> onchange="toggleAuthFields(this)">
                            <span class="slider"></span>
                        </label>
                    </div>

                    <div id="authFields" style="display: <?php echo ($smtp_auth == 1) ? 'block' : 'none'; ?>;">
                        <div class="form-group-grid">
                            <div>
                                <label class="form-label"><?= et('Username') ?></label>
                                <input type="text" name="smtp_user" class="form-input" value="<?php echo e($smtp_user); ?>">
                            </div>
                            <div>
                                <label class="form-label"><?= et('Password') ?></label>
                                <input type="password" name="smtp_pass" class="form-input" autocomplete="new-password" placeholder="••••••••">
                            </div>
                        </div>
                    </div>

                    <div style="margin-bottom: 1rem;">
                         <label class="form-label"><?= et('Encryption') ?></label>
                         <select name="smtp_secure" class="form-input">
                            <option value="tls" <?php echo ($smtp_secure === 'tls') ? 'selected' : ''; ?>><?= et('TLS (Recommended)') ?></option>
                            <option value="ssl" <?php echo ($smtp_secure === 'ssl') ? 'selected' : ''; ?>>SSL</option>
                            <option value="none" <?php echo ($smtp_secure === 'none') ? 'selected' : ''; ?>><?= et('None') ?></option>
                        </select>
                    </div>

                    <hr style="border:0; border-top:1px solid var(--border); margin: 1.5rem 0;">

                    <div class="form-group-grid">
                        <div>
                            <label class="form-label"><?= et('Sender Email') ?></label>
                            <input type="email" name="smtp_from_email" class="form-input" value="<?php echo e($smtp_from_email); ?>">
                        </div>
                        <div>
                            <label class="form-label"><?= et('Sender Name') ?></label>
                            <input type="text" name="smtp_from_name" class="form-input" value="<?php echo e($smtp_from_name); ?>">
                        </div>
                    </div>
                </section>
            </div>

            <div class="form-actions" style="margin-top: 2rem; display: flex; justify-content: flex-end;">
                <button type="submit" class="btn btn-primary" style="padding: 0.8rem 2rem;">
                    <i class="fas fa-save"></i> <?= et('Save Configuration') ?>
                </button>
            </div>
        </form>

        <section class="config-card" style="margin-top:1.5rem; height:auto;">
            <h3 style="font-size:1.1rem; margin-bottom:1rem; border-bottom:1px solid var(--border); padding-bottom:1rem;">
                <i class="fas fa-heart-pulse"></i> <?= et('System status') ?>
            </h3>
            <table class="health-table">
                <?php foreach ($health as $row): ?>
                    <tr>
                        <td class="health-status health-<?php echo e($row['status']); ?>">
                            <i class="fas <?php echo $row['status'] === 'ok' ? 'fa-circle-check' : ($row['status'] === 'warn' ? 'fa-triangle-exclamation' : 'fa-circle-xmark'); ?>"></i>
                            <span class="sr-only"><?php echo e($row['status']); ?></span>
                        </td>
                        <td><strong><?php echo e($row['label']); ?></strong></td>
                        <td style="color:var(--text-muted);"><?php echo e($row['detail']); ?></td>
                    </tr>
                <?php endforeach; ?>
            </table>
        </section>

    </main>

    <div id="testEmailModal" class="modal-overlay">
        <div class="modal-box">
            <h3 style="margin-top:0;"><i class="fas fa-vial"></i> <?= et('Send Test Email') ?></h3>
            <p style="color:var(--text-muted); font-size:0.9rem;"><?= et('Check your configuration.') ?></p>
            
            <form method="POST" action="admin_config.php">
                <?php echo csrfField(); ?>
                <input type="hidden" name="action" value="test_email">
                
                <div style="margin: 1.5rem 0;">
                    <label class="form-label"><?= et('Recipient') ?></label>
                    <input type="email" name="test_recipient" required class="form-input" placeholder="your@email.com">
                </div>

                <div style="margin-bottom: 1.5rem;">
                    <label style="display:flex; align-items:center; gap:0.5rem; font-size:0.9rem; cursor:pointer;">
                        <input type="checkbox" name="show_debug_log" value="1">
                        <span><?= et('Show detailed SMTP connection log') ?></span>
                    </label>
                    <p style="font-size:0.75rem; color:var(--text-faint); margin:0.2rem 0 0 1.4rem;"><?= et('Only use if connection fails. May contain technical details.') ?></p>
                </div>
                
                <div style="display:flex; justify-content:flex-end; gap:0.5rem;">
                    <button type="button" onclick="closeTestModal()" class="btn btn-secondary"><?= et('Cancel') ?></button>
                    <button type="submit" class="btn btn-primary"><?= et('Send Test') ?></button>
                </div>
            </form>
        </div>
    </div>

    <script>
        function openTestModal() { document.getElementById('testEmailModal').style.display = 'flex'; }
        function closeTestModal() { document.getElementById('testEmailModal').style.display = 'none'; }
        function toggleAuthFields(cb) { document.getElementById('authFields').style.display = cb.checked ? 'block' : 'none'; }
        window.onclick = function(e) { if(e.target == document.getElementById('testEmailModal')) closeTestModal(); }
    </script>
</body>
</html>
