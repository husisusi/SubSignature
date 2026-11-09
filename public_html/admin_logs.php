<?php
// admin_logs.php - audit view: security events, mail log and login attempts (admin only).
require_once 'includes/config.php';
requireAdmin(); // Security Prio 1

// ---------------------------------------------------------
// 1. INPUT VALIDATION & LOGIC
// ---------------------------------------------------------
$allowed_limits = [10, 25, 50, 100, 250, 500];
$limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 50;
if (!in_array($limit, $allowed_limits)) $limit = 50;

// ---------------------------------------------------------
// 2. DASHBOARD STATS (Quick Overview - Last 24h)
// ---------------------------------------------------------
$stats = [];
$stats['security_issues'] = $db->querySingle("SELECT COUNT(*) FROM security_events WHERE (event_type LIKE '%FAILED%' OR event_type LIKE '%LOCKED%') AND created_at > datetime('now', '-1 day')");
$stats['failed_logins']   = $db->querySingle("SELECT COUNT(*) FROM login_attempts WHERE successful = 0 AND attempted_at > datetime('now', '-1 day')");

// The mail log table is optional (statistics only if it exists)
$mailLogsExist = $db->querySingle("SELECT name FROM sqlite_master WHERE type='table' AND name='mail_logs'");
if ($mailLogsExist) {
    $stats['mails_sent'] = $db->querySingle("SELECT COUNT(*) FROM mail_logs WHERE status = 'success' AND created_at > datetime('now', '-1 day')");
    $stats['mails_error'] = $db->querySingle("SELECT COUNT(*) FROM mail_logs WHERE status = 'error' AND created_at > datetime('now', '-1 day')");
    
    // FETCH MAIL LOGS
    $mailResult = $db->query("SELECT * FROM mail_logs ORDER BY created_at DESC LIMIT $limit");
} else {
    $stats['mails_sent'] = 0;
    $stats['mails_error'] = 0;
    $mailResult = null;
}

// ---------------------------------------------------------
// 3. FETCH DATA TABLES
// ---------------------------------------------------------
$secResult = $db->query("SELECT s.*, u.username as real_username FROM security_events s LEFT JOIN users u ON s.user_id = u.id ORDER BY s.created_at DESC LIMIT $limit");
$loginResult = $db->query("SELECT * FROM login_attempts ORDER BY attempted_at DESC LIMIT $limit");

?>
<!DOCTYPE html>
<html lang="<?= e(currentLang()) ?>" dir="<?= e(langDir()) ?>">
<head>
    <meta charset="UTF-8">
    <title><?= et('System Audit') ?> - SubSignature</title>
    <?= i18nHead() ?>
    <script src="<?= assetUrl('js/theme.js') ?>"></script>
    <link rel="stylesheet" href="<?= assetUrl('css/theme.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/style.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/all.min.css') ?>">
    <style>
        :root {
            --bg-color: var(--bg-subtle);
            --card-bg: var(--bg-white);
            --border-color: var(--border);
            --primary-soft: var(--info-bg);
        }

        /* --- DASHBOARD STATS --- */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: var(--bg-white); padding: 1.5rem; border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
            border: 1px solid var(--border-color);
            display: flex; align-items: center; justify-content: space-between;
        }
        .stat-info h4 { margin: 0; font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
        .stat-info p { margin: 5px 0 0 0; font-size: 1.8rem; font-weight: 700; color: var(--text-main); }
        .stat-icon {
            width: 48px; height: 48px; border-radius: 10px;
            display: flex; align-items: center; justify-content: center;
            font-size: 1.5rem;
        }
        .icon-red { background: var(--danger-bg); color: var(--danger-text); }
        .icon-green { background: var(--success-bg); color: var(--success-text); }
        .icon-orange { background: var(--warning-bg); color: var(--warning-text); }

        /* --- TABS NAVIGATION --- */
        .tabs { display: flex; gap: 1rem; border-bottom: 2px solid var(--border-color); margin-bottom: 1.5rem; }
        .tab-btn {
            background: none; border: none; padding: 0.8rem 1.2rem;
            font-size: 0.95rem; font-weight: 600; color: var(--text-muted);
            cursor: pointer; transition: all 0.2s; border-bottom: 3px solid transparent; margin-bottom: -2px;
        }
        .tab-btn:hover { color: var(--text-main); }
        .tab-btn.active { color: var(--info-text); border-bottom-color: var(--info-text); }
        .tab-content { display: none; animation: fadeIn 0.3s ease-in-out; }
        .tab-content.active { display: block; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: translateY(0); } }

        /* --- TABLE STYLING --- */
        .log-table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 0.9rem; }
        .log-table th { 
            text-align: left; padding: 12px 15px; background: var(--bg-subtle); 
            border-bottom: 2px solid var(--border-color); color: var(--text-muted); font-weight: 600;
        }
        .log-table td { padding: 12px 15px; border-bottom: 1px solid var(--border-color); color: var(--text-main); }
        .log-table tr:last-child td { border-bottom: none; }
        .log-table tr:hover td { background: var(--bg-subtle); }
        
        .badge { padding: 4px 10px; border-radius: 99px; font-weight: 600; font-size: 0.75rem; display: inline-flex; align-items: center; gap: 5px; }
        .badge-danger { background: var(--danger-bg); color: var(--danger-text); } 
        .badge-warning { background: var(--warning-bg); color: var(--warning-text); } 
        .badge-success { background: var(--success-bg); color: var(--success-text); } 
        .badge-info { background: var(--info-bg); color: var(--info-text); }    
        
        .ip-addr { font-family: 'Courier New', monospace; background: var(--bg-subtle); padding: 2px 6px; border-radius: 4px; font-size: 0.85rem; color: var(--text-muted); }
        
        /* Limit Selector */
        .limit-selector { display: flex; align-items: center; gap: 8px; font-size: 0.85rem; color: var(--text-muted); background: var(--bg-white); padding: 5px 10px; border-radius: 6px; border: 1px solid var(--border-color); }
        .limit-selector select { border: none; outline: none; background: transparent; font-weight: bold; cursor: pointer; color: var(--text-main); }
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
    
    <header class="page-header" style="display:flex; justify-content:space-between; align-items:flex-end;">
        <div>
            <h2><?= et('System Audit') ?></h2>
            <p><?= et('Overview of system health and logs.') ?></p>
        </div>
        
        <form method="GET" class="limit-selector">
            <i class="fas fa-list"></i>
            <span><?= et('Show:') ?></span>
            <select name="limit" onchange="this.form.submit()">
                <?php foreach($allowed_limits as $val): ?>
                    <option value="<?php echo $val; ?>" <?php echo ($limit == $val) ? 'selected' : ''; ?>><?php echo $val; ?></option>
                <?php endforeach; ?>
            </select>
        </form>
    </header>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-info">
                <h4><?= et('Emails Sent (24h)') ?></h4>
                <p><?php echo $stats['mails_sent']; ?></p>
            </div>
            <div class="stat-icon icon-green"><i class="fas fa-paper-plane"></i></div>
        </div>

        <div class="stat-card">
            <div class="stat-info">
                <h4><?= et('Security Alerts (24h)') ?></h4>
                <p><?php echo $stats['security_issues']; ?></p>
            </div>
            <div class="stat-icon <?php echo ($stats['security_issues'] > 0) ? 'icon-red' : 'icon-info'; ?>">
                <i class="fas fa-shield-alt"></i>
            </div>
        </div>

        <div class="stat-card">
            <div class="stat-info">
                <h4><?= et('Login Failures (24h)') ?></h4>
                <p><?php echo $stats['failed_logins']; ?></p>
            </div>
            <div class="stat-icon <?php echo ($stats['failed_logins'] > 0) ? 'icon-orange' : 'icon-info'; ?>">
                <i class="fas fa-user-lock"></i>
            </div>
        </div>
    </div>

    <div class="tabs">
        <button class="tab-btn active" onclick="openTab(event, 'tab-security')"><i class="fas fa-shield-alt"></i> <?= et('Security Events') ?></button>
        <button class="tab-btn" onclick="openTab(event, 'tab-email')"><i class="fas fa-envelope"></i> <?= et('Email Logs') ?></button>
        <button class="tab-btn" onclick="openTab(event, 'tab-login')"><i class="fas fa-key"></i> <?= et('Login Attempts') ?></button>
    </div>

    <div id="tab-security" class="tab-content active">
        <section class="card">
            <div style="overflow-x: auto;">
                <table class="log-table">
                    <thead>
                        <tr>
                            <th width="150"><?= et('Time') ?></th>
                            <th width="140"><?= et('Type') ?></th>
                            <th><?= et('User') ?></th>
                            <th><?= et('Details') ?></th>
                            <th width="140"><?= et('IP Address') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while($row = $secResult->fetchArray(SQLITE3_ASSOC)): ?>
                            <?php 
                                $cls = 'badge-info'; $icon = 'info-circle';
                                if(strpos($row['event_type'], 'FAILED') !== false) { $cls = 'badge-danger'; $icon = 'times-circle'; }
                                if(strpos($row['event_type'], 'LOCKED') !== false) { $cls = 'badge-danger'; $icon = 'lock'; }
                                if(strpos($row['event_type'], 'SUCCESS') !== false) { $cls = 'badge-success'; $icon = 'check-circle'; }
                                if(strpos($row['event_type'], 'RATE') !== false) { $cls = 'badge-warning'; $icon = 'exclamation-triangle'; }
                            ?>
                            <tr>
                                <td style="color:var(--text-muted);"><?php echo e(date('d.m.Y H:i', strtotime($row['created_at']) ?: time())); ?></td>
                                <td><span class="badge <?php echo $cls; ?>"><i class="fas fa-<?php echo $icon; ?>"></i> <?php echo e($row['event_type']); ?></span></td>
                                <td><?php echo $row['real_username'] ? '<strong>'.e($row['real_username']).'</strong>' : '<span style="color:var(--border-strong)">-</span>'; ?></td>
                                <td><?php echo e($row['details']); ?></td>
                                <td><span class="ip-addr"><?php echo e($row['ip_address']); ?></span></td>
                            </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            </div>
        </section>
    </div>

    <div id="tab-email" class="tab-content">
        <section class="card">
            <div style="overflow-x: auto;">
                <table class="log-table">
                    <thead>
                        <tr>
                            <th width="150"><?= et('Time') ?></th>
                            <th width="100"><?= et('Status') ?></th>
                            <th><?= et('Recipient') ?></th>
                            <th><?= et('Result Message') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ($mailResult): ?>
                            <?php while($row = $mailResult->fetchArray(SQLITE3_ASSOC)): ?>
                                <tr>
                                    <td style="color:var(--text-muted);"><?php echo e(date('d.m.Y H:i', strtotime($row['created_at']) ?: time())); ?></td>
                                    <td>
                                        <?php if($row['status'] === 'success'): ?>
                                            <span class="badge badge-success"><i class="fas fa-check"></i> <?= et('Sent') ?></span>
                                        <?php else: ?>
                                            <span class="badge badge-danger"><i class="fas fa-exclamation-triangle"></i> <?= et('Error') ?></span>
                                        <?php endif; ?>
                                    </td>
                                    <td><strong><?php echo e($row['recipient']); ?></strong></td>
                                    <td style="<?php echo ($row['status'] === 'error') ? 'color:var(--danger-text);font-weight:500;' : ''; ?>">
                                        <?php echo e($row['message']); ?>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <tr><td colspan="4" style="text-align:center; padding:2rem; color:var(--text-muted);"><?= et('No logs available.') ?></td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </section>
    </div>

    <div id="tab-login" class="tab-content">
        <section class="card">
            <div style="overflow-x: auto;">
                <table class="log-table">
                    <thead>
                        <tr>
                            <th width="150"><?= et('Time') ?></th>
                            <th width="100"><?= et('Status') ?></th>
                            <th><?= et('User Attempt') ?></th>
                            <th width="140"><?= et('IP Address') ?></th>
                            <th><?= et('User Agent') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while($row = $loginResult->fetchArray(SQLITE3_ASSOC)): ?>
                            <tr>
                                <td style="color:var(--text-muted);"><?php echo e(date('d.m.Y H:i', strtotime($row['attempted_at']) ?: time())); ?></td>
                                <td>
                                    <?php if($row['successful']): ?>
                                        <span class="badge badge-success"><i class="fas fa-check"></i> <?= et('Success') ?></span>
                                    <?php else: ?>
                                        <span class="badge badge-danger"><i class="fas fa-times"></i> <?= et('Failed') ?></span>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo e($row['username']); ?></td>
                                <td><span class="ip-addr"><?php echo e($row['ip_address']); ?></span></td>
                                <td style="font-size:0.8rem; color:var(--text-muted); max-width: 300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                                    <?php echo e($row['user_agent']); ?>
                                </td>
                            </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            </div>
        </section>
    </div>

</main>

<script>
    // Simple Tab Switching Logic
    function openTab(evt, tabName) {
        var i, tabcontent, tablinks;
        
        // Hide all content
        tabcontent = document.getElementsByClassName("tab-content");
        for (i = 0; i < tabcontent.length; i++) {
            tabcontent[i].style.display = "none";
            tabcontent[i].classList.remove("active");
        }
        
        // Deactivate all buttons
        tablinks = document.getElementsByClassName("tab-btn");
        for (i = 0; i < tablinks.length; i++) {
            tablinks[i].classList.remove("active");
        }
        
        // Show current tab and activate button
        document.getElementById(tabName).style.display = "block";
        setTimeout(() => document.getElementById(tabName).classList.add("active"), 10);
        evt.currentTarget.classList.add("active");
        
        // Save state to localStorage (keeps tab open after refresh)
        localStorage.setItem('activeLogTab', tabName);
    }

    // Restore Tab on Page Load
    document.addEventListener("DOMContentLoaded", function() {
        const activeTab = localStorage.getItem('activeLogTab') || 'tab-security';
        const tabBtn = document.querySelector(`.tab-btn[onclick*='${activeTab}']`);
        if(tabBtn) {
            tabBtn.click();
        } else {
            document.querySelector('.tab-btn').click();
        }
    });
</script>

</body>
</html>
