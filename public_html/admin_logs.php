<?php
// admin_logs.php
require_once 'includes/config.php';
requireAdmin(); // Nur für Admins!

// Paginierung / Limits
$limit = 50;

// 1. Hole Security Events (Verknüpft mit Usernamen)
$secQuery = "SELECT s.*, u.username as real_username 
             FROM security_events s 
             LEFT JOIN users u ON s.user_id = u.id 
             ORDER BY s.created_at DESC LIMIT $limit";
$secResult = $db->query($secQuery);

// 2. Hole Login Versuche (Brute Force Watch)
$loginQuery = "SELECT * FROM login_attempts ORDER BY attempted_at DESC LIMIT $limit";
$loginResult = $db->query($loginQuery);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Logs - SubSignature</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/all.min.css">
    <style>
        .log-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
        .log-table th { text-align: left; padding: 10px; background: #f8fafc; border-bottom: 2px solid #e2e8f0; color: #64748b; }
        .log-table td { padding: 8px 10px; border-bottom: 1px solid #f1f5f9; color: #334155; }
        .log-table tr:hover { background: #f8fafc; }
        
        .badge { padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 0.75rem; display: inline-block; }
        .badge-danger { background: #fee2e2; color: #991b1b; } /* Rot */
        .badge-warning { background: #ffedd5; color: #9a3412; } /* Orange */
        .badge-success { background: #dcfce7; color: #166534; } /* Grün */
        .badge-info { background: #e0f2fe; color: #075985; }    /* Blau */
        
        .section-title { margin-top: 2rem; margin-bottom: 1rem; display: flex; align-items: center; justify-content: space-between; }
        .ip-addr { font-family: monospace; color: #64748b; }
    </style>
</head>
<body>

<aside class="sidebar">
    <?php include 'includes/navbar.php'; ?>
    <div class="sidebar-footer">
        <a href="logout.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> Sign Out</a>
    </div>
</aside>

<main class="main-content">
    <header class="page-header">
        <h2>Security Audit Log</h2>
        <p>Monitor system access and security events.</p>
    </header>

    <section class="card">
        <div class="card-header">
            <h3><i class="fas fa-shield-alt"></i> Critical Security Events</h3>
        </div>
        <div style="overflow-x: auto;">
            <table class="log-table">
                <thead>
                    <tr>
                        <th width="140">Time</th>
                        <th width="150">Event</th>
                        <th>User</th>
                        <th>IP Address</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while($row = $secResult->fetchArray(SQLITE3_ASSOC)): ?>
                        <?php 
                            // Farbe bestimmen
                            $cls = 'badge-info';
                            if(strpos($row['event_type'], 'FAILED') !== false) $cls = 'badge-danger';
                            if(strpos($row['event_type'], 'LOCKED') !== false) $cls = 'badge-danger';
                            if(strpos($row['event_type'], 'SUCCESS') !== false) $cls = 'badge-success';
                            if(strpos($row['event_type'], 'RATE') !== false) $cls = 'badge-warning';
                        ?>
                        <tr>
                            <td><?php echo date('M d, H:i:s', strtotime($row['created_at'])); ?></td>
                            <td><span class="badge <?php echo $cls; ?>"><?php echo htmlspecialchars($row['event_type']); ?></span></td>
                            <td>
                                <?php if($row['real_username']): ?>
                                    <strong><?php echo htmlspecialchars($row['real_username']); ?></strong>
                                <?php else: ?>
                                    <span style="color:#ccc;">-</span>
                                <?php endif; ?>
                            </td>
                            <td><span class="ip-addr"><?php echo htmlspecialchars($row['ip_address']); ?></span></td>
                            <td><?php echo htmlspecialchars($row['details']); ?></td>
                        </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
    </section>

    <div class="section-title">
        <h3><i class="fas fa-history"></i> Recent Login Attempts</h3>
    </div>

    <section class="card">
        <div style="overflow-x: auto;">
            <table class="log-table">
                <thead>
                    <tr>
                        <th width="140">Time</th>
                        <th width="100">Status</th>
                        <th>Username Tried</th>
                        <th>IP Address</th>
                        <th>User Agent</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while($row = $loginResult->fetchArray(SQLITE3_ASSOC)): ?>
                        <tr>
                            <td><?php echo date('M d, H:i:s', strtotime($row['attempted_at'])); ?></td>
                            <td>
                                <?php if($row['successful']): ?>
                                    <span class="badge badge-success"><i class="fas fa-check"></i> Success</span>
                                <?php else: ?>
                                    <span class="badge badge-danger"><i class="fas fa-times"></i> Failed</span>
                                <?php endif; ?>
                            </td>
                            <td><?php echo htmlspecialchars($row['username']); ?></td>
                            <td><span class="ip-addr"><?php echo htmlspecialchars($row['ip_address']); ?></span></td>
                            <td style="font-size:0.75rem; color:#94a3b8; max-width: 300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                                <?php echo htmlspecialchars($row['user_agent']); ?>
                            </td>
                        </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
    </section>

</main>
</body>
</html>
