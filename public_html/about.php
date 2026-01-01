<?php
// about.php
require_once 'includes/config.php';
requireLogin(); // Security Prio 1: Only logged-in users can see this

// Application Meta Data
$appVersion = '1.2.0';
$phpVersion = phpversion();
$serverSoftware = $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>About - SubSignature</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/all.min.css">
    <style>
        .about-hero {
            text-align: center;
            padding: 2rem 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 2rem;
        }
        .about-logo {
            height: 80px;
            width: auto;
            margin-bottom: 1rem;
        }
        .about-title {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text-main);
            margin-bottom: 0.5rem;
        }
        .about-badge {
            background: #e0e7ff;
            color: var(--primary);
            padding: 4px 12px;
            border-radius: 99px;
            font-size: 0.85rem;
            font-weight: 600;
            display: inline-block;
        }
        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        .feature-item {
            padding: 1rem;
            background: #f8fafc;
            border-radius: 8px;
            border: 1px solid var(--border);
        }
        .feature-icon {
            color: var(--primary);
            font-size: 1.25rem;
            margin-bottom: 0.5rem;
        }
        .feature-title { font-weight: 600; color: var(--text-main); margin-bottom: 0.25rem; }
        .feature-desc { font-size: 0.85rem; color: var(--text-muted); }
        
        .tech-table { width: 100%; font-size: 0.9rem; }
        .tech-table td { padding: 8px 0; border-bottom: 1px dashed var(--border); }
        .tech-table td:first-child { color: var(--text-muted); font-weight: 500; width: 140px; }
        .tech-table td:last-child { color: var(--text-main); font-weight: 600; text-align: right; }
        .tech-table tr:last-child td { border-bottom: none; }
    </style>
</head>
<body>

    <aside class="sidebar">
        <?php include 'includes/navbar.php'; ?>
        <div class="sidebar-footer">
            <div class="user-profile">
                <div class="avatar">
                    <?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?>
                </div>
                <div class="user-info">
                    <div><?php echo htmlspecialchars($_SESSION['username']); ?></div>
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
            <h2>About</h2>
            <p>System information and credits.</p>
        </header>

        <section class="card">
            
            <div class="about-hero">
                <img src="img/subsig.svg" alt="SubSignature" class="about-logo">
                <h1 class="about-title">SubSignature</h1>
                <span class="about-badge">Version <?php echo $appVersion; ?></span>
                <p style="margin-top: 1rem; color: var(--text-muted); max-width: 600px; margin-left: auto; margin-right: auto;">
                    A secure, self-hosted, and offline-first email signature generator designed for privacy and ease of use.
                </p>
            </div>

            <div class="feature-grid">
                <div class="feature-item">
                    <div class="feature-icon"><i class="fas fa-shield-alt"></i></div>
                    <div class="feature-title">Security First</div>
                    <div class="feature-desc">Brute-force protection, rate limiting, and comprehensive audit logs.</div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon"><i class="fas fa-wifi"></i></div>
                    <div class="feature-title">100% Offline</div>
                    <div class="feature-desc">No external requests to CDNs. Fully GDPR compliant and privacy-focused.</div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon"><i class="fas fa-database"></i></div>
                    <div class="feature-title">SQLite Powered</div>
                    <div class="feature-desc">Lightweight, file-based database architecture without complex setup.</div>
                </div>
            </div>

            <div class="form-grid">
                
                <div>
                    <h3 style="margin-bottom: 1rem; font-size: 1.1rem;">System Information</h3>
                    <table class="tech-table">
                        <tr>
                            <td>App Version</td>
                            <td>v<?php echo $appVersion; ?></td>
                        </tr>
                        <tr>
                            <td>Release Date</td>
                            <td>Jan 2026</td>
                        </tr>
                        <tr>
                            <td>PHP Version</td>
                            <td><?php echo htmlspecialchars($phpVersion); ?></td>
                        </tr>
                        <tr>
                            <td>Database</td>
                            <td>SQLite3</td>
                        </tr>
                        <tr>
                            <td>Server API</td>
                            <td><?php echo htmlspecialchars(php_sapi_name()); ?></td>
                        </tr>
                    </table>
                </div>

                <div>
                    <h3 style="margin-bottom: 1rem; font-size: 1.1rem;">Credits & Licenses</h3>
                    <table class="tech-table">
                        <tr>
                            <td>Developed by</td>
                            <td>Husisusi</td>
                        </tr>
                        <tr>
                            <td>License</td>
                            <td>MIT License</td>
                        </tr>
                        <tr>
                            <td>Editor Engine</td>
                            <td>Jodit (MIT)</td>
                        </tr>
                        <tr>
                            <td>Icons</td>
                            <td>FontAwesome Free</td>
                        </tr>
                        <tr>
                            <td>Source Code</td>
                            <td><a href="https://github.com/husisusi/SubSignature" target="_blank" style="color:var(--primary); text-decoration:none;">GitHub Repo <i class="fas fa-external-link-alt" style="font-size:0.7rem;"></i></a></td>
                        </tr>
                    </table>
                </div>

            </div>

            <div style="margin-top: 2rem; text-align: center; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--text-muted); font-size: 0.85rem;">
                &copy; <?php echo date('Y'); ?> SubSignature. Made with <i class="fas fa-heart" style="color:#ef4444;"></i> and PHP.
            </div>

        </section>

    </main>
</body>
</html>
