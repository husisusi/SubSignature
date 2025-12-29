<?php
$current_page = basename($_SERVER['PHP_SELF']);
?>

<a href="generator.php" class="brand" style="display: flex; align-items: center; gap: 12px; text-decoration: none; color: inherit; margin-bottom: 2rem; padding: 0 0.5rem;">
    
    <img src="img/subsig.svg" alt="SubSignature Logo" style="height: 40px; width: auto; object-fit: contain;">
    
    <div style="display: flex; flex-direction: column; line-height: 1;">
        <span style="font-size: 1.4rem; font-weight: 700; color: var(--text-main);">SubSignature</span>
        <span style="font-size: 0.75rem; color: var(--text-muted); font-weight: 500; margin-left: 2px;">by Husisusi</span>
    </div>
</a>

<nav class="nav-menu">
    <span class="nav-label" style="font-weight: 800; color: #334155;">Main</span>
    
    <a href="generator.php" class="nav-link <?php echo ($current_page == 'generator.php') ? 'active' : ''; ?>">
        <i class="fas fa-pen-nib"></i> <span>Generator</span>
    </a>
    
    <a href="all_signatures.php" class="nav-link <?php echo ($current_page == 'all_signatures.php') ? 'active' : ''; ?>">
        <i class="fas fa-signature"></i> <span>All Signatures</span>
    </a>

    <span class="nav-label" style="font-weight: 800; color: #334155;">Data</span>
    
    <a href="csv_import.php" class="nav-link <?php echo ($current_page == 'csv_import.php') ? 'active' : ''; ?>">
        <i class="fas fa-file-import"></i> <span>Import CSV</span>
    </a>
    
    <a href="export_signatures.php" class="nav-link <?php echo ($current_page == 'export_signatures.php') ? 'active' : ''; ?>">
        <i class="fas fa-file-export"></i> <span>Export CSV</span>
    </a>

    <?php if (isAdmin()): ?>
    <span class="nav-label" style="font-weight: 800; color: #334155;">Admin</span>
    
    <a href="template_editor.php" class="nav-link <?php echo ($current_page == 'template_editor.php') ? 'active' : ''; ?>">
        <i class="fas fa-code"></i> <span>Add/Edit Templates</span>
    </a>
    
    <?php if(file_exists('admin_templates.php')): ?>
    <a href="admin_templates.php" class="nav-link <?php echo ($current_page == 'admin_templates.php') ? 'active' : ''; ?>">
        <i class="fas fa-layer-group"></i> <span>Manage Templates</span>
    </a>
    <?php endif; ?>
    
    <?php if(file_exists('backup_templates.php')): ?>
    <a href="backup_templates.php" class="nav-link <?php echo ($current_page == 'backup_templates.php') ? 'active' : ''; ?>">
        <i class="fas fa-file-zipper"></i> <span>Backup Templates</span>
    </a>
    <?php endif; ?>
    
    <a href="admin_users.php" class="nav-link <?php echo ($current_page == 'admin_users.php') ? 'active' : ''; ?>">
        <i class="fas fa-users"></i> <span>Users</span>
    </a>

    <a href="admin_logs.php" class="nav-link <?php echo ($current_page == 'admin_logs.php') ? 'active' : ''; ?>">
        <i class="fas fa-history"></i> <span>System Logs</span>
    </a>

    <?php endif; ?>

    <span class="nav-label" style="font-weight: 800; color: #334155;">Account</span>
    
    <a href="profile.php" class="nav-link <?php echo ($current_page == 'profile.php') ? 'active' : ''; ?>">
        <i class="fas fa-user-cog"></i> <span>Profile</span>
    </a>

    <a href="change_password.php" class="nav-link <?php echo ($current_page == 'change_password.php') ? 'active' : ''; ?>">
        <i class="fas fa-key"></i> <span>Change Password</span>
    </a>

</nav>
