<?php
// Shared sidebar navigation (admin entries only for administrators)
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
    <span class="nav-label" style="font-weight: 800; color: var(--text-main);"><?= et('Main') ?></span>
    
    <a href="generator.php" class="nav-link <?php echo ($current_page == 'generator.php') ? 'active' : ''; ?>">
        <i class="fas fa-pen-nib"></i> <span><?= et('Generator') ?></span>
    </a>
    
    <a href="all_signatures.php" class="nav-link <?php echo ($current_page == 'all_signatures.php') ? 'active' : ''; ?>">
        <i class="fas fa-signature"></i> <span><?= et('All Signatures') ?></span>
    </a>

    <span class="nav-label" style="font-weight: 800; color: var(--text-main);"><?= et('Data') ?></span>
    
    <a href="csv_import.php" class="nav-link <?php echo ($current_page == 'csv_import.php') ? 'active' : ''; ?>">
        <i class="fas fa-file-import"></i> <span><?= et('Import') ?></span>
    </a>
    
    <a href="export_signatures.php" class="nav-link <?php echo ($current_page == 'export_signatures.php') ? 'active' : ''; ?>">
        <i class="fas fa-file-export"></i> <span><?= et('Export') ?></span>
    </a>

    <?php if (isAdmin()): ?>
    <span class="nav-label" style="font-weight: 800; color: var(--text-main);"><?= et('Admin') ?></span>
    
    <a href="template_editor.php" class="nav-link <?php echo ($current_page == 'template_editor.php') ? 'active' : ''; ?>">
        <i class="fas fa-code"></i> <span><?= et('Add/Edit Templates') ?></span>
    </a>
    
    <?php if(file_exists('admin_templates.php')): ?>
    <a href="admin_templates.php" class="nav-link <?php echo ($current_page == 'admin_templates.php') ? 'active' : ''; ?>">
        <i class="fas fa-layer-group"></i> <span><?= et('Manage Templates') ?></span>
    </a>

    <?php endif; ?>

    <?php if(file_exists('admin_images.php')): ?>
    <a href="admin_images.php" class="nav-link <?php echo ($current_page == 'admin_images.php') ? 'active' : ''; ?>">
        <i class="fas fa-images"></i> <span><?= et('Manage Images') ?></span>
    </a>

    <?php endif; ?>
    
    <?php if(file_exists('backup_templates.php')): ?>
    <a href="backup_templates.php" class="nav-link <?php echo ($current_page == 'backup_templates.php') ? 'active' : ''; ?>">
        <i class="fas fa-file-zipper"></i> <span><?= et('Backup Templates') ?></span>
    </a>
    <?php endif; ?>
    
    <a href="admin_users.php" class="nav-link <?php echo ($current_page == 'admin_users.php') ? 'active' : ''; ?>">
        <i class="fas fa-users"></i> <span><?= et('Users') ?></span>
    </a>

    <a href="admin_ldap.php" class="nav-link <?php echo ($current_page == 'admin_ldap.php') ? 'active' : ''; ?>">
        <i class="fas fa-sitemap"></i> <span><?= et('LDAP Import') ?></span>
    </a>

    <a href="admin_api.php" class="nav-link <?php echo ($current_page == 'admin_api.php') ? 'active' : ''; ?>">
        <i class="fas fa-plug"></i> <span><?= et('API Tokens') ?></span>
    </a>

    <a href="admin_config.php" class="nav-link <?php echo ($current_page == 'admin_config.php') ? 'active' : ''; ?>">
        <i class="fas fa-cog"></i> <span><?= et('System Configuration') ?></span>
    </a>

    <a href="admin_logs.php" class="nav-link <?php echo ($current_page == 'admin_logs.php') ? 'active' : ''; ?>">
        <i class="fas fa-history"></i> <span><?= et('System Logs') ?></span>
    </a>

    <?php endif; ?>

    <span class="nav-label" style="font-weight: 800; color: var(--text-main);"><?= et('Account') ?></span>
    
    <a href="profile.php" class="nav-link <?php echo ($current_page == 'profile.php') ? 'active' : ''; ?>">
        <i class="fas fa-user-cog"></i> <span><?= et('Profile') ?></span>
    </a>

    <a href="change_password.php" class="nav-link <?php echo ($current_page == 'change_password.php') ? 'active' : ''; ?>">
        <i class="fas fa-key"></i> <span><?= et('Change Password') ?></span>
    </a>

    <a href="about.php" class="nav-link <?php echo ($current_page == 'about.php') ? 'active' : ''; ?>">
        <i class="fas fa-info-circle"></i> <span><?= et('About') ?></span>
    </a>

</nav>
