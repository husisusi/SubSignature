<?php
// admin_images.php - upload, list and delete images used by signature templates.

require_once 'includes/config.php';
requireStaff();

$message = popFlash('success');
$error = popFlash('error');
$csrf_token = generateCSRFToken();

$upload_dir = IMAGES_DIR . '/';
if (!is_dir($upload_dir)) {
    mkdir($upload_dir, 0755, true);
}

// Allowed configurations
$allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
$allowed_mimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
$max_file_size = 5 * 1024 * 1024; // max 5 MB per file
$max_files_per_upload = 20;

// ---------------------------------------------------------
// 1. ACTION: UPLOAD IMAGES
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['upload_images'])) {
    
    requireCsrf();
    if (isset($_FILES['image_files']) && is_array($_FILES['image_files']['name'])) {
        $uploaded_files = $_FILES['image_files'];
        $success_count = 0;
        $error_details = [];

        // Finfo for real MIME-Type check (crucial for security)
        $finfo = finfo_open(FILEINFO_MIME_TYPE);

        for ($i = 0; $i < min(count($uploaded_files['name']), $max_files_per_upload); $i++) {
            $filename = cleanText(basename((string)$uploaded_files['name'][$i]), 120);
            $tmp_name = $uploaded_files['tmp_name'][$i];
            $file_error = $uploaded_files['error'][$i];
            $file_size = $uploaded_files['size'][$i];

            if ($file_error === UPLOAD_ERR_OK) {
                
                // 1. Security: Check if file was actually uploaded via HTTP POST
                if (!is_uploaded_file($tmp_name)) {
                    $error_details[] = "$filename: Security Error - invalid upload source.";
                    continue;
                }

                // 2. Security: Check File Size
                if ($file_size > $max_file_size) {
                    $error_details[] = t('{file}: File is too large (Max 5MB).', ['file' => $filename]);
                    continue;
                }

                // 3. Security: Check File Extension
                $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
                if (!in_array($ext, $allowed_extensions)) {
                    $error_details[] = "$filename: Only JPG, PNG, GIF and WEBP are allowed.";
                    continue;
                }

                // 4. Security: Check real MIME-Type
                $mime_type = finfo_file($finfo, $tmp_name);
                if (!in_array($mime_type, $allowed_mimes)) {
                    $error_details[] = "$filename: Invalid file type (Fake extension detected).";
                    continue;
                }

                // 5. Security: Is it actually an image? (Prevents image exploits)
                if (@getimagesize($tmp_name) === false) {
                    $error_details[] = "$filename: File is not a valid image.";
                    continue;
                }

                // 6. Security: Sanitize filename (Only a-z, 0-9, - and _)
                $raw_name = pathinfo($filename, PATHINFO_FILENAME);
                $safe_name = substr(preg_replace('/[^a-z0-9_-]/', '', strtolower($raw_name)), 0, 60);
                if (empty($safe_name)) {
                    $safe_name = 'img_' . bin2hex(random_bytes(4));
                }
                
                $final_name = $safe_name . '.' . $ext;
                $target_path = $upload_dir . $final_name;

                // Prevent overwriting existing images
                if (file_exists($target_path)) {
                    $final_name = $safe_name . '_' . bin2hex(random_bytes(3)) . '.' . $ext;
                    $target_path = $upload_dir . $final_name;
                }

                // Move file
                if (move_uploaded_file($tmp_name, $target_path)) {
                    @chmod($target_path, 0644);
                    $success_count++;
                } else {
                    $error_details[] = "$filename: Error saving the file.";
                }
            } elseif ($file_error !== UPLOAD_ERR_NO_FILE) {
                $error_details[] = "$filename: Upload failed (error code $file_error).";
            }
        }

        finfo_close($finfo);

        if ($success_count > 0) {
            $message = t('Successfully uploaded {count} image(s).', ['count' => $success_count]);
            logSecurityEventToDB($db, 'IMAGES_UPLOADED', (int)$_SESSION['user_id'], "Count: $success_count");
        }
        if (!empty($error_details)) {
            $error = implode("\n", $error_details); // escaped and line-broken in the view
        }
    }
}

// ---------------------------------------------------------
// 2. ACTION: DELETE IMAGE
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'delete_image') {
    requireCsrf();
    // basename() blocks path traversal; the extension whitelist protects non-raster assets (logo.svg etc.).
    $image = basename((string)($_POST['image'] ?? ''));
    $ext = strtolower(pathinfo($image, PATHINFO_EXTENSION));
    $image_path = $upload_dir . $image;

    if (in_array($ext, $allowed_extensions, true) && is_file($image_path) && isPathInside($image_path, IMAGES_DIR)) {
        if (unlink($image_path)) {
            logSecurityEventToDB($db, 'IMAGE_DELETED', (int)$_SESSION['user_id'], $image);
            setFlash('success', t('Image deleted successfully.'));
        } else {
            setFlash('error', t('Error deleting file. Check permissions.'));
        }
    } else {
        setFlash('error', t('Image not found!'));
    }
    header('Location: admin_images.php');
    exit;
}

// ---------------------------------------------------------
// 3. LOAD DATA
// ---------------------------------------------------------
$images = [];
// Uses glob with GLOB_BRACE to find multiple extensions at once
$image_files = glob($upload_dir . '*.{jpg,jpeg,png,gif,webp}', GLOB_BRACE);

if ($image_files) {
    foreach ($image_files as $file) {
        $filename = basename($file);
        $filesize = filesize($file);
        
        // Format size
        if ($filesize >= 1048576) {
            $size_str = number_format($filesize / 1048576, 2) . ' MB';
        } else {
            $size_str = number_format($filesize / 1024, 2) . ' KB';
        }

        $images[] = [
            'filename' => $filename,
            'size' => $size_str,
            'time' => filemtime($file)
        ];
    }
    
    // Sort: Newest images first
    usort($images, function($a, $b) {
        return $b['time'] - $a['time'];
    });
}

if (isset($_GET['message'])) $message = $_GET['message'];
if (isset($_GET['error'])) $error = $_GET['error'];
?>
<!DOCTYPE html>
<html lang="<?= e(currentLang()) ?>" dir="<?= e(langDir()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= et('Image Management') ?> - SubSignature</title>
    <?= i18nHead() ?>
    <script src="<?= assetUrl('js/theme.js') ?>"></script>
    <link rel="stylesheet" href="<?= assetUrl('css/theme.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/style.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/all.min.css') ?>">
    <?php echo csrfMeta(); ?>
    
    <style>
        .image-preview { 
            width: 50px; 
            height: 50px; 
            object-fit: cover; 
            border-radius: 6px; 
            border: 1px solid var(--border); 
            cursor: zoom-in; 
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        .image-preview:hover {
            transform: scale(1.15);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        
        /* Modal Styles */
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.5); display: none; justify-content: center; align-items: center; z-index: 1000; backdrop-filter: blur(2px); }
        .modal-box { background: var(--bg-white); width: 90%; max-width: 500px; padding: 2rem; border-radius: 12px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1); position: relative; }
        .modal-header h3 { margin: 0; color: var(--text-main); font-size: 1.25rem; }
        .modal-close { position: absolute; top: 1rem; right: 1rem; cursor: pointer; color: var(--text-muted); font-size: 1.2rem; }
        
        /* Lightbox Styles */
        #lightboxOverlay { background: rgba(0, 0, 0, 0.85); z-index: 2000; flex-direction: column; }
        #lightboxClose { position: absolute; top: 20px; right: 30px; color: white; font-size: 3rem; cursor: pointer; transition: color 0.2s; }
        #lightboxClose:hover { color: var(--border-strong); }
        .lightbox-img { max-width: 90%; max-height: 80vh; border-radius: 8px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); object-fit: contain; }
        .lightbox-caption { color: white; margin-top: 15px; font-family: monospace; font-size: 1.1rem; background: rgba(0,0,0,0.5); padding: 5px 15px; border-radius: 20px;}

        /* Upload Area */
        .upload-area { border: 2px dashed var(--border-strong); border-radius: 8px; padding: 2rem; text-align: center; cursor: pointer; transition: all 0.2s; background: var(--bg-subtle); position: relative; margin-top: 1rem; }
        .upload-area:hover { border-color: var(--primary); background: var(--bg-hover); }
        .upload-input { position: absolute; width: 100%; height: 100%; top: 0; left: 0; opacity: 0; cursor: pointer; }
    </style>
</head>
<body>

    <aside class="sidebar">
        <?php include 'includes/navbar.php'; ?>
        
        <div class="sidebar-footer">
        <?= langSwitcher() ?>
            <div class="user-profile">
                <div class="avatar"><?php echo strtoupper(substr($_SESSION['username'] ?? 'A', 0, 1)); ?></div>
                <div class="user-info">
                    <div><?php echo e($_SESSION['username'] ?? 'Admin'); ?></div>
                    <span><?= eRoleLabel() ?></span>
                </div>
            </div>
            <a href="logout.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> <span><?= et('Sign Out') ?></span></a>
        </div>
    </aside>

    <main class="main-content">
        
        <header class="page-header">
            <h2><?= et('Image Management') ?></h2>
            <p><?= et('Secure upload and management of images (Logos, Banners, etc.).') ?></p>
        </header>

        <?php if ($message): ?>
            <div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo e($message); ?></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="alert alert-error"><i class="fas fa-exclamation-circle"></i> <?php echo nl2br(e($error)); ?></div>
        <?php endif; ?>

        <div class="form-grid" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); margin-bottom: 2rem;">
            <div class="card" style="padding: 1.5rem; text-align:center;">
                <div style="color: var(--text-muted); margin-bottom: 0.5rem;"><?= et('Total Images') ?></div>
                <div style="font-size: 2rem; font-weight: 700; color: var(--text-main);"><?php echo count($images); ?></div>
            </div>
        </div>

        <section class="card">
            <div class="card-header">
                <h3><i class="fas fa-images"></i> <?= et('Media Library') ?></h3>
                <div style="display:flex; gap: 0.5rem;">
                    <button onclick="openImportModal()" class="btn btn-sm btn-success">
                        <i class="fas fa-upload"></i> <?= et('Upload Images') ?>
                    </button>
                    <a href="img/" target="_blank" class="btn btn-sm btn-secondary">
                        <i class="fas fa-folder-open"></i> <?= et('Open Folder') ?>
                    </a>
                </div>
            </div>
            
            <div style="overflow-x: auto;">
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="background: var(--bg-subtle); text-align: left; border-bottom: 1px solid var(--border);">
                            <th style="padding: 1rem; width: 60px;"><?= et('Preview') ?></th>
                            <th style="padding: 1rem;"><?= et('Filename') ?></th>
                            <th style="padding: 1rem;"><?= et('Size') ?></th>
                            <th style="padding: 1rem;"><?= et('Uploaded on') ?></th>
                            <th style="padding: 1rem; text-align: right;"><?= et('Actions') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($images)): ?>
                            <tr><td colspan="5" style="padding: 2rem; text-align: center; color: var(--text-muted);"><?= et('No images uploaded yet.') ?></td></tr>
                        <?php endif; ?>
                        
                        <?php foreach ($images as $img): ?>
                        <tr style="border-bottom: 1px solid var(--border);">
                            
                            <td style="padding: 0.5rem 1rem;">
                                <!-- Enhanced Clickable Preview -->
                                <img src="img/<?php echo e($img['filename']); ?>" 
                                     class="image-preview" 
                                     alt="<?= et('Preview') ?>"
                                     onclick="openLightbox('img/<?php echo rawurlencode($img['filename']); ?>', '<?php echo e($img['filename']); ?>')">
                            </td>

                            <td style="padding: 1rem;">
                                <code><?php echo e($img['filename']); ?></code>
                            </td>
                            
                            <td style="padding: 1rem; color: var(--text-muted);"><?php echo $img['size']; ?></td>
                            
                            <td style="padding: 1rem; color: var(--text-muted);">
                                <?php echo date('d.m.Y H:i', $img['time']); ?>
                            </td>
                            
                            <td style="padding: 1rem; text-align: right;">
                                <div style="display: inline-flex; gap: 0.5rem;">
                                    <button onclick="openLightbox('img/<?php echo rawurlencode($img['filename']); ?>', '<?php echo e($img['filename']); ?>')" class="btn btn-sm btn-secondary" title="<?= et('View Full Image') ?>"><i class="fas fa-eye"></i></button>
                                    
                                    <button type="button" data-post="admin_images.php" data-params='{"action":"delete_image","image":"<?php echo e($img['filename']); ?>"}' data-confirm="<?= et('Really delete image?') ?>" class="btn btn-sm btn-danger" title="<?= et('Delete') ?>"><i class="fas fa-trash"></i></button>
                                </div>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </section>

    </main>

    <!-- Upload Modal -->
    <div id="importModal" class="modal-overlay">
        <div class="modal-box">
            <span class="modal-close" onclick="closeImportModal()">&times;</span>
            <div class="modal-header">
                <h3><i class="fas fa-cloud-upload-alt" style="color:var(--primary);"></i> <?= et('Upload Images') ?></h3>
                <p style="color:var(--text-muted); font-size:0.9rem; margin-top:0.5rem;">
                    <?= eth('Allowed: {types} (Max 5MB)', ['types' => '<code>.jpg, .jpeg, .png, .gif, .webp</code>']) ?>
                </p>
            </div>
            
            <form method="POST" enctype="multipart/form-data">
                <?php echo csrfField(); ?>
                <input type="hidden" name="upload_images" value="1">
                
                <div class="upload-area" id="dropZone">
                    <input type="file" name="image_files[]" class="upload-input" accept="image/*" multiple required onchange="showFileCount(this)">
                    <i class="fas fa-file-image" style="font-size: 2.5rem; color: var(--border-strong); margin-bottom: 1rem;"></i>
                    <div id="uploadText" style="font-weight: 500; color: var(--text-main);">
                        <?= et('Click or drag files here') ?>
                    </div>
                    <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.5rem;">
                        <?= et('Files will be automatically safely renamed') ?>
                    </div>
                </div>
                
                <div style="display:flex; justify-content:flex-end; gap:0.5rem; margin-top: 1.5rem;">
                    <button type="button" class="btn btn-danger" style="background:var(--bg-white); color:var(--text-main); border:1px solid var(--border);" onclick="closeImportModal()"><?= et('Cancel') ?></button>
                    <button type="submit" class="btn btn-primary"><?= et('Upload') ?></button>
                </div>
            </form>
        </div>
    </div>

    <!-- Lightbox Modal for Image Previews -->
    <div id="lightboxOverlay" class="modal-overlay" onclick="closeLightbox()">
        <span id="lightboxClose" onclick="closeLightbox()">&times;</span>
        <img id="lightboxImage" class="lightbox-img" src="" alt="<?= et('Full Preview') ?>">
        <div id="lightboxCaption" class="lightbox-caption"></div>
    </div>

    <script src="<?= assetUrl('js/post-action.js') ?>"></script>
    <script>
    // --- JS: Upload Modal Logic ---
    const modal = document.getElementById('importModal');
    function openImportModal() { modal.style.display = 'flex'; }
    function closeImportModal() { modal.style.display = 'none'; }
    
    // --- JS: Lightbox Logic  ---
    const lightbox = document.getElementById('lightboxOverlay');
    const lightboxImg = document.getElementById('lightboxImage');
    const lightboxCap = document.getElementById('lightboxCaption');
    
    function openLightbox(src, filename) {
        lightboxImg.src = src;
        lightboxCap.innerText = filename;
        lightbox.style.display = 'flex';
    }
    
    function closeLightbox() {
        lightbox.style.display = 'none';
        lightboxImg.src = ''; // Clear source so it doesn't flash old image next time
    }

    // Close modals on background click
    window.onclick = function(event) { 
        if (event.target == modal) closeImportModal(); 
        if (event.target == lightbox) closeLightbox();
    }

    // --- JS: File Input Visuals ---
    function showFileCount(input) {
        const text = document.getElementById('uploadText');
        if (input.files && input.files.length > 0) {
            text.innerHTML = `<strong>${input.files.length}</strong> ` + <?= tj('file(s) selected') ?>;
            text.style.color = 'var(--success-text)';
        } else {
            text.innerHTML = <?= tj('Click or drag files here') ?>;
            text.style.color = 'var(--text-main)';
        }
    }
    
    // --- JS: Drag & Drop Visuals ---
    const dropZone = document.getElementById('dropZone');
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = 'var(--primary)';
        dropZone.style.background = 'var(--bg-hover)';
    });
    dropZone.addEventListener('dragleave', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = 'var(--border-strong)';
        dropZone.style.background = 'var(--bg-subtle)';
    });
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = 'var(--success-text)'; // Success green
        dropZone.style.background = 'var(--success-bg)';
        
        const input = dropZone.querySelector('input');
        input.files = e.dataTransfer.files;
        showFileCount(input);
    });

    // Auto-hide alerts
    setTimeout(() => {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(el => el.style.display = 'none');
    }, 5000);
    </script>
</body>
</html>
