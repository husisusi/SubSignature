<?php
// admin_images.php

require_once 'includes/config.php';
requireAdmin(); // Maintains your authentication

$message = '';
$error = '';

// ---------------------------------------------------------
// SECURITY: CSRF Token Generation
// ---------------------------------------------------------
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

$upload_dir = __DIR__ . '/img/';

// Ensure the directory exists
if (!is_dir($upload_dir)) {
    mkdir($upload_dir, 0755, true);
}

// Allowed configurations
$allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
$allowed_mimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];

// ---------------------------------------------------------
// 1. ACTION: UPLOAD IMAGES
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['upload_images'])) {
    
    // Security: CSRF Check
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $error = "Security Error: Invalid CSRF Token.";
    } 
    // Check if files exist
    elseif (isset($_FILES['image_files'])) {
        $uploaded_files = $_FILES['image_files'];
        $success_count = 0;
        $error_details = [];

        // Finfo for real MIME-Type check (crucial for security)
        $finfo = finfo_open(FILEINFO_MIME_TYPE);

        for ($i = 0; $i < count($uploaded_files['name']); $i++) {
            $filename = $uploaded_files['name'][$i];
            $tmp_name = $uploaded_files['tmp_name'][$i];
            $file_error = $uploaded_files['error'][$i];

            if ($file_error === UPLOAD_ERR_OK) {
                
                // 1. Security: Check File Extension
                $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
                if (!in_array($ext, $allowed_extensions)) {
                    $error_details[] = "$filename: Only JPG, PNG, GIF and WEBP are allowed.";
                    continue;
                }

                // 2. Security: Check real MIME-Type
                $mime_type = finfo_file($finfo, $tmp_name);
                if (!in_array($mime_type, $allowed_mimes)) {
                    $error_details[] = "$filename: Invalid file type (Fake extension detected).";
                    continue;
                }

                // 3. Security: Is it actually an image? (Prevents image exploits)
                if (@getimagesize($tmp_name) === false) {
                    $error_details[] = "$filename: File is not a valid image.";
                    continue;
                }

                // 4. Security: Sanitize filename (Only a-z, 0-9, - and _)
                $raw_name = pathinfo($filename, PATHINFO_FILENAME);
                $safe_name = preg_replace('/[^a-z0-9_-]/', '', strtolower($raw_name));
                if (empty($safe_name)) {
                    $safe_name = 'img_' . bin2hex(random_bytes(4));
                }
                
                $final_name = $safe_name . '.' . $ext;
                $target_path = $upload_dir . $final_name;

                // Prevent overwriting existing images
                if (file_exists($target_path)) {
                    $final_name = $safe_name . '_' . time() . '.' . $ext;
                    $target_path = $upload_dir . $final_name;
                }

                // Move file
                if (move_uploaded_file($tmp_name, $target_path)) {
                    $success_count++;
                } else {
                    $error_details[] = "$filename: Error saving the file.";
                }
            }
        }
        
        finfo_close($finfo);

        if ($success_count > 0) {
            $message = "Successfully uploaded $success_count image(s).";
        }
        if (!empty($error_details)) {
            $error = implode('<br>', $error_details);
        }
    }
}

// ---------------------------------------------------------
// 2. ACTION: DELETE IMAGE
// ---------------------------------------------------------
if (isset($_GET['delete'])) {
    if (!isset($_GET['token']) || !hash_equals($_SESSION['csrf_token'], $_GET['token'])) {
        $error = "Security Error: Invalid Token.";
    } else {
        // Security: basename() prevents Path Traversal (e.g. delete=../../config.php)
        $image = basename($_GET['delete']);
        $image_path = $upload_dir . $image;
        
        if (file_exists($image_path) && is_file($image_path)) {
            if (unlink($image_path)) {
                $message = "Image deleted successfully.";
            } else {
                $error = "Error deleting file. Check permissions.";
            }
        } else {
            $error = "Image not found!";
        }
    }
    // Clean Redirect
    $param = $error ? 'error='.urlencode($error) : 'message='.urlencode($message);
    header('Location: admin_images.php?' . $param);
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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Image Management - SubSignature</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/all.min.css">
    
    <style>
        .image-preview { width: 50px; height: 50px; object-fit: cover; border-radius: 6px; border: 1px solid #e2e8f0; }
        
        /* Modal Styles */
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.5); display: none; justify-content: center; align-items: center; z-index: 1000; backdrop-filter: blur(2px); }
        .modal-box { background: white; width: 90%; max-width: 500px; padding: 2rem; border-radius: 12px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1); position: relative; }
        .modal-header h3 { margin: 0; color: var(--text-main); font-size: 1.25rem; }
        .modal-close { position: absolute; top: 1rem; right: 1rem; cursor: pointer; color: var(--text-muted); font-size: 1.2rem; }
        
        /* Upload Area */
        .upload-area { border: 2px dashed #cbd5e1; border-radius: 8px; padding: 2rem; text-align: center; cursor: pointer; transition: all 0.2s; background: #f8fafc; position: relative; margin-top: 1rem; }
        .upload-area:hover { border-color: var(--primary); background: #eff6ff; }
        .upload-input { position: absolute; width: 100%; height: 100%; top: 0; left: 0; opacity: 0; cursor: pointer; }
    </style>
</head>
<body>

    <aside class="sidebar">
        <?php include 'includes/navbar.php'; ?>
        
        <div class="sidebar-footer">
            <div class="user-profile">
                <div class="avatar"><?php echo strtoupper(substr($_SESSION['username'] ?? 'A', 0, 1)); ?></div>
                <div class="user-info">
                    <div><?php echo htmlspecialchars($_SESSION['username'] ?? 'Admin'); ?></div>
                    <span>Administrator</span>
                </div>
            </div>
            <a href="logout.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> <span>Sign Out</span></a>
        </div>
    </aside>

    <main class="main-content">
        
        <header class="page-header">
            <h2>Image Management</h2>
            <p>Secure upload and management of images (Logos, Banners, etc.).</p>
        </header>

        <?php if ($message): ?>
            <div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="alert alert-error"><i class="fas fa-exclamation-circle"></i> <?php echo $error; ?></div>
        <?php endif; ?>

        <div class="form-grid" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); margin-bottom: 2rem;">
            <div class="card" style="padding: 1.5rem; text-align:center;">
                <div style="color: #64748b; margin-bottom: 0.5rem;">Total Images</div>
                <div style="font-size: 2rem; font-weight: 700; color: #1e293b;"><?php echo count($images); ?></div>
            </div>
        </div>

        <section class="card">
            <div class="card-header">
                <h3><i class="fas fa-images"></i> Media Library</h3>
                <div style="display:flex; gap: 0.5rem;">
                    <button onclick="openImportModal()" class="btn btn-sm btn-success">
                        <i class="fas fa-upload"></i> Upload Images
                    </button>
                    <a href="img/" target="_blank" class="btn btn-sm btn-secondary">
                        <i class="fas fa-folder-open"></i> Open Folder
                    </a>
                </div>
            </div>
            
            <div style="overflow-x: auto;">
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="background: #f8fafc; text-align: left; border-bottom: 1px solid #e2e8f0;">
                            <th style="padding: 1rem; width: 60px;">Preview</th>
                            <th style="padding: 1rem;">Filename</th>
                            <th style="padding: 1rem;">Size</th>
                            <th style="padding: 1rem;">Uploaded on</th>
                            <th style="padding: 1rem; text-align: right;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($images)): ?>
                            <tr><td colspan="5" style="padding: 2rem; text-align: center; color: #64748b;">No images uploaded yet.</td></tr>
                        <?php endif; ?>
                        
                        <?php foreach ($images as $img): ?>
                        <tr style="border-bottom: 1px solid #e2e8f0;">
                            
                            <td style="padding: 0.5rem 1rem;">
                                <a href="img/<?php echo urlencode($img['filename']); ?>" target="_blank">
                                    <img src="img/<?php echo htmlspecialchars($img['filename']); ?>" class="image-preview" alt="Preview">
                                </a>
                            </td>

                            <td style="padding: 1rem;">
                                <code><?php echo htmlspecialchars($img['filename']); ?></code>
                            </td>
                            
                            <td style="padding: 1rem; color: #64748b;"><?php echo $img['size']; ?></td>
                            
                            <td style="padding: 1rem; color: #64748b;">
                                <?php echo date('d.m.Y H:i', $img['time']); ?>
                            </td>
                            
                            <td style="padding: 1rem; text-align: right;">
                                <div style="display: inline-flex; gap: 0.5rem;">
                                    <a href="img/<?php echo urlencode($img['filename']); ?>" target="_blank" class="btn btn-sm btn-secondary" title="Preview"><i class="fas fa-eye"></i></a>
                                    
                                    <a href="admin_images.php?delete=<?php echo urlencode($img['filename']); ?>&token=<?php echo $csrf_token; ?>" class="btn btn-sm btn-danger" onclick="return confirm('Really delete image?')" title="Delete"><i class="fas fa-trash"></i></a>
                                </div>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </section>

    </main>

    <div id="importModal" class="modal-overlay">
        <div class="modal-box">
            <span class="modal-close" onclick="closeImportModal()">&times;</span>
            <div class="modal-header">
                <h3><i class="fas fa-cloud-upload-alt" style="color:var(--primary);"></i> Upload Images</h3>
                <p style="color:var(--text-muted); font-size:0.9rem; margin-top:0.5rem;">
                    Allowed: <code>.jpg, .jpeg, .png, .gif, .webp</code>
                </p>
            </div>
            
            <form method="POST" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                <input type="hidden" name="upload_images" value="1">
                
                <div class="upload-area" id="dropZone">
                    <input type="file" name="image_files[]" class="upload-input" accept="image/*" multiple required onchange="showFileCount(this)">
                    <i class="fas fa-file-image" style="font-size: 2.5rem; color: #cbd5e1; margin-bottom: 1rem;"></i>
                    <div id="uploadText" style="font-weight: 500; color: var(--text-main);">
                        Click or drag files here
                    </div>
                    <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.5rem;">
                        Files will be automatically safely renamed
                    </div>
                </div>
                
                <div style="display:flex; justify-content:flex-end; gap:0.5rem; margin-top: 1.5rem;">
                    <button type="button" class="btn btn-danger" style="background:white; color:var(--text-main); border:1px solid var(--border);" onclick="closeImportModal()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Upload</button>
                </div>
            </form>
        </div>
    </div>

    <script>
    // --- JS: Modal Logic ---
    const modal = document.getElementById('importModal');
    function openImportModal() { modal.style.display = 'flex'; }
    function closeImportModal() { modal.style.display = 'none'; }
    window.onclick = function(event) { if (event.target == modal) closeImportModal(); }

    // --- JS: File Input Visuals ---
    function showFileCount(input) {
        const text = document.getElementById('uploadText');
        if (input.files && input.files.length > 0) {
            text.innerHTML = `<strong>${input.files.length}</strong> file(s) selected`;
            text.style.color = '#166534';
        } else {
            text.innerHTML = 'Click or drag files here';
            text.style.color = 'var(--text-main)';
        }
    }
    
    // --- JS: Drag & Drop Visuals ---
    const dropZone = document.getElementById('dropZone');
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = 'var(--primary)';
        dropZone.style.background = '#eff6ff';
    });
    dropZone.addEventListener('dragleave', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = '#cbd5e1';
        dropZone.style.background = '#f8fafc';
    });
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = '#166534'; // Success green
        dropZone.style.background = '#f0fdf4';
        
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
