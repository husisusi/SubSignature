<?php
// template_editor.php

require_once 'includes/config.php';
requireAdmin();

// ---------------------------------------------------------------------
// 1. Security: Generate & Verify CSRF Token
// ---------------------------------------------------------------------
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Ensure user is logged in
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header('Location: index.php');
    exit;
}

$message = '';
$error = '';

// Default values
$current_name = '';
$current_content = '<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
</head>
<body>
<div style="font-family: Arial, sans-serif; padding: 10px;">
    <strong>{{NAME}}</strong> | {{ROLE}}<br>
    📧 {{EMAIL}} | 📞 {{PHONE}}<br>
    <hr style="border: 1px solid #eee; margin: 10px 0;">
    <small style="color: #666;">Digital Signature</small>
</div>
</body>
</html>';
$current_file = ''; 

// ---------------------------------------------------------------------
// 2. Handle POST Request
// ---------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Security Error: Invalid CSRF Token.");
    }

    $template_name = trim($_POST['template_name'] ?? '');
    $template_content = $_POST['template_content'] ?? '';
    $action = $_POST['action'] ?? '';
    
    $current_name = $template_name;
    $current_content = $template_content;
    
    $templates_dir = __DIR__ . '/templates';
    if (!is_dir($templates_dir)) {
        mkdir($templates_dir, 0755, true);
    }

    if (empty($template_name)) {
        $error = "Template name is required!";
    } elseif (empty($template_content)) {
        $error = "Template content is required!";
    } else {
        if ($action === 'save_new') {
            $clean_name = preg_replace('/[^a-z0-9_]/i', '_', $template_name);
            $filename = 'signature_' . strtolower($clean_name) . '.html';
            $filepath = $templates_dir . '/' . $filename;
            
            if (file_exists($filepath)) {
                $error = "Template with this name already exists!";
            } else {
                if (file_put_contents($filepath, $template_content) !== false) {
                    $message = "Template created: " . htmlspecialchars($filename);
                    $current_file = $filename;
                } else {
                    $error = "Could not write file. Check permissions.";
                }
            }
        } 
        elseif ($action === 'save_existing') {
            $existing_file = $_POST['existing_file'] ?? '';
            
            if (empty($existing_file)) {
                $error = "No template selected for update!";
            } else {
                $safe_filename = basename($existing_file);
                $filepath = $templates_dir . '/' . $safe_filename;
                
                // Security Check: Verify file really exists in templates dir
                if (file_exists($filepath) && realpath($filepath) === realpath($templates_dir . '/' . $safe_filename)) {
                    if (file_put_contents($filepath, $template_content) !== false) {
                        $message = "Template updated: " . htmlspecialchars($safe_filename);
                        $current_file = $safe_filename;
                    } else {
                        $error = "Could not write file. Check permissions.";
                    }
                } else {
                    $error = "Security Error: Invalid file path.";
                }
            }
        }
    }
}

// ---------------------------------------------------------------------
// 3. Load Existing Templates
// ---------------------------------------------------------------------
$templates = [];
$template_files = glob('templates/*.html');
if ($template_files) {
    foreach ($template_files as $file) {
        $templates[basename($file)] = file_get_contents($file);
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Template Editor - SubSignature</title>
    
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/all.min.css">    
    <link rel="stylesheet" href="js/jodit/jodit.min.css">
    <script src="js/jodit/jodit.min.js"></script>
    
    <style>
        .jodit-container { border-radius: 8px !important; border: 1px solid var(--border) !important; }
        .jodit-toolbar { background: #f8fafc !important; border-bottom: 1px solid var(--border) !important; position: sticky; top: 0; z-index: 10; }
        .jodit-status-bar { border-top: 1px solid var(--border) !important; background: #f8fafc !important; }
        
        .placeholders { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.5rem; padding: 1rem; background: #f8fafc; border-radius: 8px; border: 1px dashed var(--border); }
        .placeholder-btn { background: white; border: 1px solid var(--border); border-radius: 6px; padding: 0.3rem 0.6rem; font-size: 0.85rem; font-family: monospace; color: var(--primary); cursor: pointer; transition: all 0.2s; }
        .placeholder-btn:hover { background: var(--primary); color: white; border-color: var(--primary); }
        
        .preview-wrapper { background: white; border: 1px solid var(--border); border-radius: 8px; padding: 2rem; margin-top: 1rem; box-shadow: inset 0 0 10px rgba(0,0,0,0.02); overflow-x: auto; }
        
        .alert { padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; display: flex; gap: 0.75rem; align-items: center; font-size: 0.95rem; }
        .alert-success { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
        .alert-error { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }

        /* --- NEW COMPACT TOOLBAR GRID --- */
        .editor-toolbar-grid {
            display: grid;
            grid-template-columns: 1fr 1fr auto;
            gap: 1rem;
            align-items: end;
            background: #f8fafc;
            padding: 1.25rem;
            border-radius: 8px;
            border: 1px solid var(--border);
            margin-bottom: 1.5rem;
        }
        
        @media (max-width: 900px) {
            .editor-toolbar-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>

    <aside class="sidebar">
        <?php if (file_exists('includes/navbar.php')) include 'includes/navbar.php'; ?>
        <div class="sidebar-footer">
            <div class="user-profile">
                <div class="avatar">
                    <?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?>
                </div>
                <div class="user-info">
                    <div><?php echo htmlspecialchars($_SESSION['username'], ENT_QUOTES, 'UTF-8'); ?></div>
                    <span>Administrator</span>
                </div>
            </div>
            <a href="logout.php" class="btn-logout">
                <i class="fas fa-sign-out-alt"></i> <span>Sign Out</span>
            </a>
        </div>
    </aside>

    <main class="main-content">
        <header class="page-header">
            <h2>Template Editor</h2>
            <p>Design and manage HTML email signature templates.</p>
        </header>

        <?php if ($message): ?>
            <div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="alert alert-error"><i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>

        <div class="form-grid" style="grid-template-columns: 2fr 1fr; align-items: start;">
            <div style="grid-column: span 2;"> 
                
                <section class="card">
                    <form method="POST" id="editorForm">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

                        <div class="editor-toolbar-grid">
                            
                            <div class="form-group" style="margin-bottom: 0;">
                                <label for="template_selector" style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">
                                    <i class="fas fa-folder-open"></i> Load Existing
                                </label>
                                <select id="template_selector" onchange="loadTemplate(this.value)" style="width: 100%; padding: 0.6rem; border: 1px solid #cbd5e1; border-radius: 6px;">
                                    <option value="">-- Create New Template --</option>
                                    <?php foreach ($templates as $filename => $content): ?>
                                        <?php  
                                        $display_name = ucfirst(str_replace('_', ' ', str_replace(['signature_', '.html'], '', $filename)));
                                        $selected = ($filename === $current_file) ? 'selected' : '';
                                        ?>
                                        <option value="<?php echo htmlspecialchars($filename, ENT_QUOTES, 'UTF-8'); ?>" <?php echo $selected; ?>>
                                            <?php echo htmlspecialchars($display_name, ENT_QUOTES, 'UTF-8'); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <div class="form-group" style="margin-bottom: 0;">
                                <label for="template_name" style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">
                                    <i class="fas fa-tag"></i> Template Name
                                </label>
                                <input type="text" id="template_name" name="template_name"  
                                      value="<?php echo htmlspecialchars($current_name, ENT_QUOTES, 'UTF-8'); ?>"
                                      placeholder="e.g. Modern Blue" required 
                                      style="width: 100%; padding: 0.6rem; font-weight: 600; border: 1px solid #cbd5e1; border-radius: 6px;">
                            </div>

                            <div style="display: flex; gap: 0.5rem;">
                                <button type="submit" name="action" value="save_new" class="btn btn-primary" title="Create as new file"><i class="fas fa-plus"></i> Create</button>
                                <button type="submit" name="action" value="save_existing" class="btn btn-success" id="saveExistingBtn" <?php echo empty($current_file) ? 'disabled' : ''; ?> title="Overwrite existing file"><i class="fas fa-save"></i> Save</button>
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <label style="font-size: 0.85rem; font-weight: 600; color: #64748b;"><i class="fas fa-magic"></i> Insert Dynamic Variable:</label>
                            <div class="placeholders">
                                <button type="button" onclick="insertPlaceholder('{{NAME}}')" class="placeholder-btn">{{NAME}}</button>
                                <button type="button" onclick="insertPlaceholder('{{ROLE}}')" class="placeholder-btn">{{ROLE}}</button>
                                <button type="button" onclick="insertPlaceholder('{{EMAIL}}')" class="placeholder-btn">{{EMAIL}}</button>
                                <button type="button" onclick="insertPlaceholder('{{PHONE}}')" class="placeholder-btn">{{PHONE}}</button>
                                <div style="width: 1px; background: #e2e8f0; margin: 0 5px;"></div>
                                <button type="button" onclick="insertPlaceholder('<br>')" class="placeholder-btn">&lt;br&gt;</button>
                                <button type="button" onclick="insertPlaceholder('<hr>')" class="placeholder-btn">&lt;hr&gt;</button>
                            </div>
                        </div>

                        <div class="form-group">
                            <textarea id="template_content" name="template_content" class="fallback-editor"><?php echo htmlspecialchars($current_content, ENT_QUOTES, 'UTF-8'); ?></textarea>
                            <div id="editor_warning" style="display:none; color:red; margin-top:0.5rem;">Jodit Editor could not load.</div>
                        </div>

                        <div class="form-actions" style="justify-content: space-between; margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--border);">
                            <div>
                                <button type="button" onclick="clearEditor()" class="btn btn-sm btn-danger" style="background:transparent; color:var(--danger); border:1px solid var(--border);"><i class="fas fa-trash-alt"></i> Clear All</button>
                                <button type="button" onclick="loadDefaultTemplate()" class="btn btn-sm btn-secondary" style="background:transparent; color:var(--text-muted); border:1px solid var(--border);"><i class="fas fa-undo"></i> Reset Default</button>
                            </div>
                            <input type="hidden" id="existing_file" name="existing_file" value="<?php echo htmlspecialchars($current_file, ENT_QUOTES, 'UTF-8'); ?>">
                        </div>
                    </form>
                </section>
                
                <section class="card">
                    <div class="card-header">
                        <h3><i class="fas fa-eye"></i> Live Preview</h3>
                        <button onclick="updatePreview()" class="btn btn-sm btn-secondary"><i class="fas fa-sync-alt"></i> Refresh</button>
                    </div>
                    <div class="preview-wrapper"><div id="live_preview"></div></div>
                </section>

            </div>
        </div>
    </main>

    <script>
    var editorInstance = null;
    
    document.addEventListener('DOMContentLoaded', function() {
        if (typeof Jodit === 'undefined') {
            document.getElementById('editor_warning').style.display = 'block';
            return;
        }
        
        var textarea = document.getElementById('template_content');
        if (!textarea) return;
        
        try {
            editorInstance = Jodit.make(textarea, {
                height: 450,
                width: '100%',
                theme: 'default',
                
                // --- STRICT SECURITY SETTINGS ---
                useAceEditor: false,
                sourceEditor: 'area',
                beautifyHTML: false,
                sourceEditorCDN: null,
                source: false,
                // --------------------------------

                toolbar: true,
                toolbarButtonSize: 'middle',
                buttons: [
                    'source', '|',  
                    'bold', 'italic', 'underline', 'strikethrough', '|',
                    'font', 'fontsize', 'brush', 'paragraph', '|',
                    'ul', 'ol', 'align', '|',
                    'image', 'table', 'link', 'hr', '|',
                    'undo', 'redo', '|',
                    'fullsize', 'preview'
                ],
                allowResizeX: false,
                allowResizeY: true,
                spellcheck: false,
                cleanHTML: {
                    fillEmptyParagraph: false,
                    denyTags: 'script,iframe,object,embed'
                },
                events: {
                    afterInit: function(editor) { updatePreview(); },
                    change: function() { updatePreview(); }
                }
            });
        } catch (error) {
            console.error('Failed to initialize Jodit:', error);
            document.getElementById('editor_warning').style.display = 'block';
        }
    });
    
    function insertPlaceholder(placeholder) {
        if (editorInstance && editorInstance.selection) {
            editorInstance.selection.insertHTML(placeholder);
        } else {
            var textarea = document.getElementById('template_content');
            textarea.value = textarea.value + placeholder;
            updatePreview();
        }
    }
    
    function loadTemplate(filename) {
        if (!filename) {
            // Reset to new state
            document.getElementById('template_name').value = '';
            document.getElementById('existing_file').value = '';
            document.getElementById('saveExistingBtn').disabled = true;
            loadDefaultTemplate();
            return;
        }
        
        // Securely fetch template content via JS
        fetch('load_template.php?file=' + encodeURIComponent(filename))
            .then(response => {
                if(!response.ok) throw new Error('Failed to load');
                return response.text();
            })
            .then(content => {
                if (editorInstance) editorInstance.value = content;
                else document.getElementById('template_content').value = content;
                
                // Pretty name from filename
                var displayName = filename.replace('signature_', '').replace('.html', '');
                displayName = displayName.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
                
                document.getElementById('template_name').value = displayName;
                document.getElementById('existing_file').value = filename;
                document.getElementById('saveExistingBtn').disabled = false;
                
                updatePreview();
            })
            .catch(err => alert('Error loading template: ' + err));
    }
    
    function loadDefaultTemplate() {
        var defaultTpl = '<!DOCTYPE html>\n<html>\n<head><meta charset="UTF-8"></head>\n<body>\n<div style="font-family: Arial;">\n{{NAME}} | {{ROLE}}\n</div>\n</body>\n</html>';
        if (editorInstance) editorInstance.value = defaultTpl;
        else document.getElementById('template_content').value = defaultTpl;
        updatePreview();
    }
    
    function updatePreview() {
        var content = editorInstance ? editorInstance.value : document.getElementById('template_content').value;
        // Simple client-side replacement for preview
        var preview = content
            .replace(/{{NAME}}/g, 'John Doe')
            .replace(/{{ROLE}}/g, 'Senior Developer')
            .replace(/{{EMAIL}}/g, 'john.doe@company.com')
            .replace(/{{PHONE}}/g, '+49 89 12345678');
        
        document.getElementById('live_preview').innerHTML = preview;
    }
    
    function clearEditor() {
        if(confirm('Clear all content?')) {
            if(editorInstance) editorInstance.value = '';
            else document.getElementById('template_content').value = '';
        }
    }

    // Client-side validation
    document.getElementById('editorForm').addEventListener('submit', function(e) {
        if(!document.getElementById('template_name').value.trim()) {
            e.preventDefault();
            alert('Template Name is required');
        }
    });
    </script>
</body>
</html>
