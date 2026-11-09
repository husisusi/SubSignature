<?php
// template_editor.php - HTML editor for signature templates (admin only).

// The bundled code editor (Ace) needs 'unsafe-eval' in the Content-Security-Policy.
// Only this page relaxes the policy, no other page does.
define('CSP_ALLOW_EVAL', true);

require_once 'includes/config.php';
requireAdmin();

const EDITOR_MAX_BYTES = 524288; // 512 KB

$message = popFlash('success');
$error = popFlash('error');

// Variables for the editor state
$current_name = '';
$current_file = ''; 
// Fallback content if no template exists at all
$current_content = '<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
</head>
<body>
<div style="font-family: Arial, sans-serif; padding: 10px;">
    <strong>{{NAME}}</strong> | {{ROLE}}<br>
    📧 {{EMAIL}} | 📞 {{PHONE}}<br>
    <hr style="border: 1px solid var(--border); margin: 10px 0;">
    <small style="color: var(--text-muted);">Digital Signature</small>
</div>
</body>
</html>';

// Template directory (created on demand)
$templates_dir = TEMPLATES_DIR;
if (!is_dir($templates_dir)) {
    mkdir($templates_dir, 0755, true);
}

// ---------------------------------------------------------------------
// 2. Logic: Determine which file to load (Default vs. Edit vs. Post)
// ---------------------------------------------------------------------
$system_default_file = getDefaultTemplateName();
$current_file = is_file($templates_dir . '/' . $system_default_file) ? $system_default_file : '';

// ---------------------------------------------------------------------
// 3. Handle POST Request (Save / Create)
// ---------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    requireCsrf();

    $template_name = cleanText($_POST['template_name'] ?? '', 80);
    $template_content = is_string($_POST['template_content'] ?? null) ? $_POST['template_content'] : '';
    $action = $_POST['action'] ?? '';

    // Keep the entered data in the form when validation fails.
    $current_name = $template_name;
    $current_content = $template_content;

    if ($template_name === '') {
        $error = t('Template name is required!');
    } elseif (trim($template_content) === '') {
        $error = t('Template content is required!');
    } elseif (strlen($template_content) > EDITOR_MAX_BYTES) {
        $error = t('Template is too large (max 512 KB).');
    } elseif (strpos($template_content, '<?') !== false) {
        $error = t('PHP / XML processing instructions are not allowed in templates.');
    } else {
        // Active content (scripts, event handlers, javascript: URLs) is removed on save.
        $template_content = sanitizeTemplateHtml($template_content);

        if ($action === 'save_new') {
            $clean_name = substr(preg_replace('/[^a-z0-9_]/i', '_', $template_name), 0, 70);
            $filename = 'signature_' . strtolower($clean_name) . '.html';
            $filepath = $templates_dir . '/' . $filename;

            if (!isValidTemplateName($filename)) {
                $error = t('Invalid template name.');
            } elseif (file_exists($filepath)) {
                $error = t('Template with this name already exists!');
            } elseif (file_put_contents($filepath, $template_content, LOCK_EX) !== false) {
                logSecurityEventToDB($db, 'TEMPLATE_CREATED', (int)$_SESSION['user_id'], $filename);
                $message = t('Template created: {name}', ['name' => $filename]);
                $current_file = $filename;
                $current_content = $template_content;
            } else {
                $error = t('Could not write file. Check permissions.');
            }
        } elseif ($action === 'save_existing') {
            $safe_filename = basename((string)($_POST['existing_file'] ?? ''));
            $filepath = $templates_dir . '/' . $safe_filename;

            if ($safe_filename === '') {
                $error = t('No template selected for update!');
            } elseif (!isEditableTemplateName($safe_filename) || !is_file($filepath) || !isPathInside($filepath, $templates_dir)) {
                $error = t('Security Error: Invalid file path.');
            } elseif (file_put_contents($filepath, $template_content, LOCK_EX) !== false) {
                logSecurityEventToDB($db, 'TEMPLATE_UPDATED', (int)$_SESSION['user_id'], $safe_filename);
                $message = t('Template updated: {name}', ['name' => $safe_filename]);
                $current_file = $safe_filename;
                $current_content = $template_content;
            } else {
                $error = t('Could not write file. Check permissions.');
            }
        }
    }
}

// ---------------------------------------------------------------------
// 4. Handle GET Request (Edit Mode or Default Load)
// ---------------------------------------------------------------------

// Check if user specifically requested a file via URL (?edit=...)
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['edit'])) {
    $requested_file = basename($_GET['edit']);
    $target_path = $templates_dir . '/' . $requested_file;

    // SECURITY: Validate file existence and naming convention
    if (isEditableTemplateName($requested_file) && is_file($target_path)) {
        $current_file = $requested_file;
    } else {
        $error = t('Template not found or invalid filename.');
        // Reset to empty if invalid
        $current_file = ''; 
    }
}

// ---------------------------------------------------------------------
// 5. Final Content Loading
// ---------------------------------------------------------------------
// Load content based on $current_file (which is now either Default, Edited, or Saved)
if (!empty($current_file) && !($_SERVER['REQUEST_METHOD'] === 'POST' && $error !== '')) {
    $load_path = $templates_dir . '/' . $current_file;
    if (is_file($load_path)) {
        $current_content = file_get_contents($load_path);
        
        // Generate a "pretty name" for the input field
        $pretty_name = str_replace(['signature_', '.html'], '', $current_file);
        $pretty_name = str_replace('_', ' ', $pretty_name);
        $current_name = ucwords($pretty_name);
    }
}

// ---------------------------------------------------------------------
// 6. Load Existing Templates List (for Dropdown)
// ---------------------------------------------------------------------
$templates = [];
foreach (array_merge(listSignatureTemplates(), is_file($templates_dir . '/email_notification.html') ? ['email_notification.html'] : []) as $file) {
    $templates[$file] = true; // only the names are needed in the dropdown
}
?>
<!DOCTYPE html>
<html lang="<?= e(currentLang()) ?>" dir="<?= e(langDir()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= et('Template Editor') ?> - SubSignature</title>
    
    <?= i18nHead() ?>
    
    <script src="<?= assetUrl('js/theme.js') ?>"></script>
    <link rel="stylesheet" href="<?= assetUrl('css/theme.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/style.css') ?>">
    <link rel="stylesheet" href="<?= assetUrl('css/all.min.css') ?>">    
    
    <link rel="stylesheet" href="<?= assetUrl('js/jodit/jodit.min.css') ?>">
    <script src="<?= assetUrl('js/jodit/jodit.min.js') ?>"></script>
    <script src="<?= assetUrl('js/ace/ace.js') ?>"></script>
    <script src="<?= assetUrl('js/safe-html.js') ?>"></script>
    
    <style>
        .jodit-container { border-radius: 8px !important; border: 1px solid var(--border) !important; }
        .jodit-toolbar { background: var(--bg-subtle) !important; border-bottom: 1px solid var(--border) !important; position: sticky; top: 0; z-index: 10; }
        .jodit-status-bar { border-top: 1px solid var(--border) !important; background: var(--bg-subtle) !important; }
        
        .placeholders { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.5rem; padding: 1rem; background: var(--bg-subtle); border-radius: 8px; border: 1px dashed var(--border); }
        .placeholder-btn { background: var(--bg-white); border: 1px solid var(--border); border-radius: 6px; padding: 0.3rem 0.6rem; font-size: 0.85rem; font-family: monospace; color: var(--primary); cursor: pointer; transition: all 0.2s; }
        .placeholder-btn:hover { background: var(--primary); color: white; border-color: var(--primary); }
        
        .preview-wrapper { background: var(--bg-white); border: 1px solid var(--border); border-radius: 8px; padding: 2rem; margin-top: 1rem; box-shadow: inset 0 0 10px rgba(0,0,0,0.02); overflow-x: auto; }
        
        .alert { padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; display: flex; gap: 0.75rem; align-items: center; font-size: 0.95rem; }
        .alert-success { background: var(--success-bg); color: var(--success-text); border: 1px solid var(--success-border); }
        .alert-error { background: var(--danger-bg); color: var(--danger-text); border: 1px solid var(--danger-border); }

        /* COMPACT TOOLBAR GRID */
        .editor-toolbar-grid {
            display: grid;
            grid-template-columns: 1fr 1fr auto;
            gap: 1rem;
            align-items: end;
            background: var(--bg-subtle);
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
        <?= langSwitcher() ?>
            <div class="user-profile">
                <div class="avatar">
                    <?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?>
                </div>
                <div class="user-info">
                    <div><?php echo e($_SESSION['username']); ?></div>
                    <span><?= et('Administrator') ?></span>
                </div>
            </div>
            <a href="logout.php" class="btn-logout">
                <i class="fas fa-sign-out-alt"></i> <span><?= et('Sign Out') ?></span>
            </a>
        </div>
    </aside>

    <main class="main-content">
        <header class="page-header">
            <h2><?= et('Template Editor') ?></h2>
            <p><?= et('Design and manage HTML email signature templates.') ?></p>
        </header>

        <?php if ($message): ?>
            <div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo e($message); ?></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="alert alert-error"><i class="fas fa-exclamation-circle"></i> <?php echo e($error); ?></div>
        <?php endif; ?>

        <div class="form-grid" style="grid-template-columns: 2fr 1fr; align-items: start;">
            <div style="grid-column: span 2;"> 
                
                <section class="card">
                    <form method="POST" id="editorForm">
                        <?php echo csrfField(); ?>

                        <div class="editor-toolbar-grid">
                            
                            <div class="form-group" style="margin-bottom: 0;">
                                <label for="template_selector" style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">
                                    <i class="fas fa-folder-open"></i> <?= et('Load Existing') ?>
                                </label>
                                <select id="template_selector" onchange="loadTemplate(this.value)" style="width: 100%; padding: 0.6rem; border: 1px solid var(--border-strong); border-radius: 6px;">
                                    <option value=""><?= et('-- Create New Template --') ?></option>
                                    <?php foreach ($templates as $filename => $content): ?>
                                        <?php  
                                        $display_name = $filename === 'email_notification.html' ? t('Notification mail wrapper') : templateDisplayName($filename);
                                        // Mark as selected if it matches current file (default or edited)
                                        $selected = ($filename === $current_file) ? 'selected' : '';
                                        ?>
                                        <option value="<?php echo e($filename); ?>" <?php echo $selected; ?>>
                                            <?php echo e($display_name); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <div class="form-group" style="margin-bottom: 0;">
                                <label for="template_name" style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">
                                    <i class="fas fa-tag"></i> <?= et('Template Name') ?>
                                </label>
                                <input type="text" id="template_name" name="template_name"  
                                      value="<?php echo e($current_name); ?>"
                                      placeholder="<?= et('e.g. Modern Blue') ?>" required 
                                      style="width: 100%; padding: 0.6rem; font-weight: 600; border: 1px solid var(--border-strong); border-radius: 6px;">
                            </div>

                            <div style="display: flex; gap: 0.5rem;">
                                <button type="submit" name="action" value="save_new" class="btn btn-primary" title="<?= et('Create as new file') ?>"><i class="fas fa-plus"></i> <?= et('Create') ?></button>
                                <button type="submit" name="action" value="save_existing" class="btn btn-success" id="saveExistingBtn" <?php echo empty($current_file) ? 'disabled' : ''; ?> title="<?= et('Overwrite existing file') ?>"><i class="fas fa-save"></i> <?= et('Save') ?></button>
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <label style="font-size: 0.85rem; font-weight: 600; color: var(--text-muted);"><i class="fas fa-magic"></i> <?= et('Insert Dynamic Variable:') ?></label>
                            <div class="placeholders">
                                <button type="button" onclick="insertPlaceholder('{{NAME}}')" class="placeholder-btn">{{NAME}}</button>
                                <button type="button" onclick="insertPlaceholder('{{ROLE}}')" class="placeholder-btn">{{ROLE}}</button>
                                <button type="button" onclick="insertPlaceholder('{{EMAIL}}')" class="placeholder-btn">{{EMAIL}}</button>
                                <button type="button" onclick="insertPlaceholder('{{PHONE}}')" class="placeholder-btn">{{PHONE}}</button>
                                <button type="button" onclick="insertPlaceholder('{{PHONE_CLEAN}}')" class="placeholder-btn" title="<?= et('Digits only, for tel: links') ?>">{{PHONE_CLEAN}}</button>
                                <button type="button" onclick="insertPlaceholder('{{COMPANY}}')" class="placeholder-btn" title="<?= et('Company-wide value (System Configuration)') ?>">{{COMPANY}}</button>
                                <button type="button" onclick="insertPlaceholder('{{WEBSITE}}')" class="placeholder-btn" title="<?= et('Company-wide value (System Configuration)') ?>">{{WEBSITE}}</button>
                                <button type="button" onclick="insertPlaceholder('{{ADDRESS}}')" class="placeholder-btn" title="<?= et('Company-wide value (System Configuration)') ?>">{{ADDRESS}}</button>
                                <button type="button" onclick="insertPlaceholder('{{DISCLAIMER}}')" class="placeholder-btn" title="<?= et('Company-wide value (System Configuration)') ?>">{{DISCLAIMER}}</button>
                                <div style="width: 1px; background: var(--border); margin: 0 5px;"></div>
                                <button type="button" onclick="insertPlaceholder('<br>')" class="placeholder-btn">&lt;br&gt;</button>
                                <button type="button" onclick="insertPlaceholder('<hr>')" class="placeholder-btn">&lt;hr&gt;</button>
                            </div>
                        </div>

                        <div class="form-group">
                            <textarea id="template_content" name="template_content" class="fallback-editor"><?php echo e($current_content); ?></textarea>
                            <div id="editor_warning" style="display:none; color:red; margin-top:0.5rem;"><?= et('Jodit Editor could not load.') ?></div>
                        </div>

                        <div class="form-actions" style="justify-content: space-between; margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--border);">
                            <div>
                                <button type="button" onclick="clearEditor()" class="btn btn-sm btn-danger" style="background:transparent; color:var(--danger); border:1px solid var(--border);"><i class="fas fa-trash-alt"></i> <?= et('Clear All') ?></button>
                                <button type="button" onclick="loadDefaultTemplate()" class="btn btn-sm btn-secondary" style="background:transparent; color:var(--text-muted); border:1px solid var(--border);"><i class="fas fa-undo"></i> <?= et('Reset Default') ?></button>
                            </div>
                            <input type="hidden" id="existing_file" name="existing_file" value="<?php echo e($current_file); ?>">
                        </div>
                    </form>
                </section>
                
                <section class="card">
                    <div class="card-header">
                        <h3><i class="fas fa-eye"></i> <?= et('Live Preview') ?></h3>
                        <button onclick="updatePreview()" class="btn btn-sm btn-secondary"><i class="fas fa-sync-alt"></i> <?= et('Refresh') ?></button>
                    </div>
                    <div class="preview-wrapper"><div id="live_preview"></div></div>
                </section>

            </div>
        </div>
    </main>

    <script>
    // Company-wide placeholder values ({{COMPANY}} etc., Admin -> System Configuration)
    var COMPANY_VALUES = <?= json_encode(companyFields(), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var editorInstance = null;
    
    function isDarkTheme() {
        return window.SubSigTheme && window.SubSigTheme.get() === 'dark';
    }

    function createEditor() {
        if (typeof Jodit === 'undefined') {
            document.getElementById('editor_warning').style.display = 'block';
            return;
        }
        
        var textarea = document.getElementById('template_content');
        if (!textarea) return;
        lastEditorDark = isDarkTheme();
        
        try {
            editorInstance = Jodit.make(textarea, {
                height: 450,
                width: '100%',
                theme: isDarkTheme() ? 'dark' : 'default',
                // Editor UI language (Jodit falls back to English if it has no pack).
                language: <?= tj(['zh' => 'zh_cn', 'pt' => 'pt_br'][currentLang()] ?? currentLang()) ?>,
                
                // --- CONFIG FOR LOCAL ACE EDITOR ---
                useAceEditor: true,
                sourceEditor: 'ace',
                // Point to local Ace file
                sourceEditorCDNUrlsJS: ['js/ace/ace.js'], 
                // -----------------------------------

                sourceEditorNativeOptions: {
                    theme: isDarkTheme() ? 'ace/theme/tomorrow_night' : 'ace/theme/chrome',
                    mode: 'ace/mode/html',
                    showGutter: true,
                    wrap: true
                },

                beautifyHTML: false,
                source: false,
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
    }

    document.addEventListener('DOMContentLoaded', createEditor);

    // The WYSIWYG and code editor themes are fixed at creation time:
    // rebuild the editor (keeping its content) when the colour theme changes.
    var lastEditorDark = null;
    document.addEventListener('subsig-theme-change', function () {
        var dark = isDarkTheme();
        if (dark === lastEditorDark || !editorInstance) { return; }
        lastEditorDark = dark;
        var content = editorInstance.value;
        editorInstance.destruct();
        editorInstance = null;
        document.getElementById('template_content').value = content;
        createEditor();
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
    
    // JS Load Function (for Dropdown)
    function loadTemplate(filename) {
        // If user selects "Create New", clear everything and load fallback default
        if (!filename) {
            document.getElementById('template_name').value = '';
            document.getElementById('existing_file').value = '';
            document.getElementById('saveExistingBtn').disabled = true;
            loadDefaultTemplate();
            return;
        }
        
        fetch('load_template.php?file=' + encodeURIComponent(filename))
            .then(response => {
                if(!response.ok) throw new Error(<?= tj('Failed to load') ?>);
                return response.text();
            })
            .then(content => {
                if (editorInstance) editorInstance.value = content;
                else document.getElementById('template_content').value = content;
                
                // Pretty name generation
                var displayName = filename.replace('signature_', '').replace('.html', '');
                displayName = displayName.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
                
                document.getElementById('template_name').value = displayName;
                document.getElementById('existing_file').value = filename;
                document.getElementById('saveExistingBtn').disabled = false;
                
                updatePreview();
            })
            .catch(err => alert(<?= tj('Error loading template: {error}') ?>.replace('{error}', err)));
    }
    
    // Resets content to a hardcoded simple fallback
    function loadDefaultTemplate() {
        var defaultTpl = '<!DOCTYPE html>\n<html>\n<head><meta charset="UTF-8"></head>\n<body>\n<div style="font-family: Arial;">\n{{NAME}} | {{ROLE}}\n</div>\n</body>\n</html>';
        if (editorInstance) editorInstance.value = defaultTpl;
        else document.getElementById('template_content').value = defaultTpl;
        updatePreview();
    }
    
    function updatePreview() {
        var content = editorInstance ? editorInstance.value : document.getElementById('template_content').value;
        // Sample data is escaped; the resulting HTML is sanitised before it is inserted.
        var preview = SafeHtml.fill(content, {
            NAME: 'John Doe',
            ROLE: 'Senior Developer',
            EMAIL: 'john.doe@company.com',
            PHONE: '+49 89 12345678',
            PHONE_CLEAN: '+498912345678',
            // Company values as configured; sample text while still empty
            COMPANY: COMPANY_VALUES.company || 'Example Company Ltd.',
            WEBSITE: COMPANY_VALUES.website || 'https://example.com',
            ADDRESS: COMPANY_VALUES.address || 'Example Street 1\n12345 Example City',
            DISCLAIMER: COMPANY_VALUES.disclaimer || 'This email may contain confidential information.'
        });

        document.getElementById('live_preview').innerHTML = SafeHtml.sanitize(preview);
    }
    
    function clearEditor() {
        if(confirm(<?= tj('Clear all content?') ?>)) {
            if(editorInstance) editorInstance.value = '';
            else document.getElementById('template_content').value = '';
        }
    }

    document.getElementById('editorForm').addEventListener('submit', function(e) {
        if(!document.getElementById('template_name').value.trim()) {
            e.preventDefault();
            alert(<?= tj('Template Name is required') ?>);
        }
    });
    </script>
</body>
</html>
