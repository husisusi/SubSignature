<?php
/**
 * tag_picker.php - optional tag for imported signatures (CSV and LDAP import).
 *
 * The picker offers "no tag", an existing tag, or a new tag (name + colour).
 * Tags are managed by administrators, so the picker is only shown to them and
 * the server ignores the fields for everybody else. A new tag is only created
 * when the import itself runs, never while previewing.
 */

/** Tags for the picker: [[id, name, color], ...] */
function importTagList(SQLite3 $db): array
{
    $tags = [];
    $res = $db->query('SELECT id, name, color FROM signature_tags ORDER BY name COLLATE NOCASE');
    while ($r = $res->fetchArray(SQLITE3_ASSOC)) {
        $tags[] = $r;
    }
    return $tags;
}

/**
 * Reads and validates the picker fields of a request.
 * Returns ['id' => int, 'new' => string, 'color' => string, 'error' => string];
 * id 0 and new '' mean "no tag". Non-admins always get "no tag".
 */
function resolveImportTagChoice(SQLite3 $db, array $post): array
{
    $none = ['id' => 0, 'new' => '', 'color' => 'blue', 'error' => ''];
    if (!isAdmin()) {
        return $none;
    }
    $raw = (string)($post['tag'] ?? '');
    if ($raw === '') {
        return $none;
    }
    if ($raw === '__new__') {
        $name = normalizeTagName($post['tag_new'] ?? '');
        if ($name === '') {
            return ['id' => 0, 'new' => '', 'color' => 'blue', 'error' => t('Invalid tag name. Use 1-32 letters, numbers, spaces or . _ - / &')];
        }
        return ['id' => 0, 'new' => $name, 'color' => normalizeTagColor($post['tag_color'] ?? ''), 'error' => ''];
    }
    if (!preg_match('/^[1-9]\d{0,9}$/', $raw)) {
        return $none;
    }
    $st = $db->prepare('SELECT COUNT(*) FROM signature_tags WHERE id = ?');
    $st->bindValue(1, (int)$raw, SQLITE3_INTEGER);
    if ((int)$st->execute()->fetchArray(SQLITE3_NUM)[0] === 0) {
        return ['id' => 0, 'new' => '', 'color' => 'blue', 'error' => t('Please choose a tag.')];
    }
    return ['id' => (int)$raw, 'new' => '', 'color' => 'blue', 'error' => ''];
}

/**
 * Turns a validated choice into a tag id (creating a new tag if needed).
 * Returns 0 for "no tag" or when the tag limit is reached.
 */
function applyImportTagChoice(SQLite3 $db, array $choice): int
{
    if (!isAdmin()) {
        return 0;
    }
    if ((int)$choice['id'] > 0) {
        return (int)$choice['id'];
    }
    if ($choice['new'] === '') {
        return 0;
    }
    $st = $db->prepare('SELECT id FROM signature_tags WHERE name = ?');
    $st->bindValue(1, $choice['new'], SQLITE3_TEXT);
    $found = $st->execute()->fetchArray(SQLITE3_NUM);
    if ($found) {
        return (int)$found[0]; // same name (case-insensitive): reuse it
    }
    if ((int)$db->querySingle('SELECT COUNT(*) FROM signature_tags') >= MAX_SIGNATURE_TAGS) {
        return 0;
    }
    $ins = $db->prepare('INSERT INTO signature_tags (name, color) VALUES (?, ?)');
    $ins->bindValue(1, $choice['new'], SQLITE3_TEXT);
    $ins->bindValue(2, normalizeTagColor($choice['color']), SQLITE3_TEXT);
    $ins->execute();
    $id = (int)$db->lastInsertRowID();
    logSecurityEventToDB($db, 'SIGNATURE_TAG_CREATED', (int)($_SESSION['user_id'] ?? 0), $choice['new'] . ' (import)');
    return $id;
}

/** Display name of the chosen tag (for result pages); '' for none. */
function importTagName(SQLite3 $db, int $tagId): string
{
    if ($tagId <= 0) {
        return '';
    }
    $st = $db->prepare('SELECT name FROM signature_tags WHERE id = ?');
    $st->bindValue(1, $tagId, SQLITE3_INTEGER);
    $row = $st->execute()->fetchArray(SQLITE3_NUM);
    return $row ? (string)$row[0] : '';
}

/**
 * HTML of the picker. $choice = values to preselect (as returned by
 * resolveImportTagChoice); $selectClass = CSS class of the page's selects.
 */
function renderTagPicker(SQLite3 $db, array $choice, string $selectClass = 'form-input'): string
{
    if (!isAdmin()) {
        return '';
    }
    $tags = importTagList($db);
    $sel = $choice['new'] !== '' ? '__new__' : ((int)$choice['id'] > 0 ? (string)(int)$choice['id'] : '');
    ob_start();
    ?>
    <div class="tag-picker" data-tag-picker>
        <select name="tag" class="<?php echo e($selectClass); ?>" data-tag-select>
            <option value=""><?= et('No tag') ?></option>
            <?php foreach ($tags as $tg): ?>
            <option value="<?php echo (int)$tg['id']; ?>" <?php echo $sel === (string)$tg['id'] ? 'selected' : ''; ?>><?php echo e($tg['name']); ?></option>
            <?php endforeach; ?>
            <option value="__new__" <?php echo $sel === '__new__' ? 'selected' : ''; ?>><?= et('New tag...') ?></option>
        </select>
        <span class="tag-picker-new" data-tag-new style="<?php echo $sel === '__new__' ? '' : 'display:none;'; ?>">
            <input type="text" name="tag_new" maxlength="32" class="<?php echo e($selectClass); ?>" placeholder="<?= et('New tag') ?>" value="<?php echo e($choice['new']); ?>" autocomplete="off">
            <select name="tag_color" class="<?php echo e($selectClass); ?>" aria-label="<?= et('Colour') ?>">
                <?php foreach (signatureTagColors() as $c): ?>
                <option value="<?php echo e($c); ?>" <?php echo $choice['color'] === $c ? 'selected' : ''; ?>><?php echo e(signatureTagColorLabel($c)); ?></option>
                <?php endforeach; ?>
            </select>
        </span>
    </div>
    <script>
    (function () {
        var box = document.currentScript.previousElementSibling;
        if (!box) return;
        var sel = box.querySelector('[data-tag-select]'), extra = box.querySelector('[data-tag-new]');
        function sync() { extra.style.display = sel.value === '__new__' ? '' : 'none'; }
        sel.addEventListener('change', sync); sync();
    })();
    </script>
    <?php
    return (string)ob_get_clean();
}

/** Adds one tag to one signature (idempotent). */
function tagSignature(SQLite3 $db, int $signatureId, int $tagId): void
{
    if ($signatureId <= 0 || $tagId <= 0) {
        return;
    }
    $st = $db->prepare('INSERT OR IGNORE INTO signature_tag_map (signature_id, tag_id) VALUES (?, ?)');
    $st->bindValue(1, $signatureId, SQLITE3_INTEGER);
    $st->bindValue(2, $tagId, SQLITE3_INTEGER);
    $st->execute();
}
