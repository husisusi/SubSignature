<?php
// Template löschen, umbenennen, duplizieren
if (isset($_GET['delete'])) {
    $file = 'templates/' . basename($_GET['delete']);
    if (file_exists($file)) {
        unlink($file);
        echo json_encode(['success' => true]);
    }
}
?>
