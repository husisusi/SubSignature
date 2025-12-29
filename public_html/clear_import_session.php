<?php
// clear_import_session.php

// 1. Include Configuration & Security Context
// We need to load the main configuration to access session settings and auth functions.
require_once 'includes/config.php';

// 2. Authentication Check
// CRITICAL: Ensure only authorized admins can clear session data.
// Without this, anyone opening this URL could wipe the import buffer.
requireAdmin();

// 3. Enforce HTTP Method (CSRF Protection)
// State-changing actions (like deleting data) should NEVER be done via GET requests.
// Using POST prevents simple attacks where an image tag (<img src="clear...">) 
// on a malicious site triggers this action.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    // Return a 405 error if someone tries to access this via browser URL bar (GET)
    header('HTTP/1.1 405 Method Not Allowed');
    exit('Error: Request method must be POST.');
}

// 4. Clear Session Data safely
// We check if keys exist before unsetting, though unset() handles non-existent keys gracefully.
if (isset($_SESSION['preview_data'])) {
    unset($_SESSION['preview_data']);
}

if (isset($_SESSION['import_params'])) {
    unset($_SESSION['import_params']);
}

// 5. Secure Response Headers
// Prevent content sniffing and ensure correct encoding.
header('Content-Type: text/plain; charset=utf-8');
header('X-Content-Type-Options: nosniff');

echo 'OK';
?>
