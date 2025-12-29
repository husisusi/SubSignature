<?php
// clear_preview.php

// 1. Load Configuration & Security Context
// Initializes the session securely and provides auth functions.
require_once 'includes/config.php';

// 2. Authentication Check
// Only logged-in admins should be able to modify session state.
requireAdmin();

// 3. Set JSON Headers
// Since this script returns JSON, we must declare the correct content type.
// This also helps prevent browsers from interpreting the response as HTML.
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

// 4. Enforce HTTP POST Method (CSRF Protection)
// State-changing actions should only be allowed via POST requests.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    // Send 405 Method Not Allowed status
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Invalid request method. POST required.']);
    exit;
}

// 5. Perform the action
// Check if the specific session key exists before unsetting.
if (isset($_SESSION['preview'])) {
    unset($_SESSION['preview']);
    
    // Also clear related form data if it exists
    if (isset($_SESSION['form_data'])) {
        unset($_SESSION['form_data']);
    }
    
    echo json_encode(['success' => true]);
} else {
    // Return success: false if there was nothing to clear (idempotency)
    echo json_encode(['success' => false, 'message' => 'No preview data found to clear.']);
}
?>
