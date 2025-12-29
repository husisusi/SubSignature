<?php
// get_signature_count.php

// 1. Load Configuration & Security Context
require_once 'includes/config.php';
requireLogin();

// 2. Set Secure JSON Headers
// Ensure the browser knows this is JSON and prevent content sniffing.
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

// 3. Enforce HTTP Method
// Fetching data should typically be a GET request.
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405); // Method Not Allowed
    echo json_encode(['error' => 'Method Not Allowed. Use GET.']);
    exit;
}

// 4. Validate Input
if (!isset($_GET['user_id'])) {
    http_response_code(400); // Bad Request
    echo json_encode(['error' => 'No user ID provided']);
    exit;
}

// Cast to integer immediately to sanitize input
$target_user_id = (int)$_GET['user_id'];
$current_user_id = $_SESSION['user_id'];
$is_admin = isAdmin();

// 5. Authorization Check (IDOR Protection)
// Users can only see their own count, Admins can see everyone's.
// We use strict comparison (!==) for security.
if (!$is_admin && $target_user_id !== $current_user_id) {
    http_response_code(403); // Forbidden
    echo json_encode(['error' => 'Access denied']);
    exit;
}

// 6. Database Query
try {
    $stmt = $db->prepare("SELECT COUNT(*) as count FROM user_signatures WHERE user_id = ?");
    $stmt->bindValue(1, $target_user_id, SQLITE3_INTEGER);
    $result = $stmt->execute();
    
    // Fetch result safely
    if ($result) {
        $data = $result->fetchArray(SQLITE3_ASSOC);
        $count = $data['count'] ?? 0;
    } else {
        $count = 0;
    }

    echo json_encode([
        'count' => $count,
        'user_id' => $target_user_id
    ]);

} catch (Exception $e) {
    // Handle database errors gracefully without leaking system details
    http_response_code(500); // Internal Server Error
    echo json_encode(['error' => 'Database error occurred.']);
}

exit;
?>
