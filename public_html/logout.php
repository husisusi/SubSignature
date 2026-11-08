<?php
// logout.php - ends the session completely (data, server file, cookie).
require_once 'includes/config.php';

// Logging out is a state change: accept it via GET only for the navbar link
// (low impact: worst case an attacker logs the user out), but record it.
if (isLoggedIn()) {
    logSecurityEventToDB($db, 'LOGOUT', (int)($_SESSION['user_id'] ?? 0), 'User: ' . ($_SESSION['username'] ?? ''));
}
destroySession();
header('Location: index.php?msg=loggedout');
exit;
