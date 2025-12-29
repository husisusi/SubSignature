<?php
// logout.php

// 1. Load Configuration
// We include config to ensure the session is started with the exact same settings 
// (cookie name, secure flags, etc.) as the rest of the application.
require_once 'includes/config.php';

// 2. Unset all session variables
// This clears the $_SESSION array immediately.
$_SESSION = array();

// 3. Delete the Session Cookie
// This is the most important part often missing in simple scripts.
// We must delete the cookie from the user's browser to fully invalidate the session.
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// 4. Destroy the session storage on the server
session_destroy();

// 5. Redirect to homepage or login
header('Location: index.php');
exit;
?>
