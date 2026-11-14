<?php
// auth.php - session helpers shared by protected pages
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// CSRF token for state-changing API calls
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

function require_login() {
    if (empty($_SESSION['user_id'])) {
        header("Location: login.php");
        exit();
    }
}
?>