<?php
// db.php - MySQL Connector for ProcureGuard Frontend (XAMPP)
$db_host = 'localhost';
$db_name = 'procureguard';
$db_user = 'root';
$db_pass = '';   // XAMPP default is an empty password

try {
    $pdo = new PDO(
        "mysql:host=$db_host;dbname=$db_name;charset=utf8mb4",
        $db_user,
        $db_pass,
        [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]
    );
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

// Fetch helper functions for frontend views
function get_envelopes($pdo) {
    try {
        $stmt = $pdo->query("SELECT * FROM bid_envelopes");
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        return []; // Returns empty array if tables aren't built yet instead of crashing
    }
}

function get_drifts($pdo) {
    try {
        $stmt = $pdo->query("SELECT * FROM forensic_drifts");
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        return [];
    }
}

function get_baselines($pdo) {
    try {
        $stmt = $pdo->query("SELECT * FROM market_baselines");
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        return [];
    }
}

function get_registry($pdo) {
    try {
        $stmt = $pdo->query("SELECT * FROM corporate_registry");
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        return [];
    }
}
?>