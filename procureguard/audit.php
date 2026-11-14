<?php
// audit.php - hash-chained, append-only audit ledger
// Every entry stores the SHA-256 hash of the previous entry, so editing or removing
// any past entry breaks the chain and is detected by audit_verify().
require_once 'db.php';
date_default_timezone_set('Africa/Nairobi');

const AUDIT_GENESIS = '0000000000000000000000000000000000000000000000000000000000000000';

function audit_hash($prev, $created_at, $user_id, $officer, $action, $status, $details) {
    return hash('sha256', json_encode([
        (string)$prev,
        (string)$created_at,
        $user_id === null ? null : (int)$user_id,
        (string)$officer,
        (string)$action,
        (string)$status,
        (string)$details,
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
}

// Appends one entry. Returns the new entry id, or false if logging failed.
function log_event($pdo, $action, $status = 'SUCCESS', $details = null, $user_id = null, $officer = null) {
    $user_id = $user_id ?? ($_SESSION['user_id'] ?? null);
    $officer = $officer ?? ($_SESSION['username'] ?? 'SYSTEM');
    $officer = substr((string)$officer, 0, 100);
    $action  = substr((string)$action, 0, 255);
    $status  = substr((string)$status, 0, 30);
    $details = (string)$details;

    try {
        $pdo->beginTransaction();
        $prev = $pdo->query("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1 FOR UPDATE")->fetchColumn();
        if (!$prev) {
            $prev = AUDIT_GENESIS;
        }
        $ts   = date('Y-m-d H:i:s');
        $hash = audit_hash($prev, $ts, $user_id, $officer, $action, $status, $details);

        $ins = $pdo->prepare("INSERT INTO audit_log (created_at, user_id, officer, action, status, details, prev_hash, entry_hash)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
        $ins->execute([$ts, $user_id, $officer, $action, $status, $details, $prev, $hash]);
        $id = (int)$pdo->lastInsertId();
        $pdo->commit();
        return $id;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        return false;
    }
}

// Re-computes the whole chain. valid=false means an entry was altered or removed.
function audit_verify($pdo) {
    try {
        $stmt = $pdo->query("SELECT * FROM audit_log ORDER BY id ASC");
        $prev = AUDIT_GENESIS;
        $n = 0;
        while ($r = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $n++;
            $expected = audit_hash($r['prev_hash'], $r['created_at'], $r['user_id'], $r['officer'], $r['action'], $r['status'], $r['details']);
            if ($r['prev_hash'] !== $prev || !hash_equals($expected, $r['entry_hash'])) {
                return ['valid' => false, 'entries' => $n, 'broken_at' => (int)$r['id'], 'head' => null];
            }
            $prev = $r['entry_hash'];
        }
        return ['valid' => true, 'entries' => $n, 'broken_at' => null, 'head' => $n ? $prev : null];
    } catch (Throwable $e) {
        return ['valid' => null, 'entries' => 0, 'broken_at' => null, 'head' => null];
    }
}

function audit_recent($pdo, $limit = 50) {
    try {
        $limit = max(1, (int)$limit);
        $stmt = $pdo->query("SELECT id, created_at AS `timestamp`, officer, action, status, entry_hash
                             FROM audit_log ORDER BY id DESC LIMIT $limit");
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (Throwable $e) {
        return [];
    }
}
?>