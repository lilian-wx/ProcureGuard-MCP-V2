<?php
// api.php - ProcureGuard JSON API Gateway (login required, risk score computed from data)
require_once 'auth.php';
require_once 'db.php';
require_once 'audit.php';

header('Content-Type: application/json');

if (empty($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(["status" => "UNAUTHORIZED", "error" => "Login required."]);
    exit();
}

const DRIFT_FLAG_PCT = 15.0;   // a line item above baseline by more than this is flagged
const ALLOWED_ROUTES = [       // must match the Action Route options in index.php
    'REJECT BIDDER B & ESCALATE TO EACC',
    'FLAG FOR INTERNAL REVIEW',
    'APPROVE WITH CONDITIONS',
];

$action = $_GET['action'] ?? 'get_data';

// ---------- helpers ----------

function require_post_with_csrf() {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(["status" => "ERROR", "error" => "POST required."]);
        exit();
    }
    $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', $token)) {
        http_response_code(403);
        echo json_encode(["status" => "ERROR", "error" => "Invalid security token. Reload the page."]);
        exit();
    }
}

function drift_value($d) {
    return floatval(str_replace(['%', '+'], '', $d['drift_pct'] ?? 0));
}

// Companies that share a KRA PIN or a director identifier.
function find_collusion($registry) {
    $pairs = [];
    $n = count($registry);
    for ($i = 0; $i < $n; $i++) {
        for ($j = $i + 1; $j < $n; $j++) {
            $shared = [];
            if ($registry[$i]['kra_pin'] === $registry[$j]['kra_pin']) {
                $shared[] = 'KRA_PIN';
            }
            if ($registry[$i]['director_identifier'] === $registry[$j]['director_identifier']) {
                $shared[] = 'DIRECTOR_ID';
            }
            if ($shared) {
                $pairs[] = [
                    'entity_a' => $registry[$i]['company_name'],
                    'entity_b' => $registry[$j]['company_name'],
                    'shared'   => $shared,
                ];
            }
        }
    }
    return $pairs;
}

// Transparent scoring (max 100):
//   price     0-50  scales with the worst overcharge (full marks at +200% or more)
//   breadth   0-20  share of line items above the flag threshold
//   collusion 0-30  any pair of bidders sharing a KRA PIN or director identifier
function compute_risk($drifts, $pairs) {
    $vals    = array_map('drift_value', $drifts);
    $max     = $vals ? max(0, max($vals)) : 0;
    $total   = count($vals);
    $flagged = count(array_filter($vals, fn($v) => $v > DRIFT_FLAG_PCT));

    $price     = (int)round(min(50, $max / 200 * 50));
    $breadth   = $total ? (int)round($flagged / $total * 20) : 0;
    $collusion = $pairs ? 30 : 0;
    $score     = min(100, $price + $breadth + $collusion);

    if ($score >= 75)      $level = 'CRITICAL';
    elseif ($score >= 50)  $level = 'HIGH';
    elseif ($score >= 25)  $level = 'MEDIUM';
    else                   $level = 'LOW';

    if ($max >= 100)               $drift_label = 'SEVERE OVERCHARGE';
    elseif ($max > DRIFT_FLAG_PCT) $drift_label = 'ABOVE THRESHOLD';
    else                           $drift_label = 'WITHIN TOLERANCE';

    return [
        'score' => $score, 'level' => $level, 'max_drift' => $max,
        'flagged_items' => $flagged, 'total_items' => $total,
        'drift_label' => $drift_label,
        'breakdown' => ['price' => $price, 'breadth' => $breadth, 'collusion' => $collusion],
    ];
}

function rule_brief($risk, $pairs) {
    $parts = [];
    if ($risk['max_drift'] > DRIFT_FLAG_PCT) {
        $parts[] = "unit rate inflation (+" . round($risk['max_drift']) . "%) across " . $risk['flagged_items'] . " of " . $risk['total_items'] . " line items";
    }
    if ($pairs) {
        $parts[] = "shared corporate identifiers between " . count($pairs) . " bidder pair(s)";
    }
    if (!$parts) {
        return "No price drift above " . DRIFT_FLAG_PCT . "% and no shared corporate identifiers detected. Officer review remains required under PPADA 2015 Section 114.";
    }
    return ucfirst(implode(" and ", $parts)) . " detected. Mandatory human sign-off required under PPADA 2015 Section 114.";
}

// Asks the local Ollama model for a brief. Returns null if Ollama is not running.
function ollama_brief($risk, $pairs) {
    $prompt = "You are an air-gapped public procurement compliance officer operating under Kenya's PPADA 2015 Section 114. "
        . "Write a 2-sentence executive statutory brief for the Procurement Officer from this telemetry. "
        . "Composite risk score: {$risk['score']}/100. Max price drift: " . round($risk['max_drift'], 1) . "%. "
        . "Collusion risk detected: " . ($pairs ? 'yes' : 'no') . ". "
        . "State that the human officer must make the final determination.";
    $ctx = stream_context_create(['http' => [
        'method'        => 'POST',
        'header'        => "Content-Type: application/json\r\n",
        'content'       => json_encode(['model' => 'qwen2.5-instruct:3b', 'prompt' => $prompt, 'stream' => false]),
        'timeout'       => 20,
        'ignore_errors' => true,
    ]]);
    $res = @file_get_contents('http://localhost:11434/api/generate', false, $ctx);
    if ($res === false) {
        return null;
    }
    $j = json_decode($res, true);
    $text = trim($j['response'] ?? '');
    return $text !== '' ? $text : null;
}

function build_payload($pdo, $brief = null, $engine = null) {
    $envelopes = get_envelopes($pdo);
    $drifts    = get_drifts($pdo);
    $registry  = get_registry($pdo);
    $pairs     = find_collusion($registry);
    $risk      = compute_risk($drifts, $pairs);

    return [
        "status" => "SUCCESS",
        "metrics" => [
            "risk_score"  => $risk['score'],
            "risk_level"  => $risk['level'],
            "risk_detail" => "Price {$risk['breakdown']['price']}/50 · Breadth {$risk['breakdown']['breadth']}/20 · Collusion {$risk['breakdown']['collusion']}/30",
            "max_drift"   => "+" . round($risk['max_drift']) . "%",
            "drift_label" => $risk['drift_label'],
            "specs_parsed" => count($drifts) . " items",
        ],
        "ai_statutory_brief" => $brief ?? rule_brief($risk, $pairs),
        "model_engine" => $engine ?? "Deterministic Rule Engine",
        "envelopes" => $envelopes,
        "drifts"    => $drifts,
        "registry"  => $registry,
        "collusion" => $pairs,
        "baselines" => get_baselines($pdo),
        "logs"      => audit_recent($pdo, 50),
        "chain"     => audit_verify($pdo),
    ];
}

function ollama_generate($prompt) {
    $ctx = stream_context_create(['http' => [
        'method' => 'POST', 'header' => "Content-Type: application/json\r\n",
        'content' => json_encode(['model' => 'qwen2.5-instruct:3b', 'prompt' => $prompt, 'stream' => false]),
        'timeout' => 20, 'ignore_errors' => true,
    ]]);
    $res = @file_get_contents('http://localhost:11434/api/generate', false, $ctx);
    if ($res === false) return null;
    $t = trim((json_decode($res, true)['response'] ?? ''));
    return $t !== '' ? $t : null;
}

// Compliance chat: local Ollama if running, otherwise rule-based answers from the same data.
function chat_answer($q, $risk, $pairs) {
    $b = $risk['breakdown'];
    $facts = "Risk score {$risk['score']}/100 ({$risk['level']}); price {$b['price']}/50, breadth {$b['breadth']}/20, collusion {$b['collusion']}/30. "
        . "Max price drift " . round($risk['max_drift'], 1) . "%; " . $risk['flagged_items'] . " of " . $risk['total_items'] . " line items above " . DRIFT_FLAG_PCT . "%. "
        . count($pairs) . " linked bidder pair(s).";
    $ai = ollama_generate("You are an air-gapped audit compliance assistant for Kenya's PPADA 2015. Answer in at most 3 sentences using only these facts. Facts: $facts Officer question: $q");
    if ($ai !== null) return $ai;

    if (preg_match('/collu|link|director|pin|shell/i', $q)) {
        if (!$pairs) return "No bidders share a KRA PIN or director identifier in the registry.";
        $s = array_map(fn($p) => $p['entity_a'] . ' & ' . $p['entity_b'] . ' (' . implode(' + ', $p['shared']) . ')', array_slice($pairs, 0, 3));
        return count($pairs) . " linked bidder pair(s). Examples: " . implode('; ', $s) . ". Refer these to the officer for review.";
    }
    if (preg_match('/drift|price|overcharge|baseline/i', $q)) {
        return "Max drift is +" . round($risk['max_drift']) . "%, with " . $risk['flagged_items'] . " of " . $risk['total_items'] . " line items above the " . DRIFT_FLAG_PCT . "% threshold.";
    }
    if (preg_match('/risk|score/i', $q)) {
        return "Risk score is {$risk['score']}/100 ({$risk['level']}): price {$b['price']}/50, breadth {$b['breadth']}/20, collusion {$b['collusion']}/30.";
    }
    if (preg_match('/ppada|114|statut|law|sign/i', $q)) {
        return "Under PPADA 2015 Section 114 a human officer must make and sign the final determination. ProcureGuard only flags risk.";
    }
    return "I can answer about the risk score, price drift, linked bidders or PPADA Section 114. Right now the score is {$risk['score']}/100 ({$risk['level']}).";
}

// ---------- routes ----------

switch ($action) {
    case 'get_data':
        echo json_encode(build_payload($pdo));
        break;

    case 'run_audit':
        require_post_with_csrf();
        $registry = get_registry($pdo);
        $pairs    = find_collusion($registry);
        $risk     = compute_risk(get_drifts($pdo), $pairs);

        $ai = ollama_brief($risk, $pairs);
        $engine = $ai !== null ? "Local Ollama (Qwen 2.5 - Air-Gapped)" : "Deterministic Rule Engine (Ollama offline)";

        log_event($pdo, 'Forensic audit executed', $risk['score'] >= 50 ? 'FLAGGED' : 'CLEAR',
            json_encode(['risk_score' => $risk['score'], 'level' => $risk['level'], 'engine' => $engine, 'breakdown' => $risk['breakdown']]));

        echo json_encode(build_payload($pdo, $ai, $engine));
        break;

    case 'commit_decision':
        require_post_with_csrf();
        $in    = json_decode(file_get_contents('php://input'), true) ?: [];
        $badge = trim($in['badgeId'] ?? '');
        $route = trim($in['actionRoute'] ?? '');
        $notes = trim($in['notes'] ?? '');

        if (!preg_match('/^[A-Za-z0-9_-]{3,50}$/', $badge)) {
            echo json_encode(["status" => "ERROR", "error" => "Enter a valid Officer Badge ID (letters, numbers, dash)."]);
            break;
        }
        if (!in_array($route, ALLOWED_ROUTES, true)) {
            echo json_encode(["status" => "ERROR", "error" => "Invalid action route."]);
            break;
        }
        if ($notes === '') {
            echo json_encode(["status" => "ERROR", "error" => "Officer notes are required for the statutory record."]);
            break;
        }

        $id = log_event($pdo, 'Officer decision: ' . $route, 'RECORDED',
            json_encode(['badge_id' => $badge, 'route' => $route, 'notes' => substr($notes, 0, 2000)], JSON_UNESCAPED_UNICODE));

        if ($id === false) {
            echo json_encode(["status" => "ERROR", "error" => "Could not write to the audit ledger. Is the audit_log table created?"]);
        } else {
            echo json_encode(["status" => "SUCCESS", "entry_id" => $id, "message" => "Decision recorded in the audit ledger."]);
        }
        break;

    case 'chat':
        require_post_with_csrf();
        $in = json_decode(file_get_contents('php://input'), true) ?: [];
        $q  = trim(substr($in['message'] ?? '', 0, 500));
        if ($q === '') {
            echo json_encode(["status" => "ERROR", "error" => "Type a question first."]);
            break;
        }
        $pairs = find_collusion(get_registry($pdo));
        $risk  = compute_risk(get_drifts($pdo), $pairs);
        $answer = chat_answer($q, $risk, $pairs);
        log_event($pdo, 'Compliance chat query', 'SUCCESS', json_encode(['question' => $q], JSON_UNESCAPED_UNICODE));
        echo json_encode(["status" => "SUCCESS", "answer" => $answer]);
        break;

    case 'sync_records':
        require_post_with_csrf();
        // Runs the ingestion script (still writes to the old SQLite file until it is converted to MySQL)
        $output = [];
        $return_var = 0;
        @exec("python scripts/sync_tenders.py 2>&1", $output, $return_var);
        log_event($pdo, 'Public records sync requested', $return_var === 0 ? 'SUCCESS' : 'FAILED');
        echo json_encode(build_payload($pdo));
        break;

    case 'verify_chain':
        echo json_encode(["status" => "SUCCESS", "chain" => audit_verify($pdo)]);
        break;

    case 'get_envelopes':
        echo json_encode(get_envelopes($pdo));
        break;

    case 'get_drifts':
        echo json_encode(get_drifts($pdo));
        break;

    case 'get_registry':
        echo json_encode(get_registry($pdo));
        break;

    default:
        http_response_code(400);
        echo json_encode(["error" => "Invalid API action route."]);
        break;
}
?>