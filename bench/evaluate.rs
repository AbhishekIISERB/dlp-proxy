use dlp_proxy::{
    config::RuleEntry,
    detect::{Rule, Scanner},
};

fn default_rules() -> Vec<Rule> {
    [
        RuleEntry {
            id: "aws-access-key".into(),
            pattern: r"AKIA[0-9A-Z]{16}".into(),
            check: None,
            action: "block".into(),
        },
        RuleEntry {
            id: "email".into(),
            pattern: r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}".into(),
            check: None,
            action: "redact".into(),
        },
        RuleEntry {
            id: "card".into(),
            pattern: r"\b(?:\d[ -]?){13,19}\b".into(),
            check: Some("luhn".into()),
            action: "redact".into(),
        },
        RuleEntry {
            id: "high-entropy-token".into(),
            pattern: r"[A-Za-z0-9_\-]{32,}".into(),
            check: Some("entropy".into()),
            action: "log".into(),
        },
    ]
    .iter()
    .map(|e| Rule::from_config(e).unwrap())
    .collect()
}

fn generate_valid_luhn(seed: usize) -> String {
    let mut digits = vec![4, 1, 1, 1];
    for i in 0..11 {
        digits.push(((seed * 7 + i * 13) % 10) as u32);
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &x)| {
            if i % 2 == 0 {
                let y = x * 2;
                if y > 9 { y - 9 } else { y }
            } else {
                x
            }
        })
        .sum();
    let check_digit = (10 - (sum % 10)) % 10;
    digits.push(check_digit);
    digits
        .chunks(4)
        .map(|c| c.iter().map(|d| d.to_string()).collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

// Pseudo-random linear congruential generator for reproducible datasets
fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

fn main() {
    let rules = default_rules();
    let scanner = Scanner::new(rules).unwrap();

    let mut dataset: Vec<(String, Vec<&'static str>)> = Vec::new();
    let mut rng = 99999u64;

    // ==========================================
    // 1. REALISTIC POSITIVES (250 samples)
    // ==========================================

    // 50 AWS access keys in realistic formats (JSON, Form-data, Headers)
    let alnum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for i in 0..50 {
        let suffix: String = (0..16)
            .map(|_| {
                let idx = (lcg(&mut rng) as usize) % alnum.len();
                alnum.chars().nth(idx).unwrap()
            })
            .collect();
        let key = format!("AKIA{suffix}");
        let payload = match i % 3 {
            0 => format!(
                r#"{{"aws_access_key_id": "{key}", "region": "us-east-1", "action": "AssumeRole"}}"#
            ),
            1 => format!("auth_type=iam&access_key={key}&version=2026-10-13"),
            _ => format!(
                "Authorization: AWS4-HMAC-SHA256 Credential={key}/20261013/us-east-1/s3/aws4_request"
            ),
        };
        dataset.push((payload, vec!["aws-access-key"]));
    }

    // 50 Email addresses in realistic JSON, form posts, and headers
    for i in 0..50 {
        let email = format!("user_{i}.audit+security@enterprise-corp{}.com", i % 10);
        let payload = match i % 3 {
            0 => format!(r#"{{"user": {{"id": {i}, "email": "{email}", "verified": true}}}}"#),
            1 => format!("grant_type=password&username={email}&client_id=web_app"),
            _ => {
                format!("POST /v1/notifications HTTP/1.1\r\nTo: {email}\r\nSubject: Security Alert")
            }
        };
        dataset.push((payload, vec!["email"]));
    }

    // 50 Valid credit cards in realistic billing contexts
    for i in 0..50 {
        let card = generate_valid_luhn(i + 1);
        let payload = match i % 3 {
            0 => format!(
                r#"{{"payment": {{"card_number": "{card}", "cvv": "123", "exp": "11/29"}}}}"#
            ),
            1 => format!("payment_method=card&cc_number={card}&amount=49.99"),
            _ => format!("Customer checkout request: Card [{card}] authorized for $100.00"),
        };
        dataset.push((payload, vec!["card"]));
    }

    // 50 High-entropy secrets / API keys (Stripe, GitHub PAT, Cryptographic Bearer tokens)
    let secret_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
    for i in 0..50 {
        let token: String = (0..40)
            .map(|_| {
                let idx = (lcg(&mut rng) as usize) % secret_chars.len();
                secret_chars.chars().nth(idx).unwrap()
            })
            .collect();
        let payload = match i % 3 {
            0 => format!(r#"{{"api_secret": "sk_live_{token}", "active": true}}"#),
            1 => format!("Authorization: Bearer ghp_{token}"),
            _ => format!("x-api-key: {token}"),
        };
        dataset.push((payload, vec!["high-entropy-token"]));
    }

    // 50 Multi-secret compound payloads (Card + Email in same order)
    for i in 0..50 {
        let card = generate_valid_luhn(i + 100);
        let email = format!("shopper_{i}@onlinestore.org");
        let payload = format!(
            r#"{{"order_id": 9900{i}, "customer_email": "{email}", "billing": {{"card": "{card}"}}}}"#
        );
        dataset.push((payload, vec!["card", "email"]));
    }

    // ==========================================
    // 2. ADVERSARIAL HARD NEGATIVES (250 samples)
    // ==========================================

    // 50 RFC 4122 UUIDs (36 chars, hex + hyphens — look-alikes for high-entropy tokens)
    let hex = "0123456789abcdef";
    for _ in 0..50 {
        let mut u = String::new();
        for k in 0..32 {
            if k == 8 || k == 12 || k == 16 || k == 20 {
                u.push('-');
            }
            let idx = (lcg(&mut rng) as usize) % hex.len();
            u.push(hex.chars().nth(idx).unwrap());
        }
        let payload = format!(r#"{{"transaction_id": "{u}", "status": "completed"}}"#);
        dataset.push((payload, vec![]));
    }

    // 50 Git commit SHAs (40 hex) & SHA-256 hashes (64 hex)
    for i in 0..50 {
        let len = if i % 2 == 0 { 40 } else { 64 };
        let hash: String = (0..len)
            .map(|_| {
                let idx = (lcg(&mut rng) as usize) % hex.len();
                hex.chars().nth(idx).unwrap()
            })
            .collect();
        let payload = format!(r#"{{"git_ref": "{hash}", "branch": "release-v2.1"}}"#);
        dataset.push((payload, vec![]));
    }

    // 50 JWT headers/payloads & base64 encoded binary segments
    let b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for i in 0..50 {
        let b64_str: String = (0..64)
            .map(|_| {
                let idx = (lcg(&mut rng) as usize) % b64.len();
                b64.chars().nth(idx).unwrap()
            })
            .collect();
        let payload = if i % 2 == 0 {
            format!(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{b64_str}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            )
        } else {
            format!(r#"{{"data_base64": "{b64_str}=="}}"#)
        };
        dataset.push((payload, vec![]));
    }

    // 50 Random 16-digit order numbers / barcodes
    for _ in 0..50 {
        let digits: String = (0..16)
            .map(|_| {
                let d = (lcg(&mut rng) as usize) % 10;
                char::from_digit(d as u32, 10).unwrap()
            })
            .collect();
        let payload = format!(r#"{{"order_tracking_id": "{digits}", "store": "supermart"}}"#);
        dataset.push((payload, vec![]));
    }

    // 50 Benign Technical Code, SQL queries, and logs
    let benign = [
        "SELECT id, username, created_at FROM account_users WHERE status = 'active' ORDER BY id DESC LIMIT 50;",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nServer: nginx/1.24.0\r\nConnection: keep-alive",
        "INFO:worker-01: Health check passed for cluster node-eu-central-1a in 14.2ms",
        "function calculateDiscount(price, tier) { return tier === 'gold' ? price * 0.8 : price * 0.95; }",
        "sysctl -w net.ipv4.tcp_fastopen=3 net.core.somaxconn=4096 fs.file-max=2097152",
    ];
    for i in 0..50 {
        dataset.push((benign[i % benign.len()].to_string(), vec![]));
    }

    println!("Total samples in labelled dataset: {}", dataset.len());
    let rule_ids = ["aws-access-key", "email", "card", "high-entropy-token"];

    println!("| Rule ID | Expected Pos | TP | FP (Adversarial) | FN | Precision | Recall |");
    println!("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |");

    for r_id in &rule_ids {
        let mut expected_pos = 0;
        let mut tp = 0;
        let mut fp = 0;
        let mut fn_count = 0;

        for (text, expected_labels) in &dataset {
            let hits = scanner.scan(text);
            let matched = hits.iter().any(|h| scanner.rules[h.rule].id == *r_id);
            let is_target = expected_labels.contains(r_id);

            if is_target {
                expected_pos += 1;
            }

            match (matched, is_target) {
                (true, true) => tp += 1,
                (true, false) => fp += 1,
                (false, true) => fn_count += 1,
                (false, false) => {}
            }
        }

        let precision = if tp + fp > 0 {
            (tp as f64 / (tp + fp) as f64) * 100.0
        } else {
            100.0
        };
        let recall = if tp + fn_count > 0 {
            (tp as f64 / (tp + fn_count) as f64) * 100.0
        } else {
            100.0
        };

        println!(
            "| `{r_id}` | {expected_pos} | {tp} | {fp} | {fn_count} | **{precision:.1}%** | **{recall:.1}%** |"
        );
    }
}
