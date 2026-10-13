use dlp_proxy::{
    config::RuleEntry,
    detect::{self, Rule},
};

fn default_rules() -> Vec<Rule> {
    vec![
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
    // Calculate check digit
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &x)| if i % 2 == 0 { let y = x * 2; if y > 9 { y - 9 } else { y } } else { x })
        .sum();
    let check_digit = (10 - (sum % 10)) % 10;
    digits.push(check_digit);
    digits.chunks(4).map(|c| c.iter().map(|d| d.to_string()).collect::<String>()).collect::<Vec<_>>().join(" ")
}

fn generate_invalid_luhn(seed: usize) -> String {
    let mut valid = generate_valid_luhn(seed);
    let last = valid.pop().unwrap();
    let flipped = if last == '0' { '1' } else { '0' };
    valid.push(flipped);
    valid
}

fn main() {
    let rules = default_rules();
    let mut dataset: Vec<(String, Option<&'static str>)> = Vec::new();

    // 1. Positives (200)
    // 50 AWS access keys
    let alnum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for i in 0..50 {
        let suffix: String = (0..16)
            .map(|j| alnum.chars().nth((i * 17 + j * 23) % alnum.len()).unwrap())
            .collect();
        dataset.push((format!("AKIA{suffix}"), Some("aws-access-key")));
    }

    // 50 Emails
    for i in 0..50 {
        dataset.push((format!("employee_{i}.audit@internal-corp{i}.org"), Some("email")));
    }

    // 50 Valid Credit Cards
    for i in 0..50 {
        dataset.push((generate_valid_luhn(i + 1), Some("card")));
    }

    // 50 High-entropy tokens
    let pool = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for i in 0..50 {
        let tok: String = (0..36)
            .map(|j| pool.chars().nth((i * 31 + j * 47 + j * j) % pool.len()).unwrap())
            .collect();
        dataset.push((tok, Some("high-entropy-token")));
    }

    // 2. Negatives (200)
    // 50 Lookalike IDs / Short keys
    for i in 0..50 {
        dataset.push((format!("ORDER-ID-99882{i}"), None));
    }

    // 50 Natural language sentences
    let sentences = [
        "The quick brown fox jumps over the lazy dog.",
        "System latency is well within expected operating parameters.",
        "Please review the attached quarterly summary before Friday.",
        "All services reported healthy status during the automated check.",
        "Configuration update has been applied successfully across nodes.",
    ];
    for i in 0..50 {
        dataset.push((format!("{} (iteration {})", sentences[i % sentences.len()], i), None));
    }

    // 50 Invalid card numbers (fails Luhn)
    for i in 0..50 {
        dataset.push((generate_invalid_luhn(i + 1), None));
    }

    // 50 Low-entropy repeated or patterned strings
    for i in 0..50 {
        let rep = format!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa{}", i);
        dataset.push((rep, None));
    }

    println!("Total samples in labelled dataset: {}", dataset.len());
    let rule_ids = ["aws-access-key", "email", "card", "high-entropy-token"];

    println!("| Rule ID | Positives (TP) | False Pos (FP) | False Neg (FN) | Precision | Recall |");
    println!("| :--- | :--- | :--- | :--- | :--- | :--- |");

    for r_id in &rule_ids {
        let mut tp = 0;
        let mut fp = 0;
        let mut fn_count = 0;

        for (text, expected_label) in &dataset {
            let hits = detect::scan(&rules, text);
            let matched = hits.iter().any(|h| rules[h.rule].id == *r_id);
            let is_target = expected_label.map_or(false, |lbl| lbl == *r_id);

            match (matched, is_target) {
                (true, true) => tp += 1,
                (true, false) => fp += 1,
                (false, true) => fn_count += 1,
                (false, false) => {}
            }
        }

        let precision = if tp + fp > 0 { (tp as f64 / (tp + fp) as f64) * 100.0 } else { 100.0 };
        let recall = if tp + fn_count > 0 { (tp as f64 / (tp + fn_count) as f64) * 100.0 } else { 100.0 };

        println!(
            "| `{r_id}` | {tp} | {fp} | {fn_count} | {precision:.1}% | {recall:.1}% |"
        );
    }
}
