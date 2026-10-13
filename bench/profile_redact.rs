use dlp_proxy::{
    config::RuleEntry,
    detect::{Rule, Scanner, redact},
};
use std::time::Instant;

fn generate_payload_with_secrets(size: usize) -> String {
    let key = "AKIAIOSFODNN7EXAMPLE";
    let email = "auditor.security@corp-example.com";
    let card = "4111-1111-1111-1111"; // valid Luhn

    let head = format!(r#"{{"auth": "{key}", "records": ["#);
    let mid_secret = format!(r#", {{"user_email": "{email}"}}, "#);
    let tail_secret = format!(r#", {{"billing": "{card}"}}]}}"#);

    let filler = r#"{"item": "catalog_product_id_882194", "status": "active"}"#;
    let mut out = head;
    let target_mid = size / 2;
    let mut added_mid = false;

    while out.len() + tail_secret.len() < size {
        if !added_mid && out.len() >= target_mid {
            out.push_str(&mid_secret);
            added_mid = true;
        } else {
            if out.len() > 30 && !out.ends_with('[') && !out.ends_with(", ") {
                out.push_str(", ");
            }
            out.push_str(filler);
        }
    }
    if !added_mid {
        out.push_str(&mid_secret);
    }
    out.push_str(&tail_secret);
    out
}

fn main() {
    println!("Initializing scanner for profiling...");
    let rules = vec![
        RuleEntry { id: "aws-access-key".into(), pattern: r"AKIA[0-9A-Z]{16}".into(), check: None, action: "redact".into() },
        RuleEntry { id: "email".into(), pattern: r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}".into(), check: None, action: "redact".into() },
        RuleEntry { id: "card".into(), pattern: r"\b(?:\d[ -]?){13,19}\b".into(), check: Some("luhn".into()), action: "redact".into() },
    ]
    .iter()
    .map(|e| Rule::from_config(e).unwrap())
    .collect();

    let scanner = Scanner::new(rules).unwrap();

    let p_1k = generate_payload_with_secrets(1024);
    let p_100k = generate_payload_with_secrets(100 * 1024);
    let p_1m = generate_payload_with_secrets(1024 * 1024);

    let hits_1k = scanner.scan(&p_1k);
    let hits_100k = scanner.scan(&p_100k);
    let hits_1m = scanner.scan(&p_1m);

    println!("Hits found: 1KB={}, 100KB={}, 1MB={}", hits_1k.len(), hits_100k.len(), hits_1m.len());

    println!("Profiling redact() on 1MB payload (running for ~5 seconds)...");
    let start_1m = Instant::now();
    let mut count_1m = 0;
    while start_1m.elapsed().as_secs() < 3 {
        let res = redact(&p_1m, &hits_1m);
        std::hint::black_box(res);
        count_1m += 1;
    }
    println!("Completed {} iterations of redact() on 1MB in {:.2}s ({:.2} µs/op)",
        count_1m, start_1m.elapsed().as_secs_f64(), (start_1m.elapsed().as_secs_f64() * 1_000_000.0) / count_1m as f64);

    println!("Profiling redact() on 100KB payload (running for ~2 seconds)...");
    let start_100k = Instant::now();
    let mut count_100k = 0;
    while start_100k.elapsed().as_secs() < 2 {
        let res = redact(&p_100k, &hits_100k);
        std::hint::black_box(res);
        count_100k += 1;
    }
    println!("Completed {} iterations of redact() on 100KB in {:.2}s ({:.2} µs/op)",
        count_100k, start_100k.elapsed().as_secs_f64(), (start_100k.elapsed().as_secs_f64() * 1_000_000.0) / count_100k as f64);

    println!("Profiling redact() on 1KB payload (running for ~1 second)...");
    let start_1k = Instant::now();
    let mut count_1k = 0;
    while start_1k.elapsed().as_secs() < 1 {
        let res = redact(&p_1k, &hits_1k);
        std::hint::black_box(res);
        count_1k += 1;
    }
    println!("Completed {} iterations of redact() on 1KB in {:.2}s ({:.2} µs/op)",
        count_1k, start_1k.elapsed().as_secs_f64(), (start_1k.elapsed().as_secs_f64() * 1_000_000.0) / count_1k as f64);
}
