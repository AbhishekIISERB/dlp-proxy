use dlp_proxy::{
    config::{DomainEntry, RuleEntry},
    detect::{self, Rule, Scanner},
    policy::{DomainAction, Policy},
};

fn default_rules() -> Vec<Rule> {
    let entries = [
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
    ];
    entries
        .iter()
        .map(|e| Rule::from_config(e).unwrap())
        .collect()
}

#[test]
fn test_detector_table_driven() {
    let rules = default_rules();
    let scanner = Scanner::new(rules).unwrap();
    let cases = vec![
        ("Clean text with nothing sensitive", vec![]),
        (
            "My key is AKIA1234567890ABCDEF here",
            vec!["aws-access-key"],
        ),
        ("Short key AKIA12345 is ignored", vec![]),
        ("Contact test@example.com for info", vec!["email"]),
        ("Valid card: 4111 1111 1111 1111 here", vec!["card"]),
        ("Valid card unspaced: 4111111111111111", vec!["card"]),
        ("Invalid card checksum: 4111 1111 1111 1112", vec![]),
        ("Repeat char: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", vec![]),
        (
            "High entropy token: aZ9_bK2-xP8_qW4-mN1_vC7-yL5_jH3_fD",
            vec!["high-entropy-token"],
        ),
    ];

    for (input, expected_rules) in cases {
        let hits = scanner.scan(input);
        let matched: Vec<&str> = hits
            .iter()
            .map(|h| scanner.rules[h.rule].id.as_str())
            .collect();
        assert_eq!(matched, expected_rules, "Failed for input: {input}");
    }
}

#[test]
fn test_luhn_algorithm() {
    assert!(detect::luhn("4111 1111 1111 1111"));
    assert!(detect::luhn("4111-1111-1111-1111"));
    assert!(detect::luhn("4111111111111111"));
    assert!(!detect::luhn("4111 1111 1111 1112"));
    assert!(!detect::luhn("1234"));
}

#[test]
fn test_entropy_calculation() {
    let zero = detect::entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert_eq!(zero, 0.0);
    let high = detect::entropy("abcdefghijklmnopqrstuvwxyz012345");
    assert!(high > 4.5);
}

#[test]
fn test_redaction_and_overlaps() {
    let rules = default_rules();
    let scanner = Scanner::new(rules).unwrap();
    let input = "Card: 4111 1111 1111 1111, Email: user@example.com";
    let hits = scanner.scan(input);
    assert_eq!(hits.len(), 2);
    let redacted = detect::redact(input, &hits);
    assert_eq!(redacted, "Card: [REDACTED], Email: [REDACTED]");
}

#[test]
fn test_policy_lookup() {
    let domains = vec![
        DomainEntry {
            host: "ads.example.com".into(),
            action: "block".into(),
        },
        DomainEntry {
            host: "safe.internal".into(),
            action: "allow".into(),
        },
    ];
    let policy = Policy::new("inspect", &domains);

    assert_eq!(policy.decide("ads.example.com"), DomainAction::Block);
    assert_eq!(policy.decide("ads.example.com:443"), DomainAction::Block);
    assert_eq!(policy.decide("ADS.EXAMPLE.COM"), DomainAction::Block);
    assert_eq!(policy.decide("safe.internal"), DomainAction::Allow);
    assert_eq!(policy.decide("other.example.com"), DomainAction::Inspect);
}
