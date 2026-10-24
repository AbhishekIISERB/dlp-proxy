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
            direction: "out".into(),
            trust: "trusted".into(),
            inbound_action: "log".into(),
        },
        DomainEntry {
            host: "safe.internal".into(),
            action: "allow".into(),
            direction: "out".into(),
            trust: "trusted".into(),
            inbound_action: "log".into(),
        },
    ];
    let policy = Policy::new("inspect", &domains);

    assert_eq!(policy.decide("ads.example.com"), DomainAction::Block);
    assert_eq!(policy.decide("ads.example.com:443"), DomainAction::Block);
    assert_eq!(policy.decide("ADS.EXAMPLE.COM"), DomainAction::Block);
    assert_eq!(policy.decide("safe.internal"), DomainAction::Allow);
    assert_eq!(policy.decide("other.example.com"), DomainAction::Inspect);
}

#[test]
fn test_policy_wildcard_matching() {
    let domains = vec![
        DomainEntry {
            host: "*.example.com".into(),
            action: "block".into(),
            direction: "both".into(),
            trust: "untrusted".into(),
            inbound_action: "block".into(),
        },
        DomainEntry {
            host: "special.example.com".into(),
            action: "allow".into(),
            direction: "out".into(),
            trust: "trusted".into(),
            inbound_action: "log".into(),
        },
    ];
    let policy = Policy::new("inspect", &domains);

    // Exact match has higher precedence over wildcard
    assert_eq!(policy.decide("special.example.com"), DomainAction::Allow);
    assert_eq!(
        policy.decide("special.example.com:443"),
        DomainAction::Allow
    );

    // Wildcard matches subdomains
    assert_eq!(policy.decide("api.example.com"), DomainAction::Block);
    assert_eq!(policy.decide("sub.api.example.com"), DomainAction::Block);

    // Wildcard matches apex domain
    assert_eq!(policy.decide("example.com"), DomainAction::Block);

    // Suffix collision prevention: "fake-example.com" should NOT match "*.example.com"
    assert_eq!(policy.decide("fake-example.com"), DomainAction::Inspect);
    assert_eq!(policy.decide("notexample.com"), DomainAction::Inspect);
    assert_eq!(policy.decide("other.com"), DomainAction::Inspect);
}

#[test]
fn test_rules_toml_backward_compatibility() {
    let cfg = dlp_proxy::config::load_config("rules.toml").expect("Failed to parse rules.toml");
    assert_eq!(cfg.policy.default, "inspect");
    assert_eq!(cfg.policy.direction, "out");
    assert_eq!(cfg.policy.trust, "trusted");
    assert_eq!(cfg.policy.inbound_action, "log");

    let ads = cfg
        .domain
        .iter()
        .find(|d| d.host == "ads.example.com")
        .expect("ads.example.com found");
    assert_eq!(ads.action, "block");
    assert_eq!(ads.direction, "out");
    assert_eq!(ads.trust, "trusted");
    assert_eq!(ads.inbound_action, "log");
}

#[test]
fn test_policy_inbound_fields_table_driven() {
    use dlp_proxy::policy::{Direction, InboundAction, Trust};

    let cases = vec![
        (
            "untrusted-web.com",
            "inspect",
            "both",
            "untrusted",
            "sanitize",
            DomainAction::Inspect,
            Direction::Both,
            Trust::Untrusted,
            InboundAction::Sanitize,
        ),
        (
            "strict-sandbox.net",
            "inspect",
            "in",
            "untrusted",
            "block",
            DomainAction::Inspect,
            Direction::In,
            Trust::Untrusted,
            InboundAction::Block,
        ),
        (
            "internal-api.corp",
            "allow",
            "out",
            "trusted",
            "log",
            DomainAction::Allow,
            Direction::Out,
            Trust::Trusted,
            InboundAction::Log,
        ),
        (
            "legacy-default.org",
            "inspect",
            "out",
            "trusted",
            "log",
            DomainAction::Inspect,
            Direction::Out,
            Trust::Trusted,
            InboundAction::Log,
        ),
        (
            "fallback-fields.xyz",
            "unknown",
            "unknown",
            "unknown",
            "unknown",
            DomainAction::Inspect,
            Direction::Out,
            Trust::Trusted,
            InboundAction::Log,
        ),
    ];

    let entries: Vec<DomainEntry> = cases
        .iter()
        .map(|(host, act, dir, tr, in_act, _, _, _, _)| DomainEntry {
            host: (*host).into(),
            action: (*act).into(),
            direction: (*dir).into(),
            trust: (*tr).into(),
            inbound_action: (*in_act).into(),
        })
        .collect();

    let policy = Policy::new("inspect", &entries);

    for (host, _, _, _, _, exp_act, exp_dir, exp_tr, exp_in_act) in cases {
        let d = policy.decide(host);
        assert_eq!(d.action, exp_act, "Action mismatch for {host}");
        assert_eq!(d.direction, exp_dir, "Direction mismatch for {host}");
        assert_eq!(d.trust, exp_tr, "Trust mismatch for {host}");
        assert_eq!(
            d.inbound_action, exp_in_act,
            "InboundAction mismatch for {host}"
        );
    }

    let unlisted = policy.decide("random-unlisted.com");
    assert_eq!(unlisted.action, DomainAction::Inspect);
    assert_eq!(unlisted.direction, Direction::Out);
    assert_eq!(unlisted.trust, Trust::Trusted);
    assert_eq!(unlisted.inbound_action, InboundAction::Log);
}

#[test]
fn test_direction_predicates() {
    use dlp_proxy::policy::Direction;
    assert!(Direction::Out.inspects_outbound());
    assert!(!Direction::Out.inspects_inbound());

    assert!(!Direction::In.inspects_outbound());
    assert!(Direction::In.inspects_inbound());

    assert!(Direction::Both.inspects_outbound());
    assert!(Direction::Both.inspects_inbound());
}

#[test]
fn test_toml_deserialization_with_new_fields() {
    let toml_str = r#"
        [policy]
        default = "inspect"
        direction = "both"
        trust = "untrusted"
        inbound_action = "sanitize"

        [[domain]]
        host = "wiki.org"
        action = "inspect"
        direction = "both"
        trust = "untrusted"
        inbound_action = "sanitize"

        [[domain]]
        host = "plain.org"
        action = "allow"
    "#;

    let cfg: dlp_proxy::config::Config = toml::from_str(toml_str).unwrap();
    assert_eq!(cfg.policy.direction, "both");
    assert_eq!(cfg.policy.trust, "untrusted");
    assert_eq!(cfg.policy.inbound_action, "sanitize");

    let wiki = cfg.domain.iter().find(|d| d.host == "wiki.org").unwrap();
    assert_eq!(wiki.direction, "both");
    assert_eq!(wiki.trust, "untrusted");
    assert_eq!(wiki.inbound_action, "sanitize");

    let plain = cfg.domain.iter().find(|d| d.host == "plain.org").unwrap();
    assert_eq!(plain.action, "allow");
    assert_eq!(plain.direction, "out");
    assert_eq!(plain.trust, "trusted");
    assert_eq!(plain.inbound_action, "log");
}
