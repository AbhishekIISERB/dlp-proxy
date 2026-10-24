use serde::Serialize;
use std::time::SystemTime;

#[derive(Serialize)]
pub struct DecisionLog<'a> {
    pub timestamp: u64,
    pub host: &'a str,
    pub path: &'a str,
    pub action: &'a str,
    pub rules: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<&'a str>,
}

pub fn log_decision(host: &str, path: &str, action: &str, rules: &[String]) {
    log_decision_dir("out", host, path, action, rules);
}

pub fn log_decision_dir(direction: &str, host: &str, path: &str, action: &str, rules: &[String]) {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let dir = if direction == "out" {
        None
    } else {
        Some(direction)
    };
    let entry = DecisionLog {
        timestamp,
        host,
        path,
        action,
        rules,
        direction: dir,
    };
    if let Ok(json) = serde_json::to_string(&entry) {
        println!("{json}");
    }
}
