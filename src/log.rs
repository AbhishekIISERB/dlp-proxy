use serde::Serialize;
use std::time::SystemTime;

#[derive(Serialize)]
pub struct DecisionLog<'a> {
    pub timestamp: u64,
    pub host: &'a str,
    pub path: &'a str,
    pub action: &'a str,
    pub rules: &'a [String],
}

pub fn log_decision(host: &str, path: &str, action: &str, rules: &[String]) {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let entry = DecisionLog {
        timestamp,
        host,
        path,
        action,
        rules,
    };
    if let Ok(json) = serde_json::to_string(&entry) {
        println!("{json}");
    }
}
