use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub policy: PolicyConfig,
    #[serde(default)]
    pub domain: Vec<DomainEntry>,
    #[serde(default)]
    pub rule: Vec<RuleEntry>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PolicyConfig {
    #[serde(default = "default_inspect")]
    pub default: String,
    #[serde(default = "default_max_bytes")]
    pub max_body_bytes: usize,
    #[serde(default = "default_on_error")]
    pub on_error: String,
}

fn default_inspect() -> String {
    "inspect".into()
}
fn default_max_bytes() -> usize {
    1_048_576
}
fn default_on_error() -> String {
    "block".into()
}

#[derive(Debug, Deserialize, Clone)]
pub struct DomainEntry {
    pub host: String,
    pub action: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RuleEntry {
    pub id: String,
    pub pattern: String,
    pub check: Option<String>,
    #[serde(default = "default_log")]
    pub action: String,
}

fn default_log() -> String {
    "log".into()
}

// ponytail: reads config from disk on startup; upgrade: hot-reload with notify
pub fn load_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    Ok(toml::from_str(&content)?)
}
