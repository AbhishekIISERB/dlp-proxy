use crate::config::DomainEntry;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainAction {
    Allow,
    Block,
    Inspect,
}

impl DomainAction {
    pub fn parse(s: &str) -> Self {
        match s {
            "allow" => Self::Allow,
            "block" => Self::Block,
            _ => Self::Inspect,
        }
    }
}

#[derive(Clone)]
pub struct Policy {
    default: DomainAction,
    domains: HashMap<String, DomainAction>,
}

impl Policy {
    pub fn new(default: &str, entries: &[DomainEntry]) -> Self {
        let domains = entries
            .iter()
            .map(|e| (e.host.to_lowercase(), DomainAction::parse(&e.action)))
            .collect();
        Self {
            default: DomainAction::parse(default),
            domains,
        }
    }

    // ponytail: exact host match only; upgrade: support wildcards and suffix matching
    pub fn decide(&self, host: &str) -> DomainAction {
        let clean = host.split(':').next().unwrap_or(host).to_lowercase();
        self.domains.get(&clean).copied().unwrap_or(self.default)
    }
}
