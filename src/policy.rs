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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Out,
    In,
    Both,
}

impl Direction {
    pub fn parse(s: &str) -> Self {
        match s {
            "in" => Self::In,
            "both" => Self::Both,
            _ => Self::Out,
        }
    }
    pub fn inspects_outbound(self) -> bool {
        matches!(self, Self::Out | Self::Both)
    }
    pub fn inspects_inbound(self) -> bool {
        matches!(self, Self::In | Self::Both)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    Trusted,
    Untrusted,
}

impl Trust {
    pub fn parse(s: &str) -> Self {
        match s {
            "untrusted" => Self::Untrusted,
            _ => Self::Trusted,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundAction {
    Log,
    Sanitize,
    Block,
}

impl InboundAction {
    pub fn parse(s: &str) -> Self {
        match s {
            "sanitize" => Self::Sanitize,
            "block" => Self::Block,
            _ => Self::Log,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyDecision {
    pub action: DomainAction,
    pub direction: Direction,
    pub trust: Trust,
    pub inbound_action: InboundAction,
}

impl PartialEq<DomainAction> for PolicyDecision {
    fn eq(&self, o: &DomainAction) -> bool {
        self.action == *o
    }
}

impl PartialEq<PolicyDecision> for DomainAction {
    fn eq(&self, o: &PolicyDecision) -> bool {
        *self == o.action
    }
}

#[derive(Clone)]
pub struct Policy {
    default: PolicyDecision,
    domains: HashMap<String, PolicyDecision>,
}

impl Policy {
    pub fn new(default: &str, entries: &[DomainEntry]) -> Self {
        let default_dec = PolicyDecision {
            action: DomainAction::parse(default),
            direction: Direction::Out,
            trust: Trust::Trusted,
            inbound_action: InboundAction::Log,
        };
        let domains = entries
            .iter()
            .map(|e| {
                (
                    e.host.to_lowercase(),
                    PolicyDecision {
                        action: DomainAction::parse(&e.action),
                        direction: Direction::parse(&e.direction),
                        trust: Trust::parse(&e.trust),
                        inbound_action: InboundAction::parse(&e.inbound_action),
                    },
                )
            })
            .collect();
        Self {
            default: default_dec,
            domains,
        }
    }

    // ponytail: exact host match with wildcard suffix fallback; upgrade: full radix/trie domain matcher
    pub fn decide(&self, host: &str) -> PolicyDecision {
        let clean = host.split(':').next().unwrap_or(host).to_lowercase();
        if let Some(&dec) = self.domains.get(&clean) {
            return dec;
        }
        for (dom, &dec) in &self.domains {
            if let Some(suffix) = dom.strip_prefix("*.")
                && (clean == suffix || clean.strip_suffix(suffix).is_some_and(|p| p.ends_with('.')))
            {
                return dec;
            }
        }
        self.default
    }
}
