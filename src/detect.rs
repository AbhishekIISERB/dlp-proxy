use crate::config::RuleEntry;
use regex::{Regex, RegexSet};

#[derive(Debug, Clone)]
pub enum Check { None, Luhn, Entropy(f64) }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action { Block, Redact, Log }

#[derive(Clone)]
pub struct Rule {
    pub id: String,
    pub re: Regex,
    pub check: Check,
    pub action: Action,
}

#[derive(Debug, Clone)]
pub struct Hit { pub rule: usize, pub start: usize, pub end: usize }

impl Rule {
    pub fn from_config(e: &RuleEntry) -> Result<Self, regex::Error> {
        let check = match e.check.as_deref() {
            Some("luhn") => Check::Luhn,
            Some("entropy") => Check::Entropy(4.0),
            _ => Check::None,
        };
        let action = match e.action.as_str() {
            "block" => Action::Block,
            "redact" => Action::Redact,
            _ => Action::Log,
        };
        Ok(Self { id: e.id.clone(), re: Regex::new(&e.pattern)?, check, action })
    }
}

pub struct Scanner {
    pub rules: Vec<Rule>,
    pub set: RegexSet,
}

impl Scanner {
    pub fn new(rules: Vec<Rule>) -> Result<Self, regex::Error> {
        let patterns: Vec<&str> = rules.iter().map(|r| r.re.as_str()).collect();
        let set = RegexSet::new(patterns)?;
        Ok(Self { rules, set })
    }

    // ponytail: regex set pre-filters rules before exact position extraction
    pub fn scan(&self, text: &str) -> Vec<Hit> {
        let matches = self.set.matches(text);
        if !matches.matched_any() { return vec![]; }
        let mut hits = vec![];
        for i in matches.into_iter() {
            let r = &self.rules[i];
            for m in r.re.find_iter(text) {
                let ok = match r.check {
                    Check::None => true,
                    Check::Luhn => luhn(m.as_str()),
                    Check::Entropy(min) => entropy(m.as_str()) >= min,
                };
                if ok { hits.push(Hit { rule: i, start: m.start(), end: m.end() }); }
            }
        }
        hits
    }
}

pub fn luhn(s: &str) -> bool {
    let d: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if d.len() < 13 || d.len() > 19 || !matches!(d[0], 3..=6) { return false; }
    let sum: u32 = d.iter().rev().enumerate()
        .map(|(i, &x)| if i % 2 == 1 { let y = x * 2; if y > 9 { y - 9 } else { y } } else { x })
        .sum();
    sum % 10 == 0
}

pub fn entropy(s: &str) -> f64 {
    if s.is_empty() || s.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') { return 0.0; }
    let mut counts = [0usize; 256];
    for &b in s.as_bytes() { counts[b as usize] += 1; }
    let n = s.len() as f64;
    counts.iter().filter(|&&c| c > 0).map(|&c| { let p = c as f64 / n; -p * p.log2() }).sum()
}

pub fn redact(text: &str, hits: &[Hit]) -> String {
    let mut sorted = hits.to_vec();
    sorted.sort_by_key(|h| h.start);
    let mut non_overlapping = Vec::new();
    let mut last_end = 0;
    for h in sorted {
        if h.start >= last_end {
            last_end = h.end;
            non_overlapping.push(h);
        }
    }
    let mut out = text.to_string();
    for h in non_overlapping.into_iter().rev() {
        if h.start <= out.len() && h.end <= out.len() && h.start <= h.end {
            out.replace_range(h.start..h.end, "[REDACTED]");
        }
    }
    out
}
