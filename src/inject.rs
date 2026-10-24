use crate::{detect::entropy, policy::Trust};
use regex::{Regex, RegexSet};
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Tier1,
    Tier2,
    Tier3,
}

pub struct Rule {
    pub id: &'static str,
    pub tier: Tier,
    pub re: Regex,
    pub check_entropy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub rule_id: &'static str,
    pub tier: Tier,
    pub start: usize,
    pub end: usize,
}

// ponytail: regex-based hidden content detection; upgrade: full DOM parser via lol_html or scraper
pub struct InjectionScanner {
    pub rules: Vec<Rule>,
    pub set: RegexSet,
}

impl Default for InjectionScanner {
    fn default() -> Self {
        #[rustfmt::skip]
        let defs: [(&str, Tier, &str, bool); 9] = [
            ("inj-override", Tier::Tier1, r"(?i)\b(ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|former)\s+(?:instructions|prompts|commands|directives)\b", false),
            ("inj-role", Tier::Tier1, r"(?i)\b(?:you\s+are\s+now|acting\s+as|pretend\s+you\s+are|your\s+new\s+role\s+is)\b", false),
            ("inj-fake-marker", Tier::Tier1, r"(?i)(?:<\s*system\s*>|\[\s*INST\s*\]|<<SYS>>|<\|im_start\|>|<\|system\|>)", false),
            ("inj-conceal", Tier::Tier1, r"(?i)\b(?:do\s+not|never|don't)\s+(?:tell|reveal|mention|show|inform)\s+(?:to\s+)?(?:the\s+)?(?:user|human|operator|admin)\b", false),
            ("inj-hidden-style", Tier::Tier2, r#"(?i)style\s*=\s*["'][^"']*\b(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px)?)\b"#, false),
            ("inj-comment-inst", Tier::Tier2, r"(?i)<!--[\s\S]*?\b(?:ignore\s+previous|system\s+prompt|you\s+are\s+now|new\s+instructions?)\b[\s\S]*?-->", false),
            ("inj-zero-width", Tier::Tier2, r"[\u{200B}-\u{200D}\u{200E}\u{200F}\u{202A}-\u{202E}\u{2060}\u{2066}-\u{2069}\u{FEFF}]", false),
            ("inj-aria-hidden", Tier::Tier2, r#"(?i)aria-hidden\s*=\s*["']true["'][^>]*>[\s\S]*?\b(?:ignore|system|instruction)\b"#, false),
            ("inj-exfil-url", Tier::Tier3, r#"(?:!\[[^\]]*\]\((https?://[^)\s]+)\)|<img[^>]+src=["'](https?://[^"'\s]+)["'])"#, true),
        ];
        let set = RegexSet::new(defs.iter().map(|d| d.2)).expect("valid regexes");
        let rules = defs
            .into_iter()
            .map(|(id, tier, pat, check_entropy)| Rule {
                id,
                tier,
                re: Regex::new(pat).expect("valid regex"),
                check_entropy,
            })
            .collect();
        Self { rules, set }
    }
}

fn is_exfil(s: &str) -> bool {
    let url = s
        .strip_prefix("![")
        .and_then(|u| u.split_once('(')?.1.strip_suffix(')'))
        .or_else(|| {
            s.find("src=")
                .and_then(|i| s[i..].split(['"', '\'']).nth(1))
        })
        .unwrap_or(s);
    let q = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    q.split('&').any(|p| {
        let v = p.split_once('=').map(|(_, v)| v).unwrap_or(p);
        (v.len() >= 32 && entropy(v) >= 4.0) || v.len() >= 64
    })
}

impl InjectionScanner {
    pub fn scan(&self, text: &str, trust: Trust) -> Vec<Hit> {
        let matches = self.set.matches(text);
        if !matches.matched_any() {
            return vec![];
        }
        let mut hits = vec![];
        for i in matches.into_iter() {
            let r = &self.rules[i];
            if matches!(trust, Trust::Trusted) && !matches!(r.tier, Tier::Tier3) {
                continue;
            }
            for m in r.re.find_iter(text) {
                if r.check_entropy && !is_exfil(m.as_str()) {
                    continue;
                }
                hits.push(Hit {
                    rule_id: r.id,
                    tier: r.tier,
                    start: m.start(),
                    end: m.end(),
                });
            }
        }
        hits
    }
}

static SCANNER: LazyLock<InjectionScanner> = LazyLock::new(InjectionScanner::default);

pub fn scan(text: &str, trust: Trust) -> Vec<Hit> {
    SCANNER.scan(text, trust)
}

pub fn sanitize(text: &str, hits: &[Hit]) -> String {
    let mut sorted: Vec<Hit> = hits
        .iter()
        .filter(|h| h.rule_id != "inj-zero-width")
        .cloned()
        .collect();
    sorted.sort_by_key(|h| h.start);
    let mut non_overlapping: Vec<Hit> = Vec::new();
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
            out.replace_range(h.start..h.end, "[INJECTION BLOCKED]");
        }
    }
    out.retain(|c| !matches!(c, '\u{200B}'..='\u{200D}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'));
    out
}
