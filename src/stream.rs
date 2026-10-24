use crate::{detect::Scanner, inject, policy::Trust};

/// Maximum match length for patterns spanning chunk boundaries.
pub const MAX_MATCH_LEN: usize = 256;

#[derive(Debug, PartialEq, Eq)]
pub enum StreamAction {
    Clean,
    Hit(Vec<String>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum StreamError {
    SizeCapExceeded,
    InvalidUtf8,
}

pub struct StreamScanner {
    tail: Vec<u8>,
    total_bytes: usize,
    max_bytes: usize,
    trust: Trust,
}

impl StreamScanner {
    pub fn new(max_bytes: usize, trust: Trust) -> Self {
        Self {
            tail: Vec::with_capacity(MAX_MATCH_LEN * 2),
            total_bytes: 0,
            max_bytes,
            trust,
        }
    }

    // ponytail: sliding window scanner holds tail across chunks; upgrade: streaming Aho-Corasick automaton
    pub fn process_chunk(
        &mut self,
        chunk: &[u8],
        dlp: Option<&Scanner>,
    ) -> Result<StreamAction, StreamError> {
        self.total_bytes += chunk.len();
        if self.total_bytes > self.max_bytes {
            return Err(StreamError::SizeCapExceeded);
        }

        self.tail.extend_from_slice(chunk);
        let (valid_len, has_incomplete) = match std::str::from_utf8(&self.tail) {
            Ok(s) => (s.len(), false),
            Err(e) => {
                if e.error_len().is_none() {
                    (e.valid_up_to(), true)
                } else {
                    return Err(StreamError::InvalidUtf8);
                }
            }
        };

        if valid_len == 0 {
            return Ok(StreamAction::Clean);
        }
        let valid_str =
            std::str::from_utf8(&self.tail[..valid_len]).map_err(|_| StreamError::InvalidUtf8)?;

        let mut hits = Vec::new();
        if let Some(scanner) = dlp {
            for h in scanner.scan(valid_str) {
                hits.push(scanner.rules[h.rule].id.clone());
            }
        }
        for h in inject::scan(valid_str, self.trust) {
            hits.push(h.rule_id.to_string());
        }

        let keep_len = if valid_len >= MAX_MATCH_LEN {
            MAX_MATCH_LEN - 1
        } else {
            valid_len
        };
        let split_idx = valid_len - keep_len;
        let mut new_tail = self.tail[split_idx..valid_len].to_vec();
        if has_incomplete {
            new_tail.extend_from_slice(&self.tail[valid_len..]);
        }
        self.tail = new_tail;

        if hits.is_empty() {
            Ok(StreamAction::Clean)
        } else {
            Ok(StreamAction::Hit(hits))
        }
    }

    pub fn finish(self) -> Result<(), StreamError> {
        if !self.tail.is_empty() && std::str::from_utf8(&self.tail).is_err() {
            Err(StreamError::InvalidUtf8)
        } else {
            Ok(())
        }
    }
}
