use crate::{
    detect::{self, Action, Hit, Rule},
    log::log_decision,
    policy::{DomainAction, Policy},
};
use http_body_util::BodyExt;
use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse, decode_request,
    hyper::{Request, Response, StatusCode, header::{CONTENT_LENGTH, HOST, HeaderValue}},
};
use std::sync::Arc;

#[derive(Clone)]
pub struct DlpHandler {
    pub policy: Arc<Policy>,
    pub rules: Arc<Vec<Rule>>,
    pub max_body_bytes: usize,
    pub fail_closed: bool,
}

impl HttpHandler for DlpHandler {
    async fn handle_request(&mut self, _ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        let uri = req.uri();
        let host = uri
            .host()
            .or_else(|| req.headers().get(HOST).and_then(|v| v.to_str().ok()))
            .unwrap_or("")
            .to_string();
        let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/").to_string();

        match self.policy.decide(&host) {
            DomainAction::Block => {
                log_decision(&host, &path, "block", &[]);
                return block_response();
            }
            DomainAction::Allow => {
                log_decision(&host, &path, "allow", &[]);
                return req.into();
            }
            DomainAction::Inspect => {}
        }

        if let Some(cl) = req.headers().get(CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<usize>().ok()) {
            if cl > self.max_body_bytes {
                log_decision(&host, &path, "block:size_cap_exceeded", &[]);
                return block_response();
            }
        }

        let req = match decode_request(req) {
            Ok(r) => r,
            Err(_) => {
                log_decision(&host, &path, "block:decode_error", &[]);
                return block_response();
            }
        };

        let (mut parts, body) = req.into_parts();
        // ponytail: reads whole body into memory; upgrade: stream with a size cap
        let collected = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => {
                log_decision(&host, &path, "block:body_read_error", &[]);
                return block_response();
            }
        };

        if collected.len() > self.max_body_bytes {
            log_decision(&host, &path, "block:size_cap_exceeded", &[]);
            return block_response();
        }

        // ponytail: text bodies only; upgrade: multipart and binary formats
        let text = match std::str::from_utf8(&collected) {
            Ok(t) => t,
            Err(_) => {
                log_decision(&host, &path, "skipped: binary", &[]);
                return Request::from_parts(parts, Body::from(collected)).into();
            }
        };

        let hits = detect::scan(&self.rules, text);
        if hits.is_empty() {
            log_decision(&host, &path, "allow", &[]);
            return Request::from_parts(parts, Body::from(collected)).into();
        }

        let rule_ids: Vec<String> = hits.iter().map(|h| self.rules[h.rule].id.clone()).collect();
        if hits.iter().any(|h| matches!(self.rules[h.rule].action, Action::Block)) {
            log_decision(&host, &path, "block", &rule_ids);
            return block_response();
        }

        let has_redact = hits.iter().any(|h| matches!(self.rules[h.rule].action, Action::Redact));
        if has_redact {
            let redact_hits: Vec<Hit> = hits.into_iter().filter(|h| matches!(self.rules[h.rule].action, Action::Redact)).collect();
            let redacted_text = detect::redact(text, &redact_hits);
            let bytes = redacted_text.into_bytes();
            parts.headers.insert(CONTENT_LENGTH, HeaderValue::from(bytes.len()));
            log_decision(&host, &path, "redact", &rule_ids);
            return Request::from_parts(parts, Body::from(bytes)).into();
        }

        log_decision(&host, &path, "log", &rule_ids);
        Request::from_parts(parts, Body::from(collected)).into()
    }
}

fn block_response() -> RequestOrResponse {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::from("403 Forbidden: Blocked by DLP Proxy\n"))
        .unwrap()
        .into()
}
