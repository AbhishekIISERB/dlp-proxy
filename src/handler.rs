use crate::{
    detect::{self, Action, Hit, Scanner},
    inject, llm,
    log::log_decision_dir,
    policy::{DomainAction, InboundAction, Policy, PolicyDecision, Trust},
};
use http_body_util::BodyExt;
use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse, decode_request, decode_response,
    hyper::{
        Request, Response, StatusCode,
        body::Bytes,
        header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG, HOST, HeaderValue},
    },
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, LazyLock, Mutex},
};

type ReqState = (String, String, PolicyDecision);

static PENDING_REQUESTS: LazyLock<Mutex<HashMap<SocketAddr, ReqState>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Clone)]
pub struct DlpHandler {
    pub policy: Arc<Policy>,
    pub scanner: Arc<Scanner>,
    pub max_body_bytes: usize,
    pub fail_closed: bool,
}

impl HttpHandler for DlpHandler {
    async fn handle_request(&mut self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        let uri = req.uri();
        let host = uri
            .host()
            .or_else(|| req.headers().get(HOST).and_then(|v| v.to_str().ok()))
            .unwrap_or("")
            .to_string();
        let path = uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/")
            .to_string();

        let decision = self.policy.decide(&host);
        PENDING_REQUESTS
            .lock()
            .unwrap()
            .insert(ctx.client_addr, (host.clone(), path.clone(), decision));

        match decision.action {
            DomainAction::Block => {
                PENDING_REQUESTS.lock().unwrap().remove(&ctx.client_addr);
                log_decision_dir("out", &host, &path, "block", &[]);
                return block_response("403 Forbidden: Blocked by DLP Proxy\n").into();
            }
            DomainAction::Allow => {
                log_decision_dir("out", &host, &path, "allow", &[]);
                return req.into();
            }
            DomainAction::Inspect => {}
        }

        if !decision.direction.inspects_outbound() {
            log_decision_dir("out", &host, &path, "allow:direction_in_only", &[]);
            return req.into();
        }

        if matches!(
            check_content_length(req.headers().get(CONTENT_LENGTH), self.max_body_bytes),
            Some(false)
        ) {
            PENDING_REQUESTS.lock().unwrap().remove(&ctx.client_addr);
            log_decision_dir("out", &host, &path, "block:size_cap_exceeded", &[]);
            return block_response("403 Forbidden: Blocked by DLP Proxy (Size Cap Exceeded)\n")
                .into();
        }

        let req = match decode_request(req) {
            Ok(r) => r,
            Err(_) => {
                PENDING_REQUESTS.lock().unwrap().remove(&ctx.client_addr);
                log_decision_dir("out", &host, &path, "block:decode_error", &[]);
                return block_response("403 Forbidden: Blocked by DLP Proxy (Decode Error)\n")
                    .into();
            }
        };

        let (mut parts, body) = req.into_parts();
        // ponytail: reads whole body into memory; upgrade: stream with a size cap
        let collected = match collect_body_with_cap(body, self.max_body_bytes).await {
            Ok(c) => c,
            Err(e) => {
                PENDING_REQUESTS.lock().unwrap().remove(&ctx.client_addr);
                log_decision_dir("out", &host, &path, &format!("block:{e}"), &[]);
                return block_response("403 Forbidden: Blocked by DLP Proxy\n").into();
            }
        };

        // ponytail: text bodies only; upgrade: multipart and binary formats
        let text = match std::str::from_utf8(&collected) {
            Ok(t) => t,
            Err(_) => {
                log_decision_dir("out", &host, &path, "skipped: binary", &[]);
                return Request::from_parts(parts, Body::from(collected)).into();
            }
        };

        let chat_msgs = llm::parse_chat_messages(text);
        if let Some(ref msgs) = chat_msgs {
            for msg in msgs {
                if msg.is_tool_result {
                    let inj_hits = inject::scan(&msg.text, Trust::Untrusted);
                    if !inj_hits.is_empty() {
                        let rule_ids: Vec<String> =
                            inj_hits.iter().map(|h| h.rule_id.to_string()).collect();
                        PENDING_REQUESTS.lock().unwrap().remove(&ctx.client_addr);
                        log_decision_dir(
                            "out",
                            &host,
                            &path,
                            &format!("block:{}", msg.role),
                            &rule_ids,
                        );
                        return block_response(
                            "403 Forbidden: Blocked by DLP Proxy (Injection in Tool Result)\n",
                        )
                        .into();
                    }
                }
            }
        }

        let hits = self.scanner.scan(text);
        if hits.is_empty() {
            log_decision_dir("out", &host, &path, "allow", &[]);
            return Request::from_parts(parts, Body::from(collected)).into();
        }

        let rule_ids: Vec<String> = hits
            .iter()
            .map(|h| self.scanner.rules[h.rule].id.clone())
            .collect();

        let triggered_role = chat_msgs.as_ref().and_then(|msgs| {
            msgs.iter()
                .find(|m| !self.scanner.scan(&m.text).is_empty())
                .map(|m| m.role.as_str())
        });
        let role_suffix = triggered_role.map(|r| format!(":{r}")).unwrap_or_default();

        if hits
            .iter()
            .any(|h| matches!(self.scanner.rules[h.rule].action, Action::Block))
        {
            PENDING_REQUESTS.lock().unwrap().remove(&ctx.client_addr);
            log_decision_dir(
                "out",
                &host,
                &path,
                &format!("block{role_suffix}"),
                &rule_ids,
            );
            return block_response("403 Forbidden: Blocked by DLP Proxy\n").into();
        }

        let has_redact = hits
            .iter()
            .any(|h| matches!(self.scanner.rules[h.rule].action, Action::Redact));
        if has_redact {
            let redact_hits: Vec<Hit> = hits
                .into_iter()
                .filter(|h| matches!(self.scanner.rules[h.rule].action, Action::Redact))
                .collect();
            let redacted_text = detect::redact(text, &redact_hits);
            let bytes = redacted_text.into_bytes();
            parts
                .headers
                .insert(CONTENT_LENGTH, HeaderValue::from(bytes.len()));
            log_decision_dir(
                "out",
                &host,
                &path,
                &format!("redact{role_suffix}"),
                &rule_ids,
            );
            return Request::from_parts(parts, Body::from(bytes)).into();
        }

        log_decision_dir("out", &host, &path, &format!("log{role_suffix}"), &rule_ids);
        Request::from_parts(parts, Body::from(collected)).into()
    }

    async fn handle_response(&mut self, ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let (host, path, decision) = match PENDING_REQUESTS.lock().unwrap().remove(&ctx.client_addr)
        {
            Some(state) => state,
            None => return res,
        };

        if !decision.direction.inspects_inbound() || decision.action == DomainAction::Allow {
            return res;
        }

        if matches!(
            check_content_length(res.headers().get(CONTENT_LENGTH), self.max_body_bytes),
            Some(false)
        ) {
            log_decision_dir("in", &host, &path, "block:size_cap_exceeded", &[]);
            return block_response("403 Forbidden: Blocked by DLP Proxy (Size Cap Exceeded)\n");
        }

        let res = match decode_response(res) {
            Ok(r) => r,
            Err(_) => {
                log_decision_dir("in", &host, &path, "block:decode_error", &[]);
                return block_response("403 Forbidden: Blocked by DLP Proxy (Decode Error)\n");
            }
        };

        let (mut parts, body) = res.into_parts();
        // ponytail: content-type gating allows text, JSON, and XML; upgrade: parse multipart & binary formats
        if !is_scannable_content_type(parts.headers.get(CONTENT_TYPE)) {
            log_decision_dir("in", &host, &path, "skipped:content_type", &[]);
            return Response::from_parts(parts, body);
        }

        let collected = match collect_body_with_cap(body, self.max_body_bytes).await {
            Ok(c) => c,
            Err(e) => {
                log_decision_dir("in", &host, &path, &format!("block:{e}"), &[]);
                return block_response("403 Forbidden: Blocked by DLP Proxy\n");
            }
        };

        let text = match std::str::from_utf8(&collected) {
            Ok(t) => t,
            Err(_) => {
                log_decision_dir("in", &host, &path, "skipped: binary", &[]);
                return Response::from_parts(parts, Body::from(collected));
            }
        };

        let hits = inject::scan(text, decision.trust);
        if hits.is_empty() {
            log_decision_dir("in", &host, &path, "allow", &[]);
            return Response::from_parts(parts, Body::from(collected));
        }

        let rule_ids: Vec<String> = hits.iter().map(|h| h.rule_id.to_string()).collect();
        match decision.inbound_action {
            InboundAction::Log => {
                log_decision_dir("in", &host, &path, "log", &rule_ids);
                Response::from_parts(parts, Body::from(collected))
            }
            InboundAction::Sanitize => {
                let sanitized = inject::sanitize(text, &hits);
                let bytes = sanitized.into_bytes();
                parts
                    .headers
                    .insert(CONTENT_LENGTH, HeaderValue::from(bytes.len()));
                parts.headers.remove(CONTENT_ENCODING);
                parts.headers.remove("content-md5");
                parts.headers.remove(ETAG);
                log_decision_dir("in", &host, &path, "sanitize", &rule_ids);
                Response::from_parts(parts, Body::from(bytes))
            }
            InboundAction::Block => {
                log_decision_dir("in", &host, &path, "block", &rule_ids);
                block_response("403 Forbidden: Blocked by DLP Proxy (Inbound Injection Detected)\n")
            }
        }
    }
}

fn check_content_length(val: Option<&HeaderValue>, max_bytes: usize) -> Option<bool> {
    val.and_then(|v| v.to_str().ok())?
        .parse::<usize>()
        .ok()
        .map(|cl| cl <= max_bytes)
}

fn is_scannable_content_type(val: Option<&HeaderValue>) -> bool {
    let s = match val.and_then(|v| v.to_str().ok()) {
        Some(s) => s.split(';').next().unwrap_or("").trim().to_lowercase(),
        None => return false,
    };
    s.starts_with("text/")
        || s == "application/json"
        || s == "application/xml"
        || s == "application/xhtml+xml"
}

async fn collect_body_with_cap(body: Body, max_bytes: usize) -> Result<Bytes, &'static str> {
    let c = body
        .collect()
        .await
        .map_err(|_| "body_read_error")?
        .to_bytes();
    if c.len() > max_bytes {
        Err("size_cap_exceeded")
    } else {
        Ok(c)
    }
}

fn block_response(msg: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::from(msg.to_string()))
        .unwrap()
}
