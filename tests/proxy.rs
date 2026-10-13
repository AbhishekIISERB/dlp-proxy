use dlp_proxy::{
    config::{DomainEntry, RuleEntry},
    detect::Rule,
    handler::DlpHandler,
    policy::Policy,
};
use hudsucker::{
    Proxy,
    certificate_authority::RcgenAuthority,
    rcgen::{Issuer, KeyPair},
    rustls::crypto::aws_lc_rs,
};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

async fn start_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let mut n = 0;
                let mut header_end = None;
                while n < buf.len() {
                    match socket.read(&mut buf[n..]).await {
                        Ok(0) | Err(_) => break,
                        Ok(b) => {
                            n += b;
                            if let Some(pos) = buf[..n].windows(4).position(|w| w == b"\r\n\r\n") {
                                header_end = Some(pos + 4);
                                break;
                            }
                        }
                    }
                }
                if let Some(h_end) = header_end {
                    let headers_str = String::from_utf8_lossy(&buf[..h_end]);
                    let content_len: usize = headers_str
                        .lines()
                        .find_map(|line| {
                            let lower = line.to_lowercase();
                            if lower.starts_with("content-length:") {
                                line.split(':').nth(1)?.trim().parse().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    let mut body = buf[h_end..n].to_vec();
                    while body.len() < content_len {
                        let mut chunk = vec![0u8; content_len - body.len()];
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(b) => body.extend_from_slice(&chunk[..b]),
                        }
                    }
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                    let _ = socket.write_all(&body).await;
                }
            });
        }
    });
    (port, handle)
}

fn test_rules() -> Vec<Rule> {
    vec![
        RuleEntry {
            id: "aws-access-key".into(),
            pattern: r"AKIA[0-9A-Z]{16}".into(),
            check: None,
            action: "block".into(),
        },
        RuleEntry {
            id: "email".into(),
            pattern: r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}".into(),
            check: None,
            action: "redact".into(),
        },
        RuleEntry {
            id: "card".into(),
            pattern: r"\b(?:\d[ -]?){13,19}\b".into(),
            check: Some("luhn".into()),
            action: "redact".into(),
        },
    ]
    .iter()
    .map(|e| Rule::from_config(e).unwrap())
    .collect()
}

#[tokio::test]
async fn test_proxy_end_to_end() {
    let (echo_port, _echo_handle) = start_echo_server().await;

    let key_pem = std::fs::read_to_string("ca.key").expect("Read ca.key");
    let cert_pem = std::fs::read_to_string("ca.pem").expect("Read ca.pem");
    let key_pair = KeyPair::from_pem(&key_pem).unwrap();
    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair).unwrap();
    let ca = RcgenAuthority::new(issuer, 100, aws_lc_rs::default_provider());

    let domain_entries = vec![
        DomainEntry { host: "ads.example.com".into(), action: "block".into() },
        DomainEntry { host: "safe.internal".into(), action: "allow".into() },
    ];
    let policy = Policy::new("inspect", &domain_entries);

    let handler = DlpHandler {
        policy: Arc::new(policy),
        rules: Arc::new(test_rules()),
        max_body_bytes: 1024 * 1024,
        fail_closed: true,
    };

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();

    let proxy = Proxy::builder()
        .with_listener(proxy_listener)
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(handler)
        .build()
        .unwrap();

    tokio::spawn(async move {
        let _ = proxy.start().await;
    });

    // Allow proxy server to bind and start accepting
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{proxy_port}")).unwrap())
        .build()
        .unwrap();

    // 1. Redaction test: sensitive card number in body is redacted before reaching echo server
    let res = client
        .post(format!("http://127.0.0.1:{echo_port}/submit"))
        .body("Customer payment with card 4111 1111 1111 1111, please")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body = res.text().await.unwrap();
    assert_eq!(body, "Customer payment with card [REDACTED], please");

    // 2. Block test: AWS key in request body returns 403 Forbidden
    let res = client
        .post(format!("http://127.0.0.1:{echo_port}/upload"))
        .body("Here is my key AKIA1234567890ABCDEF")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);

    // 3. Domain policy test: blocked domain returns 403 Forbidden
    let res = client
        .get("http://ads.example.com/track")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
}
