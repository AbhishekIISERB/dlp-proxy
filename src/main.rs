use dlp_proxy::{
    config::load_config,
    detect::{Rule, Scanner},
    handler::DlpHandler,
    policy::Policy,
};
use hudsucker::{
    Proxy,
    certificate_authority::RcgenAuthority,
    rcgen::{Issuer, KeyPair},
    rustls::crypto::aws_lc_rs,
};
use std::{net::SocketAddr, sync::Arc};
use tracing::error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "rules.toml".into());
    let cfg = load_config(&config_path)?;
    let rules: Vec<Rule> = cfg
        .rule
        .iter()
        .filter_map(|r| Rule::from_config(r).ok())
        .collect();
    let scanner = Scanner::new(rules)?;
    let policy = Policy::new(&cfg.policy.default, &cfg.domain);

    let key_pem = std::fs::read_to_string("ca.key").expect("Failed to read ca.key");
    let cert_pem = std::fs::read_to_string("ca.pem").expect("Failed to read ca.pem");
    let key_pair = KeyPair::from_pem(&key_pem)?;
    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair)?;
    let ca = RcgenAuthority::new(issuer, 1_000, aws_lc_rs::default_provider());

    let handler = DlpHandler {
        policy: Arc::new(policy),
        scanner: Arc::new(scanner),
        max_body_bytes: cfg.policy.max_body_bytes,
        fail_closed: cfg.policy.on_error == "block",
    };

    let proxy = Proxy::builder()
        .with_addr(SocketAddr::from(([127, 0, 0, 1], 3000)))
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(handler)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
        })
        .build()?;

    println!("DLP proxy listening on http://127.0.0.1:3000");
    if let Err(e) = proxy.start().await {
        error!("Proxy error: {e}");
    }
    Ok(())
}
