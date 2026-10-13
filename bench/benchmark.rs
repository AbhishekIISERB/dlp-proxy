use dlp_proxy::{
    config::RuleEntry,
    detect::{Rule, Scanner},
    handler::DlpHandler,
    policy::Policy,
};
use hudsucker::{
    Proxy,
    certificate_authority::{CertificateAuthority, RcgenAuthority},
    rcgen::{Issuer, KeyPair},
    rustls::crypto::aws_lc_rs,
};
use hudsucker::hyper::Uri;
use std::{sync::Arc, time::{Duration, Instant}};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

async fn handle_keepalive_conn(mut socket: TcpStream) {
    let mut buf = vec![0u8; 65536];
    let mut pending = Vec::new();

    loop {
        let mut header_end = None;
        // Search pending buffer first
        if let Some(pos) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = Some(pos + 4);
        } else {
            // Read until header ends
            while header_end.is_none() {
                match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => return, // EOF or close
                    Ok(n) => {
                        pending.extend_from_slice(&buf[..n]);
                        if let Some(pos) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_end = Some(pos + 4);
                        }
                    }
                }
            }
        }

        let h_end = header_end.unwrap();
        let headers_str = String::from_utf8_lossy(&pending[..h_end]);
        let cl: usize = headers_str
            .lines()
            .find_map(|l| {
                let s = l.to_lowercase();
                if s.starts_with("content-length:") {
                    l.split(':').nth(1)?.trim().parse().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);

        // Read remaining body bytes
        while pending.len() < h_end + cl {
            match socket.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => pending.extend_from_slice(&buf[..n]),
            }
        }

        // Drain the processed request from pending
        pending.drain(..h_end + cl);

        let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK";
        if socket.write_all(resp.as_bytes()).await.is_err() {
            return;
        }
    }
}

async fn start_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(handle_keepalive_conn(socket));
        }
    });
    port
}

async fn start_proxy(inspect: bool) -> u16 {
    let key_pem = std::fs::read_to_string("ca.key").expect("Read ca.key");
    let cert_pem = std::fs::read_to_string("ca.pem").expect("Read ca.pem");
    let key_pair = KeyPair::from_pem(&key_pem).unwrap();
    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair).unwrap();
    let ca = RcgenAuthority::new(issuer, 1000, aws_lc_rs::default_provider());

    let policy_default = if inspect { "inspect" } else { "allow" };
    let policy = Policy::new(policy_default, &[]);

    let rules = if inspect {
        vec![
            RuleEntry { id: "aws-access-key".into(), pattern: r"AKIA[0-9A-Z]{16}".into(), check: None, action: "block".into() },
            RuleEntry { id: "email".into(), pattern: r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}".into(), check: None, action: "redact".into() },
            RuleEntry { id: "card".into(), pattern: r"\b(?:\d[ -]?){13,19}\b".into(), check: Some("luhn".into()), action: "redact".into() },
            RuleEntry { id: "high-entropy-token".into(), pattern: r"[A-Za-z0-9_\-]{32,}".into(), check: Some("entropy".into()), action: "log".into() },
        ]
        .iter()
        .map(|e| Rule::from_config(e).unwrap())
        .collect()
    } else {
        vec![]
    };

    let scanner = Scanner::new(rules).unwrap();
    let handler = DlpHandler {
        policy: Arc::new(policy),
        scanner: Arc::new(scanner),
        max_body_bytes: 4 * 1024 * 1024,
        fail_closed: true,
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(handler)
        .build()
        .unwrap();

    tokio::spawn(async move {
        let _ = proxy.start().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    port
}

#[derive(Clone, Copy, Debug)]
struct TrialResult {
    rps: f64,
    p50_ms: f64,
    p99_ms: f64,
    errors: usize,
}

async fn run_trial(
    client: reqwest::Client,
    target_url: String,
    payload: Arc<Vec<u8>>,
    concurrency: usize,
    total_requests: usize,
) -> TrialResult {
    let requests_per_worker = (total_requests / concurrency).max(1);
    let start_all = Instant::now();

    let mut handles = Vec::new();
    for _ in 0..concurrency {
        let client = client.clone();
        let target_url = target_url.clone();
        let payload = payload.clone();
        let handle = tokio::spawn(async move {
            let mut latencies = Vec::with_capacity(requests_per_worker);
            let mut err_count = 0;
            for _ in 0..requests_per_worker {
                let req_start = Instant::now();
                match client
                    .post(&target_url)
                    .body(payload.as_slice().to_vec())
                    .send()
                    .await
                {
                    Ok(res) if res.status().is_success() => {
                        latencies.push(req_start.elapsed().as_secs_f64() * 1000.0);
                    }
                    _ => {
                        err_count += 1;
                    }
                }
            }
            (latencies, err_count)
        });
        handles.push(handle);
    }

    let mut all_latencies = Vec::new();
    let mut total_errors = 0;
    for h in handles {
        if let Ok((mut lats, errs)) = h.await {
            all_latencies.append(&mut lats);
            total_errors += errs;
        }
    }
    let total_duration = start_all.elapsed().as_secs_f64();
    all_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let total_done = all_latencies.len();
    let rps = total_done as f64 / total_duration.max(0.0001);
    let p50_ms = if total_done > 0 { all_latencies[(total_done as f64 * 0.50) as usize] } else { 0.0 };
    let p99_ms = if total_done > 0 { all_latencies[((total_done as f64 * 0.99) as usize).min(total_done - 1)] } else { 0.0 };

    TrialResult { rps, p50_ms, p99_ms, errors: total_errors }
}

async fn warmup(client: &reqwest::Client, target_url: &str, count: usize) {
    let dummy = b"{\"ping\":\"warmup\"}".to_vec();
    for _ in 0..count {
        let _ = client.post(target_url).body(dummy.clone()).send().await;
    }
}

async fn measure_cert_resolution() -> (f64, f64) {
    let key_pem = std::fs::read_to_string("ca.key").expect("Read ca.key");
    let cert_pem = std::fs::read_to_string("ca.pem").expect("Read ca.pem");
    let key_pair = KeyPair::from_pem(&key_pem).unwrap();
    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair).unwrap();
    let ca = RcgenAuthority::new(issuer, 1000, aws_lc_rs::default_provider());

    let authority: Uri = "https://bench-target.local:443".parse().unwrap();
    let auth = authority.authority().unwrap().clone();

    // Cold: mints X.509 cert + inserts into Moka cache
    let t0 = Instant::now();
    let _ = ca.gen_server_config(&auth).await;
    let cold_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // Warm: Moka cache lookup (capacity 1000, TTL 300s)
    let mut warm_samples = Vec::new();
    for _ in 0..20 {
        let t1 = Instant::now();
        let _ = ca.gen_server_config(&auth).await;
        warm_samples.push(t1.elapsed().as_secs_f64() * 1000.0);
    }
    warm_samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let warm_median_ms = warm_samples[warm_samples.len() / 2];

    (cold_ms, warm_median_ms)
}

fn generate_realistic_json_payload(size: usize, include_secrets: bool) -> Arc<Vec<u8>> {
    let base = if include_secrets {
        r#"{"event": "purchase", "card": "4111-1111-1111-1111", "email": "customer@example.com", "msg": "order complete"}"#
    } else {
        r#"{"event": "heartbeat", "status": "nominal", "node": "worker-42", "msg": "all system checks passed successfully"}"#
    };
    let mut out = String::from("{\"items\": [");
    while out.len() < size {
        if out.len() > 12 { out.push_str(", "); }
        out.push_str(base);
    }
    out.push_str("]}");
    Arc::new(out.into_bytes())
}

#[tokio::main]
async fn main() {
    println!("===========================================================");
    println!("DLP PROXY BENCHMARK (HTTP FORWARD PROXY + KEEP-ALIVE)");
    println!("===========================================================\n");

    // 1. Certificate Resolution Measurement
    println!("--- 1. Certificate Resolution (Hudsucker RcgenAuthority + Moka Cache) ---");
    let (cold_ms, warm_ms) = measure_cert_resolution().await;
    println!("Cold Resolution (Keygen + X.509 Minting): {:.2} ms", cold_ms);
    println!("Warm Resolution (Moka Cache Hit, 1000 capacity, 300s TTL): {:.4} ms ({:.1} µs)", warm_ms, warm_ms * 1000.0);
    println!("Cache Speedup: {:.0}x\n", cold_ms / warm_ms.max(0.0001));

    // 2. Throughput & Latency Benchmarks
    let server_port = start_server().await;
    let proxy_no_inspect_port = start_proxy(false).await;
    let proxy_inspect_port = start_proxy(true).await;

    let target_url = format!("http://127.0.0.1:{server_port}/api");

    let direct_client = reqwest::Client::builder().tcp_nodelay(true).build().unwrap();
    let no_inspect_client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{proxy_no_inspect_port}")).unwrap())
        .tcp_nodelay(true)
        .build()
        .unwrap();
    let inspect_client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{proxy_inspect_port}")).unwrap())
        .tcp_nodelay(true)
        .build()
        .unwrap();

    println!("Warming up connections...");
    warmup(&direct_client, &target_url, 200).await;
    warmup(&no_inspect_client, &target_url, 200).await;
    warmup(&inspect_client, &target_url, 200).await;
    println!("Warmup complete.\n");

    let payloads = vec![
        ("1 KB", 1024),
        ("100 KB", 100 * 1024),
        ("1 MB", 1024 * 1024),
    ];
    let concurrencies = vec![1, 16, 64];

    println!("--- 2. Forward HTTP Proxy Benchmark (7 Trials, 1st Discarded) ---");
    println!("| Payload | Concurrency | Setup | Requests/sec (Med [Min–Max]) | p50 (ms) | p99 (ms) | Errors |");
    println!("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |");

    for (p_name, size) in &payloads {
        let payload = generate_realistic_json_payload(*size, false);
        for c in &concurrencies {
            let total_reqs = match *size {
                1024 => (*c * 100).max(200),
                102400 => (*c * 30).max(60),
                _ => (*c * 10).max(20),
            };

            let setups = [
                ("Direct", direct_client.clone()),
                ("Proxy (No Inspect)", no_inspect_client.clone()),
                ("Proxy (Inspect On)", inspect_client.clone()),
            ];

            for (setup_name, client) in setups {
                let mut trials = Vec::new();
                // Run 7 trials, discard trial 0
                for trial_idx in 0..7 {
                    let res = run_trial(client.clone(), target_url.clone(), payload.clone(), *c, total_reqs).await;
                    if trial_idx > 0 {
                        trials.push(res);
                    }
                }

                trials.sort_by(|a, b| a.rps.partial_cmp(&b.rps).unwrap());
                let min = trials[0];
                let med = trials[trials.len() / 2];
                let max = trials[trials.len() - 1];
                let total_errs: usize = trials.iter().map(|t| t.errors).sum();

                let variance_flag = if min.rps > 0.0 && (max.rps / min.rps) > 1.5 { " [!]" } else { "" };

                println!(
                    "| {p_name} | {c} | {setup_name} | {med_rps:.1} [{min_rps:.1}–{max_rps:.1}]{variance_flag} | {p50:.2} | {p99:.2} | {total_errs} |",
                    med_rps = med.rps,
                    min_rps = min.rps,
                    max_rps = max.rps,
                    p50 = med.p50_ms,
                    p99 = med.p99_ms,
                    variance_flag = variance_flag,
                    total_errs = total_errs,
                );
            }
        }
    }
}
