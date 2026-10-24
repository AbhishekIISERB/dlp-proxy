use dlp_proxy::{
    config::RuleEntry,
    detect::{Rule, Scanner},
    handler::DlpHandler,
    policy::Policy,
};
use hudsucker::hyper::Uri;
use hudsucker::{
    Proxy,
    certificate_authority::{CertificateAuthority, RcgenAuthority},
    rcgen::{Issuer, KeyPair},
    rustls::crypto::aws_lc_rs,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

static LEAK_COUNT: AtomicUsize = AtomicUsize::new(0);

fn contains_planted_secrets(body: &[u8]) -> bool {
    let patterns: [&[u8]; 3] = [
        b"AKIAIOSFODNN7EXAMPLE",
        b"auditor.security@corp-example.com",
        b"4111-1111-1111-1111",
    ];
    for p in patterns {
        if body.windows(p.len()).any(|w| w == p) {
            return true;
        }
    }
    false
}

async fn handle_keepalive_conn(mut socket: TcpStream) {
    let mut buf = vec![0u8; 65536];
    let mut pending = Vec::with_capacity(128 * 1024);

    loop {
        let mut header_end = None;
        if let Some(pos) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = Some(pos + 4);
        } else {
            while header_end.is_none() {
                match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
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

        while pending.len() < h_end + cl {
            match socket.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => pending.extend_from_slice(&buf[..n]),
            }
        }

        let body_bytes = &pending[h_end..h_end + cl];
        if contains_planted_secrets(body_bytes) {
            LEAK_COUNT.fetch_add(1, Ordering::Relaxed);
        }

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
        [
            RuleEntry {
                id: "aws-access-key".into(),
                pattern: r"AKIA[0-9A-Z]{16}".into(),
                check: None,
                action: "redact".into(),
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
            RuleEntry {
                id: "high-entropy-token".into(),
                pattern: r"[A-Za-z0-9_\-]{32,}".into(),
                check: Some("entropy".into()),
                action: "log".into(),
            },
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
    mean_ms: f64,
    p50_ms: f64,
    p99_ms: f64,
    ok: usize,
    non_2xx: usize,
    conn_err: usize,
}

async fn run_duration_trial(
    client: reqwest::Client,
    target_url: String,
    payload: Arc<Vec<u8>>,
    concurrency: usize,
    duration: Duration,
) -> TrialResult {
    let start_all = Instant::now();
    let deadline = start_all + duration;

    let mut handles = Vec::new();
    for _ in 0..concurrency {
        let client = client.clone();
        let target_url = target_url.clone();
        let payload = payload.clone();
        let handle = tokio::spawn(async move {
            let mut latencies = Vec::with_capacity(2000);
            let mut ok = 0usize;
            let mut non_2xx = 0usize;
            let mut conn_err = 0usize;

            while Instant::now() < deadline {
                let req_start = Instant::now();
                match client
                    .post(&target_url)
                    .body(payload.as_slice().to_vec())
                    .send()
                    .await
                {
                    Ok(res) => {
                        if res.status().is_success() {
                            latencies.push(req_start.elapsed().as_secs_f64() * 1000.0);
                            ok += 1;
                        } else {
                            non_2xx += 1;
                        }
                    }
                    Err(_) => {
                        conn_err += 1;
                    }
                }
            }
            (latencies, ok, non_2xx, conn_err)
        });
        handles.push(handle);
    }

    let mut all_latencies = Vec::new();
    let mut total_ok = 0;
    let mut total_non_2xx = 0;
    let mut total_conn_err = 0;

    for h in handles {
        if let Ok((mut lats, ok, non_2xx, conn_err)) = h.await {
            all_latencies.append(&mut lats);
            total_ok += ok;
            total_non_2xx += non_2xx;
            total_conn_err += conn_err;
        }
    }
    let total_duration = start_all.elapsed().as_secs_f64();
    all_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let rps = total_ok as f64 / total_duration.max(0.0001);
    let mean_ms = if !all_latencies.is_empty() {
        all_latencies.iter().sum::<f64>() / all_latencies.len() as f64
    } else {
        0.0
    };
    let p50_ms = if !all_latencies.is_empty() {
        all_latencies[(all_latencies.len() as f64 * 0.50) as usize]
    } else {
        0.0
    };
    let p99_ms = if !all_latencies.is_empty() {
        all_latencies[((all_latencies.len() as f64 * 0.99) as usize).min(all_latencies.len() - 1)]
    } else {
        0.0
    };

    TrialResult {
        rps,
        mean_ms,
        p50_ms,
        p99_ms,
        ok: total_ok,
        non_2xx: total_non_2xx,
        conn_err: total_conn_err,
    }
}

async fn warmup(client: &reqwest::Client, target_url: &str, payload: Arc<Vec<u8>>, count: usize) {
    for _ in 0..count {
        let _ = client
            .post(target_url)
            .body(payload.as_slice().to_vec())
            .send()
            .await;
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

    let t0 = Instant::now();
    let _ = ca.gen_server_config(&auth).await;
    let cold_ms = t0.elapsed().as_secs_f64() * 1000.0;

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

fn generate_clean_payload(size: usize) -> Arc<Vec<u8>> {
    let filler = r#"{"item": "catalog_product_id_882194", "status": "active"}"#;
    let mut out = String::from(r#"{"records": ["#);
    while out.len() + 2 < size {
        if out.len() > 14 {
            out.push_str(", ");
        }
        out.push_str(filler);
    }
    out.push_str("]}");
    Arc::new(out.into_bytes())
}

fn generate_payload_with_secrets(size: usize) -> Arc<Vec<u8>> {
    let key = "AKIAIOSFODNN7EXAMPLE";
    let email = "auditor.security@corp-example.com";
    let card = "4111-1111-1111-1111"; // valid Luhn

    let head = format!(r#"{{"auth": "{key}", "records": ["#);
    let mid_secret = format!(r#", {{"user_email": "{email}"}}, "#);
    let tail_secret = format!(r#", {{"billing": "{card}"}}]}}"#);

    let filler = r#"{"item": "catalog_product_id_882194", "status": "active"}"#;
    let mut out = head;
    let target_mid = size / 2;
    let mut added_mid = false;

    while out.len() + tail_secret.len() < size {
        if !added_mid && out.len() >= target_mid {
            out.push_str(&mid_secret);
            added_mid = true;
        } else {
            if out.len() > 30 && !out.ends_with('[') && !out.ends_with(", ") {
                out.push_str(", ");
            }
            out.push_str(filler);
        }
    }
    if !added_mid {
        out.push_str(&mid_secret);
    }
    out.push_str(&tail_secret);
    Arc::new(out.into_bytes())
}

#[derive(Clone, Copy)]
enum SetupKind {
    Direct,
    NoInspect,
    InspectClean,
    InspectRedact,
}

#[tokio::main]
async fn main() {
    println!("===========================================================");
    println!("DLP PROXY BENCHMARK (DURATION-BASED 3s TRIALS + LEAK CHECK)");
    println!("===========================================================\n");

    // 1. Certificate Resolution Measurement
    println!("--- 1. Certificate Resolution (Hudsucker RcgenAuthority + Moka Cache) ---");
    let (cold_ms, warm_ms) = measure_cert_resolution().await;
    println!(
        "Cold Resolution (Keygen + X.509 Minting): {:.2} ms",
        cold_ms
    );
    println!(
        "Warm Resolution (Moka Cache Hit, 1000 capacity, 300s TTL): {:.4} ms ({:.1} µs)",
        warm_ms,
        warm_ms * 1000.0
    );
    println!("Cache Speedup: {:.0}x\n", cold_ms / warm_ms.max(0.0001));

    // 2. Throughput & Latency Benchmarks
    let server_port = start_server().await;
    let proxy_no_inspect_port = start_proxy(false).await;
    let proxy_inspect_port = start_proxy(true).await;

    let target_url = format!("http://127.0.0.1:{server_port}/api");

    let payloads = vec![
        ("1 KB", 1024),
        ("100 KB", 100 * 1024),
        ("1 MB", 1024 * 1024),
    ];
    let concurrencies = vec![1, 16, 64];
    let trial_duration = Duration::from_secs(3);

    println!("--- 2. Forward HTTP Proxy Benchmark (7 Trials of 3s, 1st Discarded) ---");
    println!(
        "| Payload | Concurrency | Setup | Requests/sec (Med [Min–Max]) | Mean (ms) | p50 (ms) | p99 (ms) | OK | Non-2xx | Conn Err | Leaked |"
    );
    println!("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |");

    for (p_name, size) in &payloads {
        let clean_payload = generate_clean_payload(*size);
        let secrets_payload = generate_payload_with_secrets(*size);

        for c in &concurrencies {
            let row_setups = [
                ("Direct", SetupKind::Direct),
                ("Proxy (No Inspect)", SetupKind::NoInspect),
                ("Proxy (Inspect On - Clean)", SetupKind::InspectClean),
                ("Proxy (Inspect On - Redact)", SetupKind::InspectRedact),
            ];

            for (setup_name, kind) in row_setups {
                let client_builder = reqwest::Client::builder()
                    .pool_max_idle_per_host(*c + 10)
                    .tcp_nodelay(true);

                let client = match kind {
                    SetupKind::Direct => client_builder.build().unwrap(),
                    SetupKind::NoInspect => client_builder
                        .proxy(
                            reqwest::Proxy::all(format!(
                                "http://127.0.0.1:{proxy_no_inspect_port}"
                            ))
                            .unwrap(),
                        )
                        .build()
                        .unwrap(),
                    SetupKind::InspectClean | SetupKind::InspectRedact => client_builder
                        .proxy(
                            reqwest::Proxy::all(format!("http://127.0.0.1:{proxy_inspect_port}"))
                                .unwrap(),
                        )
                        .build()
                        .unwrap(),
                };

                let active_payload = match kind {
                    SetupKind::InspectRedact => secrets_payload.clone(),
                    _ => clean_payload.clone(),
                };

                // Warmup
                warmup(&client, &target_url, active_payload.clone(), 30).await;

                // Reset leak counter before timed trials
                LEAK_COUNT.store(0, Ordering::Relaxed);

                // Run 7 timed trials of 3s, discard the first
                let mut trials = Vec::new();
                for trial_idx in 0..7 {
                    let res = run_duration_trial(
                        client.clone(),
                        target_url.clone(),
                        active_payload.clone(),
                        *c,
                        trial_duration,
                    )
                    .await;
                    if trial_idx > 0 {
                        trials.push(res);
                    }
                }

                // Sort by rps to pick median
                trials.sort_by(|a, b| a.rps.partial_cmp(&b.rps).unwrap());
                let min = trials[0];
                let med = trials[trials.len() / 2];
                let max = trials[trials.len() - 1];

                let total_ok: usize = trials.iter().map(|t| t.ok).sum();
                let total_non_2xx: usize = trials.iter().map(|t| t.non_2xx).sum();
                let total_conn_err: usize = trials.iter().map(|t| t.conn_err).sum();
                let leaks = LEAK_COUNT.load(Ordering::Relaxed);

                let leaked_col = match kind {
                    SetupKind::InspectRedact => leaks.to_string(),
                    _ => "-".to_string(),
                };

                let variance_flag = if min.rps > 0.0 && (max.rps / min.rps) > 1.5 {
                    " [!]"
                } else {
                    ""
                };

                println!(
                    "| {p_name} | {c} | {setup_name} | {med_rps:.1} [{min_rps:.1}–{max_rps:.1}]{variance_flag} | {mean:.2} | {p50:.2} | {p99:.2} | {total_ok} | {total_non_2xx} | {total_conn_err} | {leaked_col} |",
                    med_rps = med.rps,
                    min_rps = min.rps,
                    max_rps = max.rps,
                    mean = med.mean_ms,
                    p50 = med.p50_ms,
                    p99 = med.p99_ms,
                    variance_flag = variance_flag,
                    total_ok = total_ok,
                    total_non_2xx = total_non_2xx,
                    total_conn_err = total_conn_err,
                    leaked_col = leaked_col,
                );
            }
        }
    }
}
