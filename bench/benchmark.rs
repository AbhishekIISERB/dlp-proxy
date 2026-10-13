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
    net::TcpListener,
};

async fn start_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
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
                    let headers = String::from_utf8_lossy(&buf[..h_end]);
                    let cl: usize = headers
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
                    let mut body = buf[h_end..n].to_vec();
                    while body.len() < cl {
                        let mut chunk = vec![0u8; (cl - body.len()).min(65536)];
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(b) => body.extend_from_slice(&chunk[..b]),
                        }
                    }
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\nOK",
                        2
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                }
            });
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
        max_body_bytes: 2 * 1024 * 1024,
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

#[derive(Clone, Copy)]
struct RunResult {
    rps: f64,
    p50_ms: f64,
    p99_ms: f64,
}

async fn run_benchmark(
    client: reqwest::Client,
    target_url: String,
    payload: Arc<Vec<u8>>,
    concurrency: usize,
    total_requests: usize,
) -> RunResult {
    let requests_per_worker = (total_requests / concurrency).max(1);
    let start_all = Instant::now();

    let mut handles = Vec::new();
    for _ in 0..concurrency {
        let client = client.clone();
        let target_url = target_url.clone();
        let payload = payload.clone();
        let handle = tokio::spawn(async move {
            let mut latencies = Vec::with_capacity(requests_per_worker);
            for _ in 0..requests_per_worker {
                let req_start = Instant::now();
                if let Ok(res) = client
                    .post(&target_url)
                    .body(payload.as_slice().to_vec())
                    .send()
                    .await
                {
                    if res.status().is_success() {
                        latencies.push(req_start.elapsed().as_secs_f64() * 1000.0);
                    }
                }
            }
            latencies
        });
        handles.push(handle);
    }

    let mut all_latencies = Vec::new();
    for h in handles {
        if let Ok(mut lats) = h.await {
            all_latencies.append(&mut lats);
        }
    }
    let total_duration = start_all.elapsed().as_secs_f64();
    all_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let total_done = all_latencies.len();
    let rps = total_done as f64 / total_duration.max(0.0001);
    let p50_ms = if total_done > 0 { all_latencies[(total_done as f64 * 0.50) as usize] } else { 0.0 };
    let p99_ms = if total_done > 0 { all_latencies[((total_done as f64 * 0.99) as usize).min(total_done - 1)] } else { 0.0 };

    RunResult { rps, p50_ms, p99_ms }
}

async fn warmup(client: &reqwest::Client, target_url: &str, count: usize) {
    let dummy = vec![b'W'; 256];
    for _ in 0..count {
        let _ = client.post(target_url).body(dummy.clone()).send().await;
    }
}

async fn measure_cert_cache() -> (f64, f64) {
    let key_pem = std::fs::read_to_string("ca.key").expect("Read ca.key");
    let cert_pem = std::fs::read_to_string("ca.pem").expect("Read ca.pem");
    let key_pair = KeyPair::from_pem(&key_pem).unwrap();
    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair).unwrap();
    let ca = RcgenAuthority::new(issuer, 1000, aws_lc_rs::default_provider());

    let authority: Uri = "https://example.com:443".parse().unwrap();
    let auth = authority.authority().unwrap().clone();

    // Cold request: generates new RSA/ECDSA key, mints X.509 cert, inserts into Moka cache
    let t0 = Instant::now();
    let _ = ca.gen_server_config(&auth).await;
    let cold_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // Warm requests: Moka in-memory cache hit
    let mut warm_samples = Vec::new();
    for _ in 0..10 {
        let t1 = Instant::now();
        let _ = ca.gen_server_config(&auth).await;
        warm_samples.push(t1.elapsed().as_secs_f64() * 1000.0);
    }
    warm_samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let warm_median_ms = warm_samples[warm_samples.len() / 2];

    (cold_ms, warm_median_ms)
}

#[tokio::main]
async fn main() {
    println!("===========================================================");
    println!("DLP PROXY BENCHMARK SUITE (OPTIMIZED SCANNER + WARMUP)");
    println!("===========================================================\n");

    // 1. Certificate Authority Cache Benchmark (Cold vs Warm)
    println!("--- 1. Certificate Authority Moka Cache Benchmark ---");
    let (cold_ms, warm_ms) = measure_cert_cache().await;
    println!("Cold Request (Dynamic Keygen + X.509 Minting): {:.2} ms", cold_ms);
    println!("Warm Request (Moka Cache Hit, hudsucker v0.25.0): {:.4} ms", warm_ms);
    println!("Cache Speedup: {:.1}x\n", cold_ms / warm_ms.max(0.0001));

    // 2. HTTP Proxy & Scanning Benchmark
    let server_port = start_server().await;
    let proxy_no_inspect_port = start_proxy(false).await;
    let proxy_inspect_port = start_proxy(true).await;

    let target_url = format!("http://127.0.0.1:{server_port}/api");

    let direct_client = reqwest::Client::builder().build().unwrap();
    let no_inspect_client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{proxy_no_inspect_port}")).unwrap())
        .build()
        .unwrap();
    let inspect_client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{proxy_inspect_port}")).unwrap())
        .build()
        .unwrap();

    // Warmup phase for all endpoints
    println!("Warming up connection pools...");
    warmup(&direct_client, &target_url, 100).await;
    warmup(&no_inspect_client, &target_url, 100).await;
    warmup(&inspect_client, &target_url, 100).await;
    println!("Warmup complete.\n");

    let payloads = vec![
        ("1 KB", 1024),
        ("100 KB", 100 * 1024),
        ("1 MB", 1024 * 1024),
    ];
    let concurrencies = vec![1, 16, 64];

    println!("--- 2. Forwarding & Inspection Throughput Matrix ---");
    println!("| Payload | Concurrency | Setup | Requests/sec (Med [Min–Max]) | p50 (ms) | p99 (ms) |");
    println!("| :--- | :--- | :--- | :--- | :--- | :--- |");

    for (p_name, size) in &payloads {
        let payload = Arc::new(vec![b'X'; *size]);
        for c in &concurrencies {
            let total_reqs = match *size {
                1024 => (*c * 50).max(100),
                102400 => (*c * 20).max(40),
                _ => (*c * 10).max(20),
            };

            let setups = [
                ("Direct", direct_client.clone()),
                ("Proxy (No Inspect)", no_inspect_client.clone()),
                ("Proxy (Inspect On)", inspect_client.clone()),
            ];

            for (setup_name, client) in setups {
                let mut runs = Vec::new();
                for _ in 0..3 {
                    let r = run_benchmark(client.clone(), target_url.clone(), payload.clone(), *c, total_reqs).await;
                    runs.push(r);
                }
                runs.sort_by(|a, b| a.rps.partial_cmp(&b.rps).unwrap());
                let min_rps = runs[0].rps;
                let med = runs[1];
                let max_rps = runs[2].rps;

                println!(
                    "| {p_name} | {c} | {setup_name} | {med_rps:.1} [{min_rps:.1}–{max_rps:.1}] | {p50:.2} | {p99:.2} |",
                    med_rps = med.rps,
                    min_rps = min_rps,
                    max_rps = max_rps,
                    p50 = med.p50_ms,
                    p99 = med.p99_ms
                );
            }
        }
    }
}
