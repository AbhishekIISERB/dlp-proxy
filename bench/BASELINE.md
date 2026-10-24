# Baseline Performance & Evaluation Measurements

Recorded on: Apple M1 (8 cores: 4 performance + 4 efficiency, arm64), macOS, rustc 1.94.1

---

## 1. Unit & Integration Test Baseline (`cargo test`)

```text
running 5 tests
test test_entropy_calculation ... ok
test test_policy_lookup ... ok
test test_luhn_algorithm ... ok
test test_redaction_and_overlaps ... ok
test test_detector_table_driven ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s

running 1 test
test test_proxy_end_to_end ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.14s
```

All 6 tests passing, zero failures.

---

## 2. Detection Quality Baseline (`cargo run --example evaluate`)

Evaluated against the 500-sample labelled adversarial corpus (evaluation seed `99999`):

```text
Total samples in labelled dataset: 500
| Rule ID | Expected Pos | TP | FP (Adversarial) | FN | Precision | Recall |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `aws-access-key` | 50 | 50 | 0 | 0 | **100.0%** | **100.0%** |
| `email` | 100 | 100 | 0 | 0 | **100.0%** | **100.0%** |
| `card` | 100 | 100 | 3 | 0 | **97.1%** | **100.0%** |
| `high-entropy-token` | 50 | 50 | 50 | 0 | **50.0%** | **100.0%** |
```

- **AWS Keys (`AKIA...`):** 100.0% Precision, 100.0% Recall.
- **Emails:** 100.0% Precision, 100.0% Recall.
- **Credit Cards (BIN prefix 3-6 + Luhn):** 97.1% Precision (3 collisions out of 50 random 16-digit order IDs), 100.0% Recall.
- **High-Entropy Tokens (entropy >= 4.0 excluding hex/UUID):** 50.0% Precision, 100.0% Recall (remaining 50 false positives are non-hex base64 strings and JWT payload segments).

---

## 3. Dynamic Certificate CA Resolution Latency

Measured via Hudsucker `RcgenAuthority` with in-memory Moka cache (1,000 capacity, 300s TTL):
- **Cold Resolution (RSA-2048 CA, Ephemeral Keypair + X.509 Minting):** 2.19 ms – 2.44 ms
- **Warm Resolution (Moka Cache Hit):** 0.0003 ms – 0.0004 ms (0.3 µs – 0.4 µs)
- **Speedup:** ~6,500x – 7,500x

---

## 4. Forward HTTP Proxy Throughput & Latency Matrix (`cargo run --release --example benchmark`)

7 timed trials of 3 seconds per cell, 1st trial discarded as warmup. All requests HTTP 200 OK (0 connection errors, 0 dropped frames).

| Payload | Concurrency | Setup | Requests/sec (Med [Min–Max]) | Mean (ms) | p50 (ms) | p99 (ms) | OK | Non-2xx | Conn Err | Leaked |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1 KB** | 1 | Direct | 36,649.9 [35143.5–37462.4] | 0.03 | 0.03 | 0.05 | 654,035 | 0 | 0 | - |
| 1 KB | 1 | Proxy (No Inspect) | 2,710.6 [1968.7–3701.3] | 0.37 | 0.20 | 2.97 | 48,390 | 0 | 0 | - |
| 1 KB | 1 | Proxy (Inspect On - Clean) | 1,498.4 [1316.9–1750.6] | 0.67 | 0.20 | 7.66 | 26,890 | 0 | 0 | - |
| 1 KB | 1 | Proxy (Inspect On - Redact) | **692.3** [580.6–778.9] | **1.44** | **0.26** | **17.32** | 12,295 | 0 | 0 | **0** |
| **1 KB** | 16 | Direct | 132,730.3 [119462.8–139474.9] | 0.12 | 0.11 | 0.27 | 2,363,560 | 0 | 0 | - |
| 1 KB | 16 | Proxy (No Inspect) | 1,097.2 [959.0–1121.5] | 14.54 | 11.10 | 32.14 | 19,219 | 0 | 0 | - |
| 1 KB | 16 | Proxy (Inspect On - Clean) | 953.6 [842.0–1002.2] | 16.72 | 12.96 | 40.34 | 16,807 | 0 | 0 | - |
| 1 KB | 16 | Proxy (Inspect On - Redact) | **609.2** [542.2–646.7] | **26.16** | **26.00** | **51.81** | 10,810 | 0 | 0 | **0** |
| **1 KB** | 64 | Direct | 112,164.8 [103574.9–117766.7] | 0.57 | 0.54 | 1.26 | 1,987,465 | 0 | 0 | - |
| 1 KB | 64 | Proxy (No Inspect) | 729.8 [598.8–762.5] | 87.29 | 85.10 | 158.32 | 12,568 | 0 | 0 | - |
| 1 KB | 64 | Proxy (Inspect On - Clean) | 646.3 [563.9–672.6] | 98.94 | 96.89 | 161.97 | 11,636 | 0 | 0 | - |
| 1 KB | 64 | Proxy (Inspect On - Redact) | **447.9** [415.1–461.4] | **142.14** | **141.76** | **226.48** | 8,117 | 0 | 0 | **0** |
| **100 KB** | 1 | Direct | 3,249.9 [2384.1–3341.2] | 0.31 | 0.29 | 0.44 | 53,815 | 0 | 0 | - |
| 100 KB | 1 | Proxy (No Inspect) | 577.6 [555.7–611.6] | 1.73 | 0.52 | 18.36 | 10,471 | 0 | 0 | - |
| 100 KB | 1 | Proxy (Inspect On - Clean) | 534.3 [469.5–570.5] | 1.87 | 0.84 | 15.06 | 9,506 | 0 | 0 | - |
| 100 KB | 1 | Proxy (Inspect On - Redact) | **189.9** [160.1–218.2] | **5.26** | **1.97** | **53.86** | 3,454 | 0 | 0 | **0** |
| **100 KB** | 16 | Direct | 6,125.4 [5186.1–6645.8] | 2.59 | 1.67 | 26.05 | 108,493 | 0 | 0 | - |
| 100 KB | 16 | Proxy (No Inspect) | 248.1 [189.8–277.8] | 64.44 | 52.37 | 183.74 | 4,203 | 0 | 0 | - |
| 100 KB | 16 | Proxy (Inspect On - Clean) | 247.7 [164.2–287.7] | 64.56 | 53.90 | 226.94 | 4,320 | 0 | 0 | - |
| 100 KB | 16 | Proxy (Inspect On - Redact) | **175.0** [137.4–207.9] | **90.54** | **81.34** | **314.09** | 3,132 | 0 | 0 | **0** |
| **100 KB** | 64 | Direct | 5,306.0 [4558.3–5950.5] | 11.97 | 9.33 | 52.93 | 95,551 | 0 | 0 | - |
| 100 KB | 64 | Proxy (No Inspect) | 244.3 [183.6–273.4] | 260.71 | 242.83 | 498.43 | 4,277 | 0 | 0 | - |
| 100 KB | 64 | Proxy (Inspect On - Clean) | 326.8 [210.3–410.4] | 194.82 | 186.01 | 374.15 | 5,588 | 0 | 0 | - |
| 100 KB | 64 | Proxy (Inspect On - Redact) | **214.2** [148.3–298.6] | **294.35** | **286.26** | **506.85** | 4,011 | 0 | 0 | **0** |
| **1 MB** | 1 | Direct | 413.1 [381.2–427.3] | 2.42 | 2.36 | 3.53 | 7,345 | 0 | 0 | - |
| 1 MB | 1 | Proxy (No Inspect) | 254.0 [240.0–281.9] | 3.93 | 3.48 | 10.44 | 4,598 | 0 | 0 | - |
| 1 MB | 1 | Proxy (Inspect On - Clean) | 145.4 [133.5–147.1] | 6.88 | 6.42 | 14.87 | 2,564 | 0 | 0 | - |
| 1 MB | 1 | Proxy (Inspect On - Redact) | **105.8** [97.1–107.1] | **9.45** | **9.03** | **16.52** | 1,872 | 0 | 0 | **0** |
| **1 MB** | 16 | Direct | 1,771.7 [1727.4–1833.9] | 9.02 | 8.84 | 16.87 | 32,000 | 0 | 0 | - |
| 1 MB | 16 | Proxy (No Inspect) | 333.3 [303.8–343.6] | 47.89 | 45.01 | 105.48 | 5,979 | 0 | 0 | - |
| 1 MB | 16 | Proxy (Inspect On - Clean) | 292.4 [266.1–307.1] | 54.32 | 51.14 | 112.65 | 5,321 | 0 | 0 | - |
| 1 MB | 16 | Proxy (Inspect On - Redact) | **171.9** [117.1–219.0] | **91.56** | **90.43** | **156.50** | 3,029 | 0 | 0 | **0** |
| **1 MB** | 64 | Direct | 978.9 [645.3–1094.1] | 64.88 | 59.42 | 168.69 | 16,449 | 0 | 0 | - |
| 1 MB | 64 | Proxy (No Inspect) | 230.6 [174.6–232.8] | 275.59 | 266.39 | 455.78 | 4,012 | 0 | 0 | - |
| 1 MB | 64 | Proxy (Inspect On - Clean) | 220.2 [201.8–226.6] | 288.12 | 281.61 | 471.37 | 4,074 | 0 | 0 | - |
| 1 MB | 64 | Proxy (Inspect On - Redact) | **153.0** [123.5–174.2] | **412.14** | **409.51** | **679.90** | 2,872 | 0 | 0 | **0** |
