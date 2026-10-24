# Inbound Prompt Injection Evaluation & Adversarial Results

Generated: October 2026
Environment: Apple Silicon (arm64, macOS, rustc 1.94.1, `--release` profile)

---

## 1. Executive Summary & Evaluation Discipline

Evaluation follows strict **generalization and held-out evaluation discipline**:
- **Dev / Test Split:** The 600-sample corpus was partitioned 50/50 prior to any rule tuning. The test split remained completely untouched during heuristic authoring.
- **Adaptive Attacker Set:** Evaluated on 35 distinct evasion techniques (paraphrasing, multilingual injection, base64/rot13/hex encoding, homoglyphs, and tag splitting). **No rules were tuned to artificially patch this set**, ensuring an honest accounting of heuristic-based guardrail limits.

---

## 2. Detection Quality: Dev vs. Held-Out Test

| Metric | Dev Split (300 samples) | Held-Out Test Split (300 samples) | Target Gate |
| :--- | :--- | :--- | :--- |
| **True Positives (TP)** | 90 / 150 | 95 / 150 | - |
| **False Positives (FP)** | 25 / 150 | 25 / 150 | - |
| **True Negatives (TN)** | 125 / 150 | 125 / 150 | - |
| **False Negatives (FN)** | 60 / 150 | 55 / 150 | - |
| **Precision** | **78.3%** | **79.2%** | >= 90.0% |
| **Recall** | **60.0%** | **63.3%** | >= 90.0% |
| **F1 Score** | **67.9%** | **70.4%** | >= 90.0% |
| **False Positive Rate (FPR)** | **16.7%** | **16.7%** | <= 5.0% |

### Per-Tier Detection Recall (Dev vs. Held-Out Test)

| Tier | Description | Dev Recall (TP/Total) | Held-Out Test Recall (TP/Total) |
| :--- | :--- | :--- | :--- |
| **Tier 1** | Instruction Override, Role Switch, Markers, Concealment | 37 / 75 (**49.3%**) | 42 / 75 (**56.0%**) |
| **Tier 2** | HTML Hidden Styles, Comments, Aria-Hidden, Zero-Width | 35 / 45 (**77.8%**) | 37 / 45 (**82.2%**) |
| **Tier 3** | Markdown Image Exfil & High-Entropy Query Params | 18 / 30 (**60.0%**) | 16 / 30 (**53.3%**) |

---

## 3. Adaptive Attacker Evasion Matrix

Evaluated on **35 held-out adversarial evasion samples** across 7 distinct evasion vectors:
- **Overall Evasion Bypass Rate:** **74.3%** (26 of 35 attacks bypassed regular expression rules)
- **Caught / Blocked:** **25.7%** (9 of 35 attacks detected)

| Evasion Category | Specific Technique | Samples | Bypassed | Bypass Rate | Failure Mode Analysis |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Encoding Obfuscation | `base64` | 1 | 1 | **100.0%** | Base64/rot13/hex payloads lack plaintext signature without decoding |
| Encoding Obfuscation | `base64_json` | 1 | 1 | **100.0%** | Base64/rot13/hex payloads lack plaintext signature without decoding |
| HTML / Tag Fragmentation | `case_variation` | 1 | 0 | **0.0%** | Tags split across comments ('ign<!-- -->ore') break linear regex patterns |
| Character / Unicode Manipulation | `combining_accents` | 1 | 1 | **100.0%** | Cyrillic lookalikes ('а', 'о') and punctuation splits break word boundaries |
| HTML / Tag Fragmentation | `comment_split` | 1 | 1 | **100.0%** | Tags split across comments ('ign<!-- -->ore') break linear regex patterns |
| HTML / Tag Fragmentation | `custom_xml_tags` | 1 | 1 | **100.0%** | Tags split across comments ('ign<!-- -->ore') break linear regex patterns |
| Semantic / Framing Evasion | `fiction_framing` | 1 | 1 | **100.0%** | Meta-framing / typos disguise imperative commands as benign queries |
| Encoding Obfuscation | `hex_stream` | 1 | 1 | **100.0%** | Base64/rot13/hex payloads lack plaintext signature without decoding |
| Character / Unicode Manipulation | `homoglyph_cyrillic` | 1 | 1 | **100.0%** | Cyrillic lookalikes ('а', 'о') and punctuation splits break word boundaries |
| HTML / Tag Fragmentation | `html_style_variant` | 1 | 0 | **0.0%** | Tags split across comments ('ign<!-- -->ore') break linear regex patterns |
| HTML / Tag Fragmentation | `html_tag_split` | 1 | 0 | **0.0%** | Tags split across comments ('ign<!-- -->ore') break linear regex patterns |
| Character / Unicode Manipulation | `hyphen_separated` | 1 | 1 | **100.0%** | Cyrillic lookalikes ('а', 'о') and punctuation splits break word boundaries |
| Semantic / Framing Evasion | `hypothetical_framing` | 1 | 1 | **100.0%** | Meta-framing / typos disguise imperative commands as benign queries |
| Structural Obfuscation | `invisible_separator` | 1 | 0 | **0.0%** | Whitespace splits or markdown tables disrupt contiguous tokens |
| Structural Obfuscation | `markdown_table_split` | 1 | 0 | **0.0%** | Whitespace splits or markdown tables disrupt contiguous tokens |
| Structural Obfuscation | `math_symbol_obfuscation` | 1 | 1 | **100.0%** | Whitespace splits or markdown tables disrupt contiguous tokens |
| Multilingual Injection | `multilingual_de` | 1 | 1 | **100.0%** | Non-English instruction words are not in English vocabulary regexes |
| Multilingual Injection | `multilingual_es` | 1 | 1 | **100.0%** | Non-English instruction words are not in English vocabulary regexes |
| Multilingual Injection | `multilingual_fr` | 1 | 1 | **100.0%** | Non-English instruction words are not in English vocabulary regexes |
| Multilingual Injection | `multilingual_ja` | 1 | 1 | **100.0%** | Non-English instruction words are not in English vocabulary regexes |
| Multilingual Injection | `multilingual_ru` | 1 | 1 | **100.0%** | Non-English instruction words are not in English vocabulary regexes |
| Multilingual Injection | `multilingual_zh` | 1 | 1 | **100.0%** | Non-English instruction words are not in English vocabulary regexes |
| Semantic Paraphrase | `paraphrase` | 5 | 5 | **100.0%** | Synonyms ('set aside prior mandates') bypass literal regex tokens |
| Structural Obfuscation | `recursive_nesting` | 1 | 0 | **0.0%** | Whitespace splits or markdown tables disrupt contiguous tokens |
| Semantic / Framing Evasion | `reverse_psychology` | 1 | 0 | **0.0%** | Meta-framing / typos disguise imperative commands as benign queries |
| Encoding Obfuscation | `rot13` | 1 | 1 | **100.0%** | Base64/rot13/hex payloads lack plaintext signature without decoding |
| Character / Unicode Manipulation | `space_separated` | 1 | 1 | **100.0%** | Cyrillic lookalikes ('а', 'о') and punctuation splits break word boundaries |
| Semantic / Framing Evasion | `spelling_deliberate_typos` | 1 | 1 | **100.0%** | Meta-framing / typos disguise imperative commands as benign queries |
| Semantic / Framing Evasion | `translation_framing` | 1 | 0 | **0.0%** | Meta-framing / typos disguise imperative commands as benign queries |
| Character / Unicode Manipulation | `underscore_separated` | 1 | 1 | **100.0%** | Cyrillic lookalikes ('а', 'о') and punctuation splits break word boundaries |
| Structural Obfuscation | `vertical_whitespace` | 1 | 0 | **0.0%** | Whitespace splits or markdown tables disrupt contiguous tokens |

---

## 4. Inbound Scan Latency & Throughput Benchmark

Measured on 100 KB and 1 MB payloads comparing pass-through vs. clean and attack scans:

| Payload Size | Operation | Mean Latency | Scan Throughput | Overhead vs. Pass-Through |
| :--- | :--- | :--- | :--- | :--- |
| **100 KB** | Pass-Through (No Inspect) | 0.000 µs | - | Baseline |
| 100 KB | Inbound Scan (Clean) | **209.7 µs** | **465.7 MB/s** | +209.7 µs |
| 100 KB | Inbound Scan (Attack Hit) | **226.4 µs** | - | +226.4 µs |
| **1 MB** | Pass-Through (No Inspect) | 0.001 µs | - | Baseline |
| 1 MB | Inbound Scan (Clean) | **2243.9 µs** (2.24 ms) | **445.6 MB/s** | +2.24 ms |
| 1 MB | Inbound Scan (Attack Hit) | **2196.1 µs** (2.20 ms) | - | +2.20 ms |

---

## 5. Architectural Insights & Honest Guardrail Boundaries

1. **Detection Performance:** Across the balanced 600-sample corpus, the DFA RegexSet engine achieves **78.3%–79.2% precision** and **60.0%–63.3% recall** (with Tier 2 structural hiding reaching 77.8%–82.2% recall). The 16.7% false positive rate is driven by defensive security articles quoting injection phrases.
2. **Honest Limitations of Heuristic Filters:** As shown by the **74.3% bypass rate** on the held-out adaptive set, deterministic regex filters alone cannot counter semantic paraphrasing, multilingual instructions, or encoded payloads.
3. **Defense-in-Depth Recommendation:** Inbound regex filtering operates at line rate (395–475 MB/s, ~2.2 ms for 1 MB), making it an efficient, zero-GPU Tier 0 filter. High-risk environments should combine this proxy layer with a small classification model or an LLM judge for second-tier semantic analysis.

### Reproduction Command
```bash
cargo run --release --example eval_injection
```
