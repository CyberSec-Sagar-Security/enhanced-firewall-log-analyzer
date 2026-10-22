# Threat Model — Rebuild v1

> Scope: the Rebuild v1 CLI described in [`SCOPE.md`](SCOPE.md) §5. Method: STRIDE per component, risk = impact × likelihood (1–4 each).
> Every mitigation marked **REQ** is a v1 requirement and must have a test or CI check proving it.

## 1. System description

A local Python command-line tool. A user points it at firewall / flow log files. The tool parses them, runs YAML detection rules, groups alerts into incidents, enriches them from a locally cached threat-intel store, and writes JSON/JSONL/CSV/Markdown/HTML/ATT&CK Navigator files. The only network activity is the explicit `intel update` command, which downloads public feeds over HTTPS.

**The core security fact:** the main input — log content — is **attacker-influenced**. Anyone who can send traffic past a firewall controls parts of what gets logged (IPs in some formats, ports, hostnames, URLs, user agents, Suricata signature text, arbitrary bytes in malformed lines). The tool must treat every log byte as hostile, then render it into files that a human opens in a browser or spreadsheet.

## 2. Components & trust boundaries

```
  ATTACKER-INFLUENCED                   LOCAL USER (trusted operator)
  ───────────────────                   ─────────────────────────────
  network traffic ──► firewall ──► log files ─┐      config.yaml / user rules / suppressions
                                             │                 │
  ═══════════════════ TB1: untrusted input ══╪═════════════════╪══════════════════════════
                                             ▼                 ▼
                                   ┌─────────────────────────────────────┐
                                   │ [P1] Format detection + parsers     │
                                   │ [P2] Rule engine (stateful windows) │
                                   │ [P3] Incident grouping + scoring    │
                                   │ [P4] Enrichment ◄── [D1] intel cache│
                                   │ [P5] Output writers                 │
                                   └──────────────┬──────────────────────┘
                                                  │
  ═══════════════════ TB2: output consumed by other software ═════════════════════════════
                                                  ▼
                   report.html (browser) · alerts.csv (Excel/Sheets) · JSON (other tools)

  ═══════════════════ TB3: internet ══════════════════════════════════════════════════════
  public feed URLs (abuse.ch, Spamhaus, Tor, FireHOL) ──HTTPS──► [P6] intel update ──► [D1]
```

## 3. STRIDE analysis

| ID | Component | STRIDE | Threat | I×L = Risk | Mitigation |
|---|---|---|---|---|---|
| T1 | P5 HTML report | Tampering / Info disclosure | Stored XSS: a crafted log field (hostname, URL, signature text) runs script when the analyst opens the report | 4×3 = **12 Critical** | **REQ** Jinja2 autoescape on; no `|safe` on log-derived data; data embedded as JSON in `<script type="application/json">` with `<`/`>`/`&` escaped; strict CSP meta tag (`default-src 'none'`, inline hashes only); no external requests; XSS payload golden test |
| T2 | P5 CSV export | Tampering | Formula/DDE injection (`=HYPERLINK(...)`, `=cmd|...`) when CSV is opened in Excel | 3×3 = **9 High** | **REQ** prefix cells starting with `= + - @ \t \r` with `'`; test with known payloads |
| T3 | P1 parsers | DoS | ReDoS: catastrophic backtracking regex on crafted lines | 3×3 = **9 High** | **REQ** no nested quantifiers; anchored patterns; prefer split/CSV/JSON parsers over regex; max line length (default 64 KiB, longer lines truncated + counted); fuzz tests with time budget |
| T4 | P1 / P2 | DoS | Memory exhaustion: huge files, gzip bombs, millions of distinct IPs blowing up window state | 3×3 = **9 High** | **REQ** streaming parsers; decompression ratio/size cap; bounded per-rule state with eviction of expired windows; `--max-events` guard; memory test on large generated file |
| T5 | P2 user rules | Elevation of privilege | Rule file executes code (`eval`, Python expressions, `yaml.load` object tags) | 4×2 = **8 High** | **REQ** `yaml.safe_load` only; rule language is a declarative schema validated by Pydantic, never evaluated as Python; user regex compiled with a timeout-safe engine or length/complexity limits |
| T6 | P6 intel update | Tampering / Spoofing | Malicious or MITM'd feed injects false positives (e.g. lists 0.0.0.0/0) or crafted content | 3×2 = **6 Medium** | **REQ** HTTPS only, TLS verification always on; per-feed size cap; strict line validator (valid IP/CIDR only); reject feeds with implausibly broad prefixes (e.g. shorter than /8); atomic replace, keep previous cache on failure; record fetch time + SHA-256 |
| T7 | P5 writers | Tampering | Path traversal / overwrite: output names derived from input (e.g. `../../.bashrc`), symlink in output dir | 3×2 = **6 Medium** | **REQ** output paths only from flags/config, never from log content; resolve and confine to output dir; refuse to overwrite without `--force`; open with exclusive create |
| T8 | Terminal output | Tampering | Terminal escape-sequence injection from log fields (spoof output, set title, hide lines) | 2×3 = **6 Medium** | **REQ** strip/escape control characters before printing; Rich markup escaping for all log-derived strings |
| T9 | P1 time handling | Tampering / Repudiation | Attacker-controlled or malformed timestamps reorder events to dodge window-based rules | 2×3 = **6 Medium** | **REQ** unparseable time = counted error, never "now"; report out-of-order and future timestamps; rules state which time field they use |
| T10 | P4 / P5 | Info disclosure | Reports leak internal IPs, hostnames, usernames when shared | 2×2 = **4 Medium** | `--redact` option (hash or mask internal IPs/hosts); document that reports contain sensitive data |
| T11 | D1 / config | Tampering | Another local user edits the intel cache or rules directory | 2×1 = **2 Low** | Cache in user-owned dir with 0700 permissions on POSIX; document the trust assumption |
| T12 | Tool's own logging | Repudiation | Can't tell which rules, feeds and versions produced a result | 2×2 = **4 Medium** | **REQ** every result file records tool version, rule pack hash, feed timestamps, config hash, input file hashes |
| T13 | Supply chain | Tampering | Compromised or vulnerable dependency | 3×2 = **6 Medium** | **REQ** minimal deps; lock file with hashes; `pip-audit` + Dependabot in CI; trusted publishing for releases |

## 4. Top mitigations (priority order)

1. **Output encoding everywhere** — HTML autoescape + CSP, CSV formula neutralization, terminal control-char stripping (T1, T2, T8).
2. **Bounded parsing** — no backtracking-prone regex, line-length cap, streaming, decompression limits (T3, T4).
3. **Declarative rules only** — `safe_load`, Pydantic schema, no evaluation of user content as code (T5).
4. **Bounded detection state** — window eviction and caps so one noisy source can't exhaust memory (T4).
5. **Feed integrity checks** — HTTPS, validation, plausibility limits, atomic updates (T6).
6. **Confined writes** — output paths only from the operator, no overwrite by default (T7).
7. **Provenance in every result** — versions, hashes, timestamps (T12).
8. **Supply-chain hygiene in CI** (T13).

## 5. Out of scope for this model

Compromise of the analyst's machine; integrity of the firewall producing the logs; the v2 web UI and syslog listener (these need their own threat model before v2 starts: network exposure, auth, CSRF, request limits).

## 6. Portfolio summary

> Threat-modelled the rebuild with STRIDE before writing code. The main finding was that firewall logs are attacker-influenced input, rendered into files that analysts open in browsers and spreadsheets. That made stored XSS in HTML reports, CSV formula injection, ReDoS and memory exhaustion the highest risks. Each mitigation is a v1 requirement backed by a test: autoescaped and CSP-locked reports, neutralized CSV cells, bounded streaming parsers, declarative-only detection rules, and integrity-checked threat-intel feeds.
