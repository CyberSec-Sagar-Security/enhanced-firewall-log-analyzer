# Project Scope & Roadmap

> **This is the single source of truth for what this project is, what it is becoming, and what is in or out of each release.**
> If a feature is not listed here, it is not in scope. Update this file *before* starting work that changes scope.

| | |
|---|---|
| **Owner** | Sagar Suryawanshi (Tony) |
| **Status** | Rebuild v1 — planning complete, implementation not started |
| **Last updated** | 2026-10-22 |
| **Working name** | Firewall Log Analyzer (final name TBD — see [Open decisions](#9-open-decisions)) |
| **Related docs** | [`THREAT_MODEL.md`](THREAT_MODEL.md) — security requirements for the rebuild |

---

## Table of contents

1. [Vision & positioning](#1-vision--positioning)
2. [Product form: CLI first, web later](#2-product-form-cli-first-web-later)
3. [Hard boundaries (what this project is NOT)](#3-hard-boundaries-what-this-project-is-not)
4. [Legacy version (v2.0.0, 2025) — what existed and why we are rebuilding](#4-legacy-version-v200-2025--what-existed-and-why-we-are-rebuilding)
5. [**Rebuild v1 — the scope we are building now**](#5-rebuild-v1--the-scope-we-are-building-now)
6. [Rebuild v2 — next](#6-rebuild-v2--next)
7. [Later / backlog](#7-later--backlog)
8. [Engineering standards (apply to every version)](#8-engineering-standards-apply-to-every-version)
9. [Open decisions](#9-open-decisions)
10. [Change log for this document](#10-change-log-for-this-document)

---

## 1. Vision & positioning

**One line:** a lightweight, offline-first **detection-engineering engine for firewall and network flow logs**, written as installable software.

**The problem it solves:** raw firewall logs are huge, noisy and come in many incompatible formats. Small teams, students and home-lab owners have no simple tool that turns them into a short list of *real incidents* with context. This tool reads the logs, normalizes them, runs version-controlled detection rules, groups related alerts into incidents, enriches them with threat intel, and produces reports that an analyst can act on.

**How it fits with my other work:**

| Project | Question it answers | Data it looks at |
|---|---|---|
| CloudGuard (CSPM/CNAPP-style) | *"Is this environment misconfigured?"* | Configuration / posture |
| **This project** | *"What is actually happening on the network?"* | Runtime traffic (firewall + flow logs) |

Together they cover both halves: **posture** and **behaviour**. The cloud flow log parsers (AWS / Azure / GCP) are the deliberate bridge between the two.

**What a reviewer or interviewer should see:** real detection engineering practice — normalized schema, detections-as-code with tests, statistical (not port-list) detections, alert-to-incident grouping, MITRE ATT&CK mapping, and production-quality Python (typed, tested, packaged, CI).

---

## 2. Product form: CLI first, web later

**Decision: v1 is a command-line application. A local web UI comes in v2, built on the same engine.**

Why:

- **The engine is the product.** Parsing, detection and incident logic must be correct and tested first; a UI on top of a weak engine is decoration.
- **A CLI is scriptable and testable.** Every feature can be covered by automated tests and used in pipelines (exit codes, JSON output).
- **Visual output still exists in v1** — the CLI writes a **self-contained HTML report** (one file, no server, opens in any browser). That gives most of the "web app" value with none of the server/auth/attack-surface cost.
- **v2 adds `serve`** — a local-only web UI (bound to `127.0.0.1`) that reads the same results. No rewrite needed, because the engine is a library and the CLI is just one front-end.

```
            ┌─────────────────────── core library (the engine) ───────────────────────┐
log files → │ ingest/parsers → normalized events → rule engine → incidents → enrich │ → outputs
            └──────────────────────────────────────────────────────────────────────────┘
                         ▲                                           ▲
                    CLI (v1)                                 local web UI (v2)
```

---

## 3. Hard boundaries (what this project is NOT)

These apply to **Rebuild v1** and stay in force unless this document is changed on purpose.

- ❌ **No VMs, no lab infrastructure.** No Wazuh, no Security Onion, no ELK/OpenSearch stack, no pfSense VM, no Windows VM required to build, test or demo the tool.
- ❌ **No SIEM.** The tool does not require, deploy, or integrate with a SIEM in v1 (no Splunk HEC, no Elastic output, no Wazuh agent). SIEM *output connectors* are listed under [Later](#7-later--backlog) only.
- ❌ **No cloud accounts required.** Cloud flow logs are parsed from **files**; the tool never needs AWS/Azure/GCP credentials.
- ❌ **No automatic blocking / response.** The tool may *suggest* firewall rules (later); it never changes a firewall.
- ❌ **No packet capture.** Input is logs, not PCAP.
- ✅ **All test and demo data is generated or bundled in the repo** (sample logs + a synthetic log generator), so everything runs on a plain laptop with Python.

**Network use:** the only outbound network call in v1 is the explicit `intel update` command that downloads public threat-intel feeds. Every other command works fully offline.

---

## 4. Legacy version (v2.0.0, 2025) — what existed and why we are rebuilding

> This section is the record of the **old project** (what I previously called "V1"). It is kept for history only. **No new features go into the legacy code.** It is replaced module by module during Rebuild v1 milestones M0–M2 and then deleted.

### 4.1 What it claimed

Windows Firewall + pfSense parsing; suspicious-port, brute-force, exfiltration, reverse-shell and off-hours detection; correlation engine; MITRE ATT&CK tagging; live tailing; scheduler; Excel/PDF/JSON reports; Streamlit dashboard; Windows toast alerts.

### 4.2 What an audit on 2026-10-22 actually found

Measured by running the tool against its own bundled sample logs and its own test suite:

| Area | Finding |
|---|---|
| Portability | Hard import of `win10toast` (Windows-only) → the tool and the test suite **crash on Linux/macOS** before doing anything. |
| pfSense parser | Reads CSV columns by position and ignores the header. On `test_logs/sample_pfsense.csv` the header row becomes an event and `action` becomes `"13:45:12"`. An obviously malicious log produces **1 alert**. |
| Timestamps | Any unparseable timestamp is silently replaced with `datetime.now()`, corrupting every time-window detection. |
| Alert quality | 55 log lines → **68 alerts** (one alert per matching line, no dedup, no grouping). |
| Correlation | Crashes on every run with `TypeError: '>' not supported between 'str' and 'float'` (string timestamps compared with epoch floats); the error is logged and swallowed, so it reports **0 correlations** even on the sample built to demonstrate multi-stage attacks. Its design (keyword matching on alert *titles*) was fragile anyway. |
| Detection logic | Mostly static port lists; ports 22/80/443 flagged as risky → high false-positive rate. No baselining, no statistics. |
| Tests | 3 of 14 tests fail; only one detector has unit tests. |
| Structure | Three entry points (`main.py`, `enhanced_main.py`, `launcher.py`); a duplicated class pasted after `if __name__ == "__main__"` in `main.py`; output JSON appended forever. |
| Dependencies | Old pins (e.g. `pandas==2.1.3`) that do not install on current Python. |
| CI | Workflow referenced Python 3.8 and deprecated actions (`upload-artifact@v3`) and could not pass. |

### 4.3 Decision

**Rebuild, don't patch.** The idea is good; the implementation is not a foundation worth extending. The rebuild keeps the repository (history shows the evolution) and ships as package version **3.0.0** so semantic versioning stays monotonic. In this document "Rebuild v1 / v2" means *phases of the rebuild*, not package versions.

### 4.4 Cleanup already done (2026-10-22)

Removed because they are dead, duplicated, broken, or out of the new scope: `enhanced_main.py`, `launcher.py`, `deploy_to_github.py`, `gui/dashboard.py`, `utils/excel_report.py`, `utils/time_utils.py`, `setup.py` (entry points pointed at deleted scripts; replaced by `pyproject.toml` in M0), `DEPLOYMENT.md`, `MANIFEST.in`, the `streamlit`/`plotly` requirements, `test_logs/clean_windows_fw.csv` (despite the name it contained attack traffic), and the broken CI workflow. Everything remains available in git history (commit `051c3c8`). The remaining legacy modules stay only until their rebuild replacements land.

---

## 5. Rebuild v1 — the scope we are building now

**Goal of v1:** a pip-installable CLI that turns raw firewall/flow log files into a small number of well-explained, MITRE-mapped incidents, with detections written as tested code.

**Definition of done for v1:** every item in 5.1–5.6 below meets its acceptance criteria, the [engineering standards](#8-engineering-standards-apply-to-every-version) are met, and the full demo in [5.8](#58-v1-demo-script-what-done-looks-like) runs on a clean machine.

### 5.1 Ingest & normalization (foundation)

Read log files, auto-detect the format, and convert every record into **one normalized event schema**.

**Formats in v1:**

| Format | Source | Notes |
|---|---|---|
| pfSense / OPNsense `filterlog` | syslog text | Raw filterlog CSV-in-syslog, IPv4 + IPv6 |
| Windows Defender Firewall `pfirewall.log` | W3C-style text | Honour the `#Fields:` header instead of fixed positions |
| Linux iptables / nftables `LOG` lines | kernel/syslog text | `SRC= DST= SPT= DPT= PROTO=` key-value style |
| Zeek `conn.log` | TSV and JSON | Byte counts + duration → enables exfil/beacon detections |
| Suricata `eve.json` | JSON lines | `flow` and `alert` event types |
| AWS VPC Flow Logs | text (v2–v5 fields) | Parsed from files; **no AWS account needed** |
| Azure NSG / VNet flow logs | JSON | Parsed from files |
| GCP VPC Flow Logs | JSON (Cloud Logging export) | Parsed from files |
| Generic CSV | CSV + column mapping file | Escape hatch for anything else |

**Normalized event schema** — aligned to **OCSF Network Activity** (field names mapped, documented in `docs/schema.md`):
`time (UTC, tz-aware)`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `action (allowed/blocked/unknown)`, `direction (inbound/outbound/internal/unknown)`, `bytes_in`, `bytes_out`, `packets`, `duration`, `interface`, `rule_id`, `app/process`, `source_format`, `source_file`, `source_line`, `raw`.

**Acceptance criteria:**
- Format auto-detection with a confidence score; `--format` overrides it.
- Header-driven parsing — never rely on fixed column positions when the format has a header.
- Timestamps always timezone-aware UTC; an unparseable timestamp is a **counted parse error**, never "now". Syslog formats without a year take the year from `--year` or the file's mtime, and this is documented.
- Malformed lines are skipped, counted and reported (`--strict` turns them into a failure); one bad line never aborts a file.
- Streaming parsers: memory stays flat regardless of file size; gzip input supported transparently.
- Each parser has golden-file tests (input sample → expected normalized JSONL) plus fuzz/property tests for malformed input.
- `parse` command exports normalized events as JSONL so the parsers are useful on their own.

### 5.2 Detection-as-code engine

Detections are **YAML files**, not Python `if` statements. Each rule is versioned, documented, and tested.

**Rule capabilities:**
- Field conditions: equals, in-list, CIDR match, port ranges, numeric comparisons, regex (safe, bounded — see threat model).
- **Stateful aggregation**: `group_by` entity + sliding `window` + thresholds on `count`, `distinct_count(field)`, `sum(field)`.
- **Sequences**: rule A followed by rule B for the same entity within a window (e.g. many blocked → one allowed).
- Built-in helpers: `is_private(ip)`, `is_internal(ip)` (driven by a configurable `internal_networks` list), `in_list(ip, intel_feed)`.
- Metadata per rule: `id`, `title`, `description`, `severity`, `confidence`, MITRE ATT&CK `techniques`, `false_positives`, `references`, `tests`.

**Rule testing (the key differentiator):** every rule ships with positive and negative test logs. `rules test` runs them; CI fails if a rule stops firing on its positive case or starts firing on its negative case.

**Example rule (illustrative):**

```yaml
id: NET-0003
title: Horizontal port scan from single source
severity: medium
mitre: [T1046]
match:
  action: [blocked, allowed]
aggregate:
  group_by: [src_ip, dst_port]
  window: 5m
  condition: distinct_count(dst_ip) >= 20
tests:
  positive: tests/data/scan_horizontal.log
  negative: tests/data/benign_dns.log
```

**Sigma:** native YAML rules are the v1 commitment. Importing Sigma rules (`logsource: category: firewall`) is a **v1 stretch goal** — if it threatens the timeline it moves to v2.

**Acceptance criteria:** `rules validate` (schema check with clear errors), `rules list`, `rules test`; rules load from the built-in pack plus user directories; a broken user rule is reported and skipped, never crashes the run.

### 5.3 Behavioural detections (built-in rule pack)

Replaces the legacy port-list detectors. Every detection maps to MITRE ATT&CK.

| # | Detection | Logic (summary) | ATT&CK |
|---|---|---|---|
| 1 | Horizontal port scan | One source → same port on many hosts within a window | T1046 |
| 2 | Vertical port scan | One source → many ports on one host within a window | T1046 |
| 3 | Low-and-slow scan | Same as 1/2 but spread across hours, distinct-count over a long window | T1046 |
| 4 | Brute force | Many blocked/short connections to auth services (SSH, RDP, SMB, WinRM, DBs) | T1110 |
| 5 | Brute force → success | Burst of blocked/failed attempts followed by an allowed session from the same source | T1110, T1078 |
| 6 | C2 beaconing | Regular connection intervals to one destination: low jitter (coefficient of variation), minimum event count, minimum duration | T1071 |
| 7 | Exfiltration by volume | Outbound bytes well above the host's own baseline, or high bytes-out / bytes-in ratio to an external IP | T1041, T1048 |
| 8 | Lateral movement fan-out | Internal host suddenly connects to many internal hosts on admin ports (SMB/RDP/WinRM/SSH) | T1021 |
| 9 | Non-standard port egress | Allowed outbound connections to known backdoor/listener ports (4444, 31337, …) — low weight on its own, boosts incident score | T1571 |
| 10 | First-seen destination | Host talks to a new external ASN/country/port compared with the earlier part of the dataset (or a saved baseline) | T1071 |
| 11 | Known-bad infrastructure | Traffic to/from IPs in cached intel feeds (C2 lists, Tor exits, DROP lists) | T1071, T1090.003 |
| 12 | Off-hours activity | Outbound activity outside configurable business hours/timezone — context signal, low weight | — (context) |

Thresholds live in config, not code. Detections that need bytes/duration (6, 7) degrade gracefully when the format has no byte counts, and say so in the report.

### 5.4 Incident grouping & risk scoring

The fix for the legacy alert flood: **alerts are evidence, incidents are the output.**

- Alerts are grouped into incidents per **entity** (host or external IP) and time proximity.
- Each incident has: a risk score (severity × confidence × intel boost × number of distinct tactics), a timeline of alerts, involved hosts/IPs/ports, ATT&CK techniques, a kill-chain stage summary (recon → access → C2 → exfil), and a plain-English explanation of *why* it was raised.
- Dedup: repeated hits of the same rule on the same entity collapse into one alert with a count and first/last seen.
- Allow-listing: suppress known-good IPs/CIDRs/rules through a suppression file, and report how many alerts each suppression hid (suppressions stay visible).

**Acceptance criterion:** the bundled multi-stage sample produces a handful of incidents (target: ≤ 5), not dozens of alerts, and the main attack chain is one incident.

### 5.5 Threat-intel enrichment (offline-first)

- `intel update` downloads free public feeds, **verifies and stores them locally with a timestamp**: abuse.ch Feodo Tracker (C2), Spamhaus DROP/EDROP, Tor exit node list, FireHOL level1. Feeds are configurable; each has a size limit and a format validator.
- All other commands use the local cache only; stale feeds are flagged in the report (e.g. "intel is 9 days old").
- Optional GeoIP/ASN lookup with a MaxMind GeoLite2 `.mmdb` file **if the user provides one** (it needs a free MaxMind account, so it cannot be bundled). Everything works without it.
- Enrichment adds context to incidents (feed name, country, ASN) and boosts risk scores.

### 5.6 Outputs & CLI

**Commands (v1):**

| Command | Purpose |
|---|---|
| `analyze <files/dirs>` | Full pipeline: parse → detect → group → enrich → report |
| `parse <files>` | Normalize only; write JSONL |
| `rules list / validate / test` | Manage and test detection rules |
| `intel update / status` | Refresh or inspect the local threat-intel cache |
| `generate <scenario>` | Synthetic log generator for demos and tests (see 5.7) |
| `formats` | List supported formats and how detection works |

**Output formats:**
- Rich terminal summary (incidents first, colour, works without colour for CI).
- `json` (full results) and `jsonl` (one alert/incident per line).
- **Self-contained HTML report** — one file, inline CSS/JS, no external requests, safe escaping of all log-derived data.
- **MITRE ATT&CK Navigator layer** JSON — load into the public Navigator to see coverage and hits.
- Markdown incident summary (good for pasting into a ticket or a GitHub issue).
- **CSV** export with spreadsheet formula-injection protection. (Excel/PDF from the legacy version are dropped; the HTML report replaces them.)

**CLI behaviour:**
- Exit codes: `0` no incidents, `1` incidents at or above `--fail-on <severity>`, `2` usage/config error, `3` parse failure in `--strict` mode — usable in scripts and CI.
- One config file (`config.yaml`) for internal networks, business hours/timezone, thresholds, feed list, suppressions; every option also available as a flag; `--config` path is validated.
- Output never overwrites an existing file unless `--force`; output directory is created safely.

### 5.7 Synthetic log generator (v1, supporting feature)

Small built-in generator that writes realistic logs (in any supported format) for named scenarios: `benign`, `port-scan`, `brute-force`, `brute-force-success`, `beaconing`, `exfil`, `lateral-movement`, `full-chain`. It exists so that:
- tests and demos never depend on a VM or real network,
- every built-in rule has generated positive/negative fixtures,
- the README demo is reproducible with one command.

(The full purple-team coverage feature built on this is in [Later](#7-later--backlog).)

### 5.8 v1 demo script (what "done" looks like)

On a clean machine with Python ≥ 3.11:

```bash
pip install .                                    # or pipx install .
fwla generate full-chain --format pfsense -o demo.log
fwla intel update                                # optional, only network call
fwla analyze demo.log --html report.html --navigator layer.json
fwla rules test                                  # all rule tests pass
```

Expected: a few incidents, the main one showing scan → brute force → successful login → beaconing → exfil with ATT&CK techniques, and an HTML report that opens offline. (`fwla` is a placeholder command name.)

### 5.9 Rebuild v1 milestones

| Milestone | Content | Exit criteria |
|---|---|---|
| **M0 — Foundation** | `src/` layout, `pyproject.toml`, typed event model, config loading, CLI skeleton, logging, CI (lint, type check, tests, security scan) | `fwla --help` works; CI green on Linux/Windows/macOS |
| **M1 — Parsers** | All v1 formats + auto-detect + golden tests + fuzz tests | Every sample parses with zero silent errors |
| **M2 — Rule engine + rule pack** | YAML rules, stateful windows, sequences, rule tests, detections 1–12 | `rules test` green; legacy detectors deleted |
| **M3 — Incidents** | Dedup, grouping, scoring, suppressions | Multi-stage sample → ≤ 5 incidents |
| **M4 — Intel** | Feed download/verify/cache, GeoIP optional, enrichment | Works offline with cache; stale-feed warning |
| **M5 — Outputs + generator** | HTML, Navigator, JSON/JSONL, Markdown, CSV, generator scenarios | Demo script in 5.8 passes end-to-end |
| **M6 — Release 3.0.0** | README rewrite, docs, threat model review, changelog, tag | Clean-machine install + demo verified |

---

## 6. Rebuild v2 — next

Starts only after v1 is released.

1. **Firewall policy vs. traffic audit** *(the most distinctive feature)* — ingest the ruleset itself (iptables-save / nftables, pfSense/OPNsense `config.xml`, AWS Security Group JSON export) together with the traffic, and report: shadowed rules, rules never hit, any-any / overly broad rules, rules that attack traffic actually passed through, and **suggested least-privilege rules** generated from the observed flows. Bridges directly to CloudGuard.
2. **Threat-hunting query mode** — `hunt "dst_port=4444 and action=allowed and bytes_out>1MB"` over millions of events using DuckDB + Parquet; saved hunts.
3. **Local web UI (`serve`)** — browse incidents, timelines and hunts in the browser; bound to `127.0.0.1` by default, read-only on results.
4. **Continuous mode** — tail files and/or listen for syslog (UDP/TCP 514) and run the same rules in streaming mode with persistent state.
5. **Docker image** for the CLI and `serve`.
6. **Sigma import** (if not delivered as the v1 stretch goal).

## 7. Later / backlog

Ideas recorded so they are not lost. Not committed; each needs to be moved into a version section before work starts.

- **Purple-team coverage report** — run every generator scenario, show which ATT&CK techniques are detected and which are gaps.
- **Notifications** — Slack / Microsoft Teams / generic webhook for high-severity incidents.
- **Suggested block rules** — generate iptables / pfSense alias / AWS NACL snippets for an incident (suggest only, never apply).
- **SIEM output connectors** — Splunk HEC, Elastic bulk, OCSF export for any SIEM. *(Explicitly out of v1/v2 per section 3.)*
- **AI-assisted triage** — incident summary and next steps; must support a local model so offline mode survives; only after detections are solid.
- **STIX 2.1 export** of indicators from incidents.
- **More formats** — Palo Alto, FortiGate, Cisco ASA, Check Point, Sophos.
- **Tony's own use case** — *(to be added here; see Open decisions)*.

---

## 8. Engineering standards (apply to every version)

**Language & tooling:** Python ≥ 3.11; `pyproject.toml` (no `setup.py`); `src/` layout; Typer (CLI), Pydantic v2 (models/config), PyYAML `safe_load` only, Jinja2 with autoescape (HTML report), Rich (terminal). Optional extras: `geoip` (maxminddb), later `hunt` (duckdb). No platform-specific hard dependencies.

**Architecture rules:**
- The engine is a library; the CLI is a thin layer. No `print()` in library code — use logging and return values.
- Parsers, rules and outputs are plug-ins behind small interfaces; adding one never requires editing another.
- Pure functions for detection logic; I/O at the edges. Deterministic output (stable sorting) so golden tests are reliable.
- No global mutable state; no hidden file writes; all paths come from config/flags.

**Quality gates (CI must enforce):**
- `ruff` (lint + format), `mypy --strict` on `src/`, `pytest` with coverage ≥ 85% on `src/`.
- Golden-file tests for every parser and output; rule tests for every rule; property/fuzz tests for parsers.
- Security: `bandit`, `pip-audit`, secret scanning; dependencies pinned via a lock file and updated by Dependabot.
- Matrix: Linux, Windows, macOS × supported Python versions.

**Security requirements:** all mitigations in [`THREAT_MODEL.md`](THREAT_MODEL.md) are v1 requirements, not nice-to-haves. Highlights: treat every log byte as hostile; bounded regex and line length; no `eval`/`pickle`/unsafe YAML; HTML/CSV output escaping; HTTPS-only feed download with size limits and validation; never write outside the chosen output directory.

**Docs:** README (what/why/quick start/demo GIF), `docs/schema.md`, `docs/rules.md` (rule language), `docs/formats.md`, this scope file, threat model, changelog (Keep a Changelog).

---

## 9. Open decisions

| # | Decision | Status |
|---|---|---|
| 1 | Product name and CLI command name (`fwla` is a placeholder) | Open |
| 2 | Tony's own use case — where it fits (v1, v2, or later) | Open — add to this table and to the right section |
| 3 | Sigma import in v1 (stretch) or v2 | Decide at end of M2 |
| 4 | Normalized schema: OCSF field names directly, or internal names + OCSF mapping | Proposed: internal names + documented OCSF mapping; confirm in M0 |
| 5 | Minimum Python version (3.11 proposed) | Confirm in M0 |
| — | Product form: CLI first, local web UI in v2 | **Decided** 2026-10-22 |
| — | No VMs / SIEM in v1 | **Decided** 2026-10-22 |
| — | Rebuild in this repo, release as 3.0.0 | **Decided** 2026-10-22 |

---

## 10. Change log for this document

| Date | Change |
|---|---|
| 2026-10-22 | Initial scope: legacy audit, Rebuild v1 scope + milestones, v2, backlog, standards, open decisions. Repo cleanup recorded in 4.4. |
