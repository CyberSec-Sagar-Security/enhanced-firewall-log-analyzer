# Firewall Log Analyzer

> **Status: being rebuilt.** This repository holds a 2025 learning project (v2.0.0, "legacy") that is being rebuilt from scratch into a detection-engineering engine for firewall and network flow logs.
>
> 📌 **Read [`docs/SCOPE.md`](docs/SCOPE.md) first.** It is the single source of truth for what the rebuild includes, what it doesn't, and the milestone plan.
> 🛡️ Security requirements for the rebuild are in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## What the rebuild will be (v1, released as 3.0.0)

A pip-installable, offline-first **command-line tool** that:

- ingests pfSense/OPNsense, Windows Firewall, iptables/nftables, Zeek, Suricata, and AWS/Azure/GCP flow log **files** into one normalized schema;
- runs **detections-as-code**: YAML rules with stateful windows and sequences, each shipped with its own tests;
- detects scans, brute force (including brute force followed by a successful login), C2 beaconing, exfiltration, lateral movement and known-bad infrastructure, all mapped to MITRE ATT&CK;
- groups alerts into a handful of scored **incidents** instead of an alert flood;
- enriches incidents from locally cached public threat-intel feeds;
- writes JSON/JSONL, CSV, Markdown, a self-contained **HTML report** and an **ATT&CK Navigator layer**.

There are no VMs, no SIEM and no cloud accounts. Everything runs on a laptop with Python. See [`docs/SCOPE.md`](docs/SCOPE.md) §3 for the hard boundaries.

## Legacy code (v2.0.0)

The legacy modules (`main.py`, `parsers/`, `detectors/`, `alerts/`, `utils/`) are kept only until the rebuild replaces them. They have known defects, which are documented in [`docs/SCOPE.md`](docs/SCOPE.md) §4. In short:

- the pfSense CSV parser misreads its own sample;
- the correlation step crashes;
- one alert is raised per log line;
- `win10toast` is a hard dependency, so it runs only on Windows.

```powershell
pip install -r requirements.txt
python main.py --logfile test_logs/sample_windows_fw.csv --parser windows --quiet
```

No new features are being added to the legacy code.

## License

MIT. See [LICENSE](LICENSE).
