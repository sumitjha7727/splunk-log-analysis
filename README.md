# SOC Splunk Log Analysis Labs

[![Validate Sigma rules](https://github.com/sumitjha7727/splunk-log-analysis/actions/workflows/validate.yml/badge.svg)](https://github.com/sumitjha7727/splunk-log-analysis/actions/workflows/validate.yml)

Hands-on Splunk SIEM log analysis labs covering six common network log types plus a detection-as-code pass on top of them, run end-to-end against real captured network traffic — ingestion, field extraction, SPL-based threat hunting, and findings write-ups for each log type, then Sigma-modeled standing detections, a deployable Splunk app, and CI validation for the strongest findings among them.

Inspired by [0xrajneesh/Splunk-Projects-For-Beginners](https://github.com/0xrajneesh/Splunk-Projects-For-Beginners) as a starting list of project ideas. Every project here was rebuilt from scratch: original SPL queries, real field-extraction issues worked through (see Project 1 for a schema bug that would've silently broken the analysis), and full findings for each log type — not just a copy of the source guides.

## About

Built by Sumit Kant Jha, SOC Engineer II, as a hands-on exercise in end-to-end SIEM log analysis with Splunk.

## Key findings

- **SSH brute-force to compromise, on two separate hosts** — `192.168.204.45` broke into `192.168.28.203` (95 failed logins, then 1 success) and `192.168.21.253` (57 failures, then 1 success), the clearest "the attacker got in" signature in the whole dataset, now a standing correlation detection in Project 7.
- **Two vulnerability scanners fingerprinted by their SMTP HELO strings** — Nmap's `nmap.scanme.org` sweep hit three hosts once each; Nessus's `mail.nessus.org`/`nessus` strings hit a smaller set of hosts repeatedly from a single source, `192.168.202.110` — the same host also responsible for the SMTP command-injection probes below.
- **Live command-injection probes against SMTP envelope fields** — shell metacharacters (`|`, `;`, embedded quotes) planted in `RCPT TO`/`MAIL FROM`, with 7 of 11 destination mail servers accepting the malformed address instead of rejecting it outright.
- **A DNS tunneling lead, worked all the way through** — repeated long, base32/base64-looking subdomains from one host to one domain, first flagged in Project 1 as an unconfirmed pattern and formally investigated (entropy, cache-miss ratio, beacon timing, `conn.log` correlation) in Project 7's detection-as-code pass.
- **A Splunk ingestion bug that erased a network's biggest DHCP anomaly from view** — default line-breaking silently folded 1,502 real DHCP records down to 333 indexed events, hiding the single host responsible for half the network's DHCP traffic until a raw-file cross-check caught it. Fixed at the source in `splunk-app/default/props.conf`, not just noted and left alone.

Three things this repo is meant to demonstrate, beyond any one finding: that real field-extraction and ingestion bugs get caught and written down rather than quietly worked around off-screen; that a hunt's output should end as a standing, versioned detection instead of a one-off query nobody re-runs; and that "the detection is documented" and "the detection is live" are different claims, kept honestly distinct throughout rather than blurred together.

## Lab environment

- Splunk Enterprise (free trial), run locally via Docker
- Sample data: Zeek/Bro network logs from the [MACCDC 2012](https://www.secrepo.com/maccdc2012/) capture — a public dataset from the Mid-Atlantic Collegiate Cyber Defense Competition, commonly used for SOC/blue-team training

To reproduce the Splunk environment:

```bash
docker run -d -p 8000:8000 -p 8088:8088 -p 8089:8089 --name splunk \
  -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com \
  -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_PASSWORD=<your-password> \
  splunk/splunk:latest
```

Then log in at `http://localhost:8000` with user `admin` and the password you set.

## Projects

| # | Log type | Status | Link |
|---|----------|--------|------|
| 1 | DNS | Done | [01-dns-log-analysis](./01-dns-log-analysis) |
| 2 | FTP | Done | [02-ftp-log-analysis](./02-ftp-log-analysis) |
| 3 | SSH | Done | [03-ssh-log-analysis](./03-ssh-log-analysis) |
| 4 | Tunnel (GRE / IPv4 / IPv6, via Zeek) | Done | [04-tunnel-log-analysis](./04-tunnel-log-analysis) |
| 5 | SMTP | Done | [05-smtp-log-analysis](./05-smtp-log-analysis) |
| 6 | DHCP | Done | [06-dhcp-log-analysis](./06-dhcp-log-analysis) |
| 7 | Detection-as-Code | Done | [07-detection-as-code](./07-detection-as-code) |

Each of Projects 1-6 contains: objective, data source, ingestion steps, field-extraction notes, the SPL queries used, findings, and screenshots. Project 7 formalizes the strongest findings from Projects 1-6 into standing Sigma/SPL detections, including a DNS tunneling detection promoted from Project 1's own investigative lead (see [`01-dns-log-analysis/investigation/`](./01-dns-log-analysis/investigation)).

Two more top-level pieces tie the whole repo together: [`splunk-app/`](./splunk-app) packages the field extractions and detections from all seven projects as deployable `.conf` files rather than leaving them as GUI clicks and copy-pasted SPL, and [`RUNBOOK.md`](./RUNBOOK.md) tracks every action that needs a live Splunk instance or a human operator to actually run — this repo's tooling has no Splunk connector, so anything requiring live query output or a GUI change is written there instead of simulated.

## detection-lab

[`detection-lab/`](./detection-lab) is the natural next step past Project 7: Projects 1-7 prove detections can be built from a static capture, but a static capture has no ground truth, so there's no way to measure a real true/false-positive rate for any of them. `detection-lab` scaffolds an isolated VM lab, Atomic Red Team campaign tooling, and a CI fixture-replay pipeline to actually measure that — see its own `README.md` for the architecture, build order, and isolation warnings. As of this commit it's scaffolding only: no lab has been provisioned and no attack has been run.

## License

MIT — see [LICENSE](./LICENSE).
