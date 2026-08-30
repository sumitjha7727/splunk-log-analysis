# Detection Coverage Matrix

Tracks every detection this lab exists to validate against real Atomic
Red Team campaign data, not just static-capture SPL. **Nothing in this
table has been tested yet** — `detection-lab` is scaffolding as of this
commit. See [`../README.md`](../README.md)'s 7-stage build order for
where "capture ground truth from Atomic runs" sits in the sequence
relative to everything else that has to happen first.

| ATT&CK technique | Rule | Ported from | Tested | Result |
|---|---|---|---|---|
| T1110 (Brute Force) | `ssh-failed-login-threshold.yml` | Project 7 / Project 3 | No | pending |
| T1078 (Valid Accounts) | `ssh-successful-login.yml` | Project 7 / Project 3 | No | pending |
| T1110 + T1078 (correlation) | `ssh-bruteforce-then-success.yml` | Project 7 / Project 3 | No | pending |
| T1595, T1046 (Reconnaissance / Network Service Scanning) | `nmap-scan-signature.yml` | Project 7 / Project 5 | No | pending |
| T1595 (Reconnaissance) | `nessus-scan-signature.yml` | Project 7 / Project 5 | No | pending |
| T1190 (Exploit Public-Facing Application) | `smtp-injection-probe.yml` | Project 7 / Project 5 | No | pending |
| — (deliberately untagged, informational) | `dhcp-lease-anomaly.yml` | Project 7 / Project 6 | No | pending |
| T1071.004, T1048.003 (Application Layer Protocol: DNS / Exfiltration Over Alternative Protocol) | `dns-tunneling-high-cardinality.yml` | Project 7 / Project 1 | No | pending |

## How this table gets filled in

Once a campaign actually runs (`attacks/run_campaign.py --execute`,
against the isolated lab only — see the isolation warning in
`../README.md`), update each row with:

- **Tested** — `Yes`, plus the campaign manifest's timestamp
  (`attacks/manifests/campaign-<timestamp>.json`).
- **Result** — one of `true_positive` (alert fired, attack ran),
  `false_negative` (attack ran, alert didn't fire), `false_positive`
  (alert fired without a matching attack in the campaign window), or
  `true_negative` (neither happened).

That four-way vocabulary is the actual point of this whole project —
Projects 1-7 could never produce it, since a static one-time capture
has no controlled ground truth to score a detection against. A
detection documented in `07-detection-as-code/README.md` as "fires on
this pattern" is a claim about SPL syntax; a row in this table marked
`true_positive` with a manifest link is a claim about measured
behavior, and this repo has been careful throughout not to blur the
two together.

See [`findings/`](./findings) for the narrative writeup once campaigns
start producing one.
