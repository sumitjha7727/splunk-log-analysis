# Project 8: Detection-as-Code

## Objective

Formalize the strongest findings from Projects 1-7 into standing detections, instead of one-off hunting queries: Sigma rules mapped to MITRE ATT&CK techniques, hand-translated into Splunk SPL, and wired up as real Splunk alerts where the data supports it.

## Approach

Each detection is expressed as one or more Sigma YAML files in this folder, translated into SPL, and (where applicable) saved as a scheduled Splunk alert. A note on scope: Sigma's correlation-rule feature (used below for the SSH detection) is a newer part of the spec, and `sigma-cli`'s automatic translation support for it is still uneven - so correlation rules here are documented as the conceptual detection, while the actual Splunk alert runs the hand-written SPL directly. Same principle as this whole series: real limitations get written down, not hidden.

## Environment

Same Splunk Enterprise (Docker) instance and ingested data as Projects 1-7. License check before building any alert: Settings -> Licensing showed an active Enterprise Trial (expires 2026-10-21), confirming alerting was available - Splunk Free does not support scheduled alerts.

## Detections

| # | Title | Source finding | ATT&CK | Files | Splunk alert |
|---|---|---|---|---|---|
| 1 | SSH Brute Force Followed by Success | Project 4, Query 3 | T1110, T1078 | `ssh-failed-login-threshold.yml`, `ssh-successful-login.yml`, `ssh-bruteforce-then-success.yml` | Scheduled, hourly, trigger: results > 0 |

### 1. SSH Brute Force Followed by Success

**Why this one:** Project 4's headline finding was two hosts breached after dozens of failed logins each from the same source - a textbook "the attacker got in" signature, and the clearest case in the whole portfolio for turning a hunt into a standing detection.

**Sigma modeling:** expressed as three files rather than one, because the underlying pattern is a correlation across two conditions (a failure-count threshold, then a success), not a single-event match:
- `ssh-failed-login-threshold.yml` - fires when one source/destination pair exceeds 5 failed logins in an hour.
- `ssh-successful-login.yml` - flags any successful login (broad by design; only meaningful combined with the rule above).
- `ssh-bruteforce-then-success.yml` - the correlation rule, `type: temporal_ordered`, requiring the failure-threshold rule to fire before the success rule for the same `src_ip`/`dest_ip` pair within a 1-hour window.

**SPL (what actually runs as the Splunk alert):**
```
index=* sourcetype="ssh_sample" earliest=0 | stats count(eval(status="failure")) as failures, count(eval(status="success")) as successes by src_ip, dest_ip | where failures > 5 AND successes > 0 | sort -failures
```

**Splunk alert:** `SSH Brute Force Followed by Success` - Scheduled, runs hourly (matching the correlation rule's `timespan: 1h`), trigger condition `Number of Results > 0`, action: add to Triggered Alerts (no email action configured - this lab instance has no outbound mail server set up, a deliberate scope decision rather than an oversight).

**False positives (documented per Sigma's `falsepositives` field):** a legitimate user mistyping their password several times before succeeding; automated retry logic in a monitoring or config-management tool that eventually authenticates successfully.

**Verified against:** Project 4's original finding - `192.168.204.45 -> 192.168.28.203` (95 failures, 1 success) and `192.168.204.45 -> 192.168.21.253` (57 failures, 1 success) both satisfy this detection's logic.
