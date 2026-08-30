# Project 7: Detection-as-Code

## Objective

Formalize the strongest findings from Projects 1-6 into standing detections, instead of one-off hunting queries: Sigma rules mapped to MITRE ATT&CK techniques, hand-translated into Splunk SPL, and wired up as real Splunk alerts where the data supports it.

## Approach

Each detection is expressed as one or more Sigma YAML files in this folder, translated into SPL, and (where applicable) saved as a scheduled Splunk alert. A note on scope: Sigma's correlation-rule feature (used below for the SSH detection) is a newer part of the spec, and `sigma-cli`'s automatic translation support for it is still uneven - so correlation rules here are documented as the conceptual detection, while the actual Splunk alert runs the hand-written SPL directly. Same principle as this whole series: real limitations get written down, not hidden. That includes the two detections below that don't (yet) have a Splunk alert behind them - they're documented as findings-turned-Sigma-rules, not overstated as "live" when they aren't.

## Environment

Same Splunk Enterprise (Docker) instance and ingested data as Projects 1-6. License check before building any alert: Settings -> Licensing showed an active Enterprise Trial (expires 2026-10-21), confirming alerting was available - Splunk Free does not support scheduled alerts.

## Detections

| # | Title | Source finding | ATT&CK | Files | Splunk alert |
|---|---|---|---|---|---|
| 1 | SSH Brute Force Followed by Success | Project 3, Query 3 | T1110, T1078 | `ssh-failed-login-threshold.yml`, `ssh-successful-login.yml`, `ssh-bruteforce-then-success.yml` | Scheduled, hourly, trigger: results > 0 |
| 2 | SMTP Nmap Scan Signature (HELO Fingerprint) | Project 5, Query 5 | T1595, T1046 | `nmap-scan-signature.yml` | Scheduled, hourly, trigger: results > 0 |
| 3 | SMTP Nessus Scan Signature (HELO Fingerprint) | Project 5, Query 5 | T1595 | `nessus-scan-signature.yml` | Scheduled, hourly, trigger: results > 0 |
| 4 | SMTP Command-Injection Probe in Envelope Fields | Project 5, Query 4 | T1190 | `smtp-injection-probe.yml` | Not configured - documented finding only (see below) |
| 5 | DHCP Lease Pool Dominated by a Single Host | Project 6, Known limitations | - (deliberately untagged, see below) | `dhcp-lease-anomaly.yml` | Not configured - informational only (see below) |
| 6 | DNS Tunneling via High-Cardinality Subdomains | Project 1, Findings | T1071.004, T1048.003 | `dns-tunneling-high-cardinality.yml` | Not configured - pending investigation results (see below) |

### 1. SSH Brute Force Followed by Success

**Why this one:** Project 3's headline finding was two hosts breached after dozens of failed logins each from the same source - a textbook "the attacker got in" signature, and the clearest case in the whole portfolio for turning a hunt into a standing detection.

**Sigma modeling:** expressed as three files rather than one, because the underlying pattern is a correlation across two conditions (a failure-count threshold, then a success), not a single-event match:
- `ssh-failed-login-threshold.yml` - fires when one source/destination pair exceeds 5 failed logins in an hour.
- `ssh-successful-login.yml` - flags any successful login (broad by design; only meaningful combined with the rule above).
- `ssh-bruteforce-then-success.yml` - the correlation rule, `type: temporal_ordered`, requiring the failure-threshold rule to fire before the success rule for the same `src_ip`/`dest_ip` pair within a 1-hour window.

**SPL (what actually runs as the Splunk alert):**
```
index=main sourcetype="ssh_sample" earliest=-1h latest=now | stats count(eval(status="failure")) as failures, count(eval(status="success")) as successes by src_ip, dest_ip | where failures > 5 AND successes > 0 | sort -failures
```

**Search window:** `earliest=-1h latest=now`, matching the correlation rule's declared `timespan: 1h` and the alert's hourly schedule. This was previously `earliest=0`, which rescans the entire index on every run - against a static one-time capture that means re-matching the same already-alerted brute-force pairs every single hour, forever. The window has to equal the correlation timespan, or the SPL alert and the Sigma rule it claims to implement silently drift apart.

**Splunk alert:** `SSH Brute Force Followed by Success` - Scheduled, runs hourly (matching the correlation rule's `timespan: 1h`), trigger condition `Number of Results > 0`, action: add to Triggered Alerts (no email action configured - this lab instance has no outbound mail server set up, a deliberate scope decision rather than an oversight).

**False positives (documented per Sigma's `falsepositives` field):** a legitimate user mistyping their password several times before succeeding; automated retry logic in a monitoring or config-management tool that eventually authenticates successfully.

**Verified against:** Project 3's original finding - `192.168.204.45 -> 192.168.28.203` (95 failures, 1 success) and `192.168.204.45 -> 192.168.21.253` (57 failures, 1 success) both satisfy this detection's logic.

### 2. SMTP Nmap Scan Signature (HELO Fingerprint)

**Why this one:** Project 5's Query 5 turned up two distinct scanner fingerprints hiding in the `helo` field instead of a real mail-client hostname. This one is Nmap's SMTP script announcing itself via `nmap.scanme.org` - a broad, network-wide sweep pattern rather than a targeted probe, and cheap to detect reliably since the fingerprint string never varies.

**Sigma modeling:** a single-event match - `helo|contains: 'nmap'` - deliberately not scoped to any one source, since the pattern's signature is *breadth* (many sources, one hit each) rather than repetition from one host.

**SPL (what actually runs as the Splunk alert):**
```
index=main sourcetype="smtp_sample" earliest=-1h latest=now helo="*nmap*"
```

**Search window:** `earliest=-1h latest=now`, matching the alert's hourly schedule. This was previously `earliest=0`, which rescans the entire index on every run - against a static capture that means re-alerting on the same three hosts every hour, forever, instead of firing once per genuinely new event in the window.

**Splunk alert:** `SMTP Nmap Scan Signature (HELO Fingerprint)` - Scheduled, hourly (no correlation window to match, so hourly is just a reasonable default cadence), trigger condition `Number of Results > 0`, action: add to Triggered Alerts only, permissions private.

**False positives (documented per Sigma's `falsepositives` field):** an authorized internal vulnerability-scanning or network-inventory process using Nmap's SMTP script as part of routine scanning.

**Verified against:** Project 5's original finding - fired from three separate internal hosts (`192.168.202.79`, `.100`, `.108`), each touching a different destination once, consistent with a broad sweep rather than a targeted mail client.

### 3. SMTP Nessus Scan Signature (HELO Fingerprint)

**Why this one:** The second scanner fingerprint from the same Query 5 - Nessus's vulnerability-scanner HELO strings (`mail.nessus.org` or bare `nessus`). Split into its own rule rather than folded into the Nmap one because the two tools produce visibly different traffic patterns worth tracking separately: this one is a concentrated, repeat-hit pattern from a single source rather than a one-shot sweep.

**Sigma modeling:** single-event match - `helo|contains: 'nessus'`.

**SPL (what actually runs as the Splunk alert):**
```
index=main sourcetype="smtp_sample" earliest=-1h latest=now helo="*nessus*"
```

**Search window:** `earliest=-1h latest=now`, matching the alert's hourly schedule, for the same reason as the Nmap detection above - a hardcoded `earliest=0` on an hourly schedule re-fires on the same historical hits indefinitely rather than only alerting on genuinely new activity.

**Splunk alert:** `SMTP Nessus Scan Signature (HELO Fingerprint)` - Scheduled, hourly, same reasoning as the Nmap alert, trigger condition `Number of Results > 0`, action: add to Triggered Alerts only, permissions private.

**False positives (documented per Sigma's `falsepositives` field):** an authorized internal vulnerability-management scan (e.g. a scheduled Nessus/Tenable scan against the mail server) using its default HELO string.

**Verified against:** Project 5's original finding - fired from a single source, `192.168.202.110`, hitting a smaller set of hosts repeatedly (two separate hits each against `192.168.22.102`) - the same host also responsible for the command-injection probes below, which is what elevates this from routine noise to worth a standing alert.

### 4. SMTP Command-Injection Probe in Envelope Fields

**Why this one:** Project 5's Query 4 found the sharpest finding in the whole SMTP hunt - shell metacharacters planted in the `RCPT TO` / `MAIL FROM` envelope fields, a classic blind command-injection probe. It's documented here as a Sigma rule and SPL translation, but deliberately **not yet wired up as a live Splunk alert** - it's included as a finding worth standing detection, not overstated as one already running.

**Sigma modeling:** two selections combined with `1 of selection_*`, since the injection attempt can show up in either envelope field independently: `rcptto` checked for pipe, semicolon, or embedded quote; `mailfrom` checked for pipe or semicolon.

**SPL (translation, not yet scheduled):**
```
index=main sourcetype="smtp_sample" earliest=0 (rcptto="*|*" OR rcptto="*;*" OR rcptto="*\"*" OR mailfrom="*|*" OR mailfrom="*;*")
```

**Search window:** `earliest=0` is kept here deliberately, unlike the three scheduled alerts above. There is no live schedule for this query to match a window against - see "Why no alert yet" below - so a relative window would just mean the query silently returns nothing, which is worse than an honest full-range search over a static capture. If this is ever wired up as a real scheduled alert, the window has to be set then, matching whatever cadence is chosen at that point.

**Why no alert yet:** the underlying finding was a fixed, already-occurred set of 11 events in a static capture, not an ongoing feed - there's nothing left in this lab dataset for a schedule to catch going forward. The rule is written and ready; standing it up as a real alert is the natural next step if this were pointed at live mail traffic instead of a one-time capture.

**False positives (documented per Sigma's `falsepositives` field):** a legitimate email address or display name that happens to contain a semicolon or quote character (rare, but technically valid in some address formats).

**Verified against:** Project 5's original finding - 11 events with `rcptto` set to `root+:"|sleep 5 #"` and `mailfrom` spoofed as `<root@[source-ip]>`; 7 of 11 destinations returned `250 Ok`, accepting the malformed address without rejecting it.

### 5. DHCP Lease Pool Dominated by a Single Host

**Why this one, and why it's different from the rest:** every other detection in this folder maps to a MITRE ATT&CK technique - this one deliberately doesn't. Project 6's headline finding (a single MAC address responsible for roughly half of all DHCP traffic in the capture) is the signature of a boot-looping or misconfigured device, not a mapped adversary technique. Forcing an ATT&CK tag onto an operational anomaly would misrepresent what this actually detects, so the Sigma rule is tagged `level: informational` with no `tags:` field at all.

**Sigma modeling:** single-event match, counting by `mac` over a 24-hour window: `selection | count() by mac > 20`.

**SPL (translation, not yet scheduled):**
```
index=main sourcetype="dhcp_sample" earliest=0 | stats count by mac | where count > 20
```

**Search window:** `earliest=0` is kept here for the same reason as the command-injection detection above - this one is explicitly informational and unscheduled (see the threshold note below), so there is no schedule cadence for a relative window to match. Forcing one on would just make the query permanently return nothing rather than reflect an honest full-capture view.

**Threshold note - carried over from Project 6's own findings, not glossed over:** Project 6 documented a severe Splunk line-breaking bug that undercounts DHCP events - the true top host issued 744 of 1,502 real records, but Splunk's own indexed view only ever showed 41 for its visible top host. Since this detection queries that same buggy indexed data, the threshold above (>20) is calibrated against what Splunk can actually see, not the true count. A real deployment would fix the ingestion line-breaking issue before trusting any count-based threshold on this sourcetype - which is also why this one stays informational and unscheduled rather than promoted to a live alert on top of known-bad counts.

**False positives (documented per Sigma's `falsepositives` field):** a DHCP relay or gateway device that legitimately renews leases on behalf of many downstream clients; a single busy access point or NAT device generating high normal lease-renewal volume.

**Verified against:** Project 6's raw-file cross-check - MAC `00:26:9e:83:a2:30` (assigned `192.168.202.76`) issued 744 of 1,502 real DHCP records (49.5% of all traffic), invisible in Splunk's own `stats count by mac` output because the line-breaking bug folded nearly all of its requests into a handful of merged events.

### 6. DNS Tunneling via High-Cardinality Subdomains

**Why this one, and why it's different from the rest:** every other detection in this folder was confirmed and promoted the same day it was found. This one is different on purpose - Project 1's original hunt flagged repeated long, base32/base64-looking subdomains from a single host (`192.168.204.71`) to a single domain (`auth.rssfeeds.com`) as a DNS-tunneling *lead*, explicitly not a confirmed finding, and left it there rather than overstating it. Projects 3, 5, and 6 each turned their headline finding straight into a detection; Project 1's never did, until now. The full pivot - six specific techniques, each with a query and a `RESULTS: <pending>` placeholder - lives in [`01-dns-log-analysis/investigation/INVESTIGATION.md`](../01-dns-log-analysis/investigation/INVESTIGATION.md), since a proper writeup didn't fit in a table row.

**Sigma modeling:** thresholded on the unique-subdomain ratio per parent domain (native Sigma aggregation: `count(distinct(query)) by src_ip, parent_domain > 15` within a 1-hour window) combined, at the SPL-translation layer, with a mean-subdomain-length check - not on raw domain length alone, which is what Project 1's original ad-hoc query used and which over-fires on legitimately long subdomains from CDN edge nodes and reputation/AV services. Same "documented as the conceptual detection, hand-translated to SPL" pattern already used for the SSH correlation rule above, because a single native Sigma aggregation condition can't cleanly express two independent thresholds combined.

**SPL (translation, not yet scheduled - and not yet validated against real query results):**
```
index=main sourcetype="dns_sample" earliest=0 | rex field=query "(?<subdomain>^[^.]+)\.(?<parent_domain>.+)$" | eval subdomain_length=len(subdomain) | stats dc(query) as unique_subdomains, avg(subdomain_length) as mean_subdomain_length, count as total_queries by src_ip, parent_domain | where unique_subdomains > 15 AND mean_subdomain_length > 35
```

**Search window:** `earliest=0` is kept here deliberately, same reasoning as detections 4 and 5 above - there is no live schedule yet for this query to match a window against, and the actual threshold values (`15`, `35`) are placeholders pending the investigation's real results, not calibrated figures yet. Forcing a relative window on an unvalidated, unscheduled query would just add a second layer of guesswork on top of the first.

**Why no alert yet:** unlike detections 4 and 5, which are finished findings simply not wired to a live schedule, this one is genuinely incomplete - the thresholds above haven't been checked against actual query output yet. [`RUNBOOK.md`](../RUNBOOK.md) lists the six queries that need to be run first; this detection moves from "pending investigation results" to either a real scheduled alert or a documented ruled-out finding once they are.

**False positives (documented per Sigma's `falsepositives` field):** reputation/AV lookup services generating high subdomain churn against one parent domain (e.g. McAfee GTI, Sophos XL, Spamhaus, SORBS); per-object CDN hostnames, where each cached asset or edge node gets its own long, varied subdomain under one parent domain; a legitimate dynamic-DNS or IoT device-provisioning service issuing unique per-device subdomains under one parent domain.

**Verified against:** not yet - see `INVESTIGATION.md` and `RUNBOOK.md`. This row stays "Not configured - pending investigation results" until those queries actually run.
