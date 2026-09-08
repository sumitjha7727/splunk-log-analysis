# Project 3: SSH Log Analysis

## Objective

Ingest a real captured SSH log into Splunk and hunt for brute-force authentication activity, unusual client/server banners (scanner fingerprinting), and unexpected outbound SSH (a sign of a compromised internal host reaching out).

## Data source

[ssh.log.gz](https://www.secrepo.com/maccdc2012/ssh.log.gz) — a Zeek/Bro SSH log from the MACCDC 2012 network capture.

## Environment

Splunk Enterprise (Docker). Sourcetype `ssh_sample` (confirmed correctly under Settings → Sourcetypes before building anything on top of it — standing practice after the FTP/HTTP naming surprises).

## Ingestion

1. Extracted `ssh.log.gz` and uploaded `ssh.log` via **Settings → Add Data → Upload**.
2. Set a custom source type via **Save As**: `ssh_sample` (this Splunk instance's "classic" Add Data wizard needs Save As to create a new custom sourcetype — the "Select Source Type" dropdown only picks existing ones).
3. Verified 7,143 events landed with `index=* sourcetype="ssh_sample" earliest=0`.

## Known limitation — `_time` is ingestion time, not event time

Same issue quietly present since Project 1: Splunk didn't recognize the `ts` field (Unix epoch, e.g. `1331901011.840000`) as a timestamp automatically (flagged on the Set Source Type preview screen with `timestamp = none`), so `_time` reflects when the file was indexed rather than the real 2012 event time. `earliest=0` in every search works around this by including everything regardless of `_time`, but it means `_time`-based sorting/analysis isn't using the real event clock. In a production Splunk deployment this would be fixed with an explicit `TIME_FORMAT`/`TIME_PREFIX` in `props.conf` for the sourcetype — noting it here as a known gap in this lab setup rather than a fixed issue.

**Second, smaller limitation:** the field sidebar shows four extra generic fields Splunk auto-named `field12`–`field15` alongside the 11 fields named during extraction, plus `resp_size`. Checked several raw events directly (expanding an event's field table) and confirmed these are consistently empty (`-`) — the tab-delimited source data has a few trailing empty columns beyond what this dataset actually populates, not a broken extraction. All 11 named fields (`ts, uid, src_ip, src_port, dest_ip, dest_port, status, direction, client, server`) populate correctly and were used throughout; the empty trailing columns don't affect any of the queries below.

## Field extraction

Used the **Interactive Field Extractor** (Delimiters, Tab) again — same method as FTP, verified across multiple sample events in the wizard before saving (checking that `status` showed real success/failure values and `client`/`server` showed real SSH version banners, not misaligned data).

Fields extracted: `ts, uid, src_ip, src_port, dest_ip, dest_port, status, direction, client, server, resp_size`

## Queries used

**1. Success vs. failure breakdown** (baseline)
```
index=* sourcetype="ssh_sample" earliest=0 | stats count by status | sort -count
```

**2. Top sources by failed attempts** (brute-force candidates)
```
index=* sourcetype="ssh_sample" earliest=0 status=failure | stats count by src_ip, dest_ip | sort -count | head 20
```

**3. Brute-force → success pattern** (headline query — repeated failures followed by a success against the same host)
```
index=* sourcetype="ssh_sample" earliest=0 | stats count(eval(status="failure")) as failures, count(eval(status="success")) as successes by src_ip, dest_ip | where failures > 5 AND successes > 0 | sort -failures
```

**4. Client banner distribution** (a long tail of unusual/exotic client banners from one source can indicate a scanning tool rather than a real user)
```
index=* sourcetype="ssh_sample" earliest=0 | stats count by client | sort -count
```

**5. Most-targeted destination hosts**
```
index=* sourcetype="ssh_sample" earliest=0 | stats count by dest_ip | sort -count | head 10
```

**6. Direction breakdown** (INBOUND vs. OUTBOUND — unexpected outbound SSH from an internal host can mean it's compromised and reaching out)
```
index=* sourcetype="ssh_sample" earliest=0 | stats count by direction | sort -count
```

## Findings

- **Brute-force → success pattern (headline finding)** — Query 3 surfaced a source/destination pair with a textbook attacker-eventually-got-in signature: `192.168.204.45` racked up **95 failed logins** against `192.168.28.203` followed by exactly **1 success**, and the same source hit `192.168.21.253` with **57 failures** before **1 success**. Two separate hosts breached by the same source after dozens of failed attempts each is the clearest "the attacker got in" evidence in this dataset — both destination hosts and the `192.168.204.45` source would justify immediate credential rotation and isolation in a real response.
- **Massive single-source brute-force campaign against one host** — `192.168.202.141` alone generated **2,365** failed SSH attempts against `192.168.229.101` (Query 2), a number so far ahead of the next-highest source/destination pair (104) that it's an outlier by more than an order of magnitude. Query 5 confirms this: `192.168.229.101` received **2,444** total SSH events — meaning virtually every SSH event ever logged against that host was this one attacker's failed-login flood. Unlike the finding above, this pair never appears in the failures>5 AND successes>0 result, meaning the flood never resulted in a logged success — a brute-force run that was noisy but, as far as this log shows, unsuccessful.
- **Active Nmap-based SSH scanning across the network** — Query 4 (client banner distribution) shows over **1,000 of the 7,143 total events (~14%)** carrying Nmap's SSH probe banners rather than a real SSH client: `SSH-2.0-Nmap-SSH2-Hostkey` (496), `SSH-1.5-Nmap-SSH1-Hostkey` (251), `SSH-1.5-NmapNSE_1.0` (249), and `SSH-2.0-Nmap-SSH2-Enum-Algos` (5). This is automated reconnaissance sweeping the network for open SSH services, distinct from (and likely preceding) the brute-force activity above.
- **Non-standard client banners spoofing OpenSSH** — also in the Query 4 breakdown, `SSH-9.9-OpenSSH_5.0` (64 events) and `SSH-1.33-OpenSSH_5.0` (62 events) don't correspond to any real OpenSSH release — actual OpenSSH version numbers never reach 9.9 or 1.33. Banners like these are a common trait of scripted/custom brute-force tooling that fakes a plausible-looking client string rather than using a genuine SSH client.
- **No outbound SSH observed** — Query 6 (direction breakdown) returned **100% INBOUND** (7,143 of 7,143 events, 0 OUTBOUND). Nothing in this capture indicates an internal host reaching out over SSH to another network — a clean negative result worth recording rather than assuming, since unexpected outbound SSH from an internal host was one of the original hunting hypotheses for this project.
- **Overall breakdown** — of all 7,143 events: **5,069 failure**, **1,773 undetermined**, and only **301 success** (Query 1). The small success count relative to the volume of scanning and brute-forcing is consistent with a network under active reconnaissance/attack where most attempts don't land.

## Alerts

Converted the headline brute-force → success finding (Query 3) into a saved Splunk alert so the pattern is flagged automatically instead of requiring a manual re-run.

**SSH Brute Force Followed by Success**
```
index=* sourcetype="ssh_sample" earliest=0 | stats count(eval(status="failure")) as failures, count(eval(status="success")) as successes by src_ip, dest_ip | where failures > 5 AND successes > 0 | sort -failures
```
- **Trigger condition:** Number of Results is greater than 0 — the query's own `where failures > 5 AND successes > 0` clause already does the filtering, so any row returned means the pattern fired.
- **Schedule:** Hourly. The underlying Sigma detection specifies a `timespan: 1h` correlation window (the failures and the eventual success must fall within the same hour); this implementation runs against the full dataset (`earliest=0`) rather than a rolling 1-hour window, because of the `_time`-is-ingestion-time limitation noted above — an approximation of the Sigma rule's intent rather than an exact match, worth calling out explicitly.
- **Trigger actions:** Add to Triggered Alerts only — no email action configured, since there's no outbound mail set up on this lab instance.
- **Permissions:** Private.
- **What it catches:** The same signature as the headline finding above — a source IP racking up more than 5 failed logins against a destination host followed by at least one success. In this dataset it fired on `192.168.204.45 → 192.168.28.203` (95 failures, 1 success) and `192.168.204.45 → 192.168.21.253` (57 failures, 1 success).

## Screenshots

- `screenshot-1787591729498.png` — ingestion verification: `index=* sourcetype="ssh_sample" earliest=0` returning all 7,143 events with real `src_ip`/`dest_ip`/`status`/`direction`/`client`/`server` values populated correctly
- `screenshot-1787591823268.png` — Query 1 result: `failure=5069, undetermined=1773, success=301`
- `screenshot-1787591840100.png` — raw Events view showing the field sidebar, including the extra generic `field12`–`field15` fields referenced in the Known Limitations section
- `screenshot-1787591925903.png` — Query 2 result: top source/destination pairs by failed attempts, headlined by `192.168.202.141 → 192.168.229.101` at 2,365 failures
- `screenshot-1787591951560.png` — Query 3 result (headline query): brute-force → success pairs, topped by `192.168.204.45 → 192.168.28.203` (95 failures, 1 success)
- `screenshot-1787591972115.png` — Query 4 result: client banner distribution, showing the Nmap scanning banners and the non-standard `SSH-9.9`/`SSH-1.33` banners
- `screenshot-1787591991061.png` — Query 5 result: top 10 destination hosts by event count, `192.168.229.101` dominating at 2,444
- `screenshot-1787592006964.png` — raw event sample confirming `field12`–`field15` and `resp_size` are consistently empty (`-`) across events
- `screenshot-1787592041187.png` — Query 6 result: direction breakdown, 100% `INBOUND`
