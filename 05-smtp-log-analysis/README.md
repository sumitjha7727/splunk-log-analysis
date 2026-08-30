# Project 5: SMTP Log Analysis

## Objective

Hunt for SMTP-based threats in a real network capture — reconnaissance/vulnerability scanning against mail servers, command-injection-style probes in SMTP envelope fields, and protocol anomalies that suggest scripted/automated traffic rather than genuine mail clients.

## Data source

[smtp.log.gz](https://www.secrepo.com/maccdc2012/smtp.log.gz) — a Zeek/Bro SMTP log from the MACCDC 2012 network capture.

## Environment

Splunk Enterprise (Docker). Sourcetype `smtp_sample` (verified under Settings → Sourcetypes immediately after upload, per standing practice).

## Ingestion

1. Extracted `smtp.log.gz` and uploaded `smtp.log` (35KB) via **Settings → Add Data → Upload**.
2. Set a custom source type via **Save As**: `smtp_sample`.
3. Verified 194 events landed with `index=* sourcetype="smtp_sample" earliest=0`.

## Known limitations

**`_time` is ingestion time, not event time.** Same issue present since Project 1: Splunk didn't recognize the `ts` field (Unix epoch, e.g. `1332014962.270000`) as a timestamp automatically, so `_time` reflects when the file was indexed rather than the real 2012 event time. `earliest=0` in every search works around this. Worth noting because it's visible directly in the raw event data below — timestamps that read `2026-08-27` are `_time` (indexing time), while `ts` (in the payload) is the real 2012 epoch value.

**Field extraction wizard silently mis-mapped 13 of 25 columns on this wide schema (the differentiator bug for this project).** This dataset's Zeek `smtp.log` schema is 25 tab-separated fields — noticeably wider than any prior project in this series (`ts, uid, src_ip, src_port, dest_ip, dest_port, trans_depth, helo, mailfrom, rcptto, date, from, to, cc, reply_to, msg_id, in_reply_to, subject, x_originating_ip, first_received, last_reply, path, user_agent, fuids, is_webmail` — this MACCDC-2012 capture's Zeek version is missing the modern `second_received` and `tls` fields present in newer Zeek releases). Using the Interactive Field Extractor (Delimiters → Tab) and manually renaming 25 columns one at a time, two mistakes crept in during the click-through: **`ts`** (column 1) was left completely unnamed, and the entire **`helo` through `first_received`** block (columns 8–20, 13 fields) was left as Splunk's generic auto-generated defaults (`field8` ... `field20`) instead of being renamed.

This wasn't obvious at first — the extraction *looked* saved and complete, and queries built on the correctly-named columns (`src_ip`, `dest_ip`, `dest_port`, `last_reply`, etc. — columns 2–7 and 21–25) worked fine. It only surfaced when two queries filtering on `helo`/`mailfrom`/`rcptto` (the scanner-signature and injection-probe hunts) returned **0 events**, despite the raw log clearly containing matching values on manual inspection. Expanding a raw event's field table confirmed the diagnosis directly: `ts` missing, `field8` through `field20` present instead of their real names.

**Fix:** deleted the broken extraction and replaced it with a manual regex-based Field Extraction (Settings → Fields → Field Extractions → New, Type = Inline), defining all 25 named capture groups in a single paste instead of 25 individual wizard clicks:

```
^(?<ts>[^\t]+)\t(?<uid>[^\t]+)\t(?<src_ip>[^\t]+)\t(?<src_port>[^\t]+)\t(?<dest_ip>[^\t]+)\t(?<dest_port>[^\t]+)\t(?<trans_depth>[^\t]+)\t(?<helo>[^\t]+)\t(?<mailfrom>[^\t]+)\t(?<rcptto>[^\t]+)\t(?<date>[^\t]+)\t(?<from>[^\t]+)\t(?<to>[^\t]+)\t(?<cc>[^\t]+)\t(?<reply_to>[^\t]+)\t(?<msg_id>[^\t]+)\t(?<in_reply_to>[^\t]+)\t(?<subject>[^\t]+)\t(?<x_originating_ip>[^\t]+)\t(?<first_received>[^\t]+)\t(?<last_reply>[^\t]+)\t(?<path>[^\t]+)\t(?<user_agent>[^\t]+)\t(?<fuids>[^\t]+)\t(?<is_webmail>.+)$
```

Verified working via `| table ts helo mailfrom rcptto last_reply | head 5` showing real values in every column, then confirmed the two previously-broken queries returned real results.

**Takeaway:** the Interactive Field Extractor is reliable for narrow schemas (it's what every other project in this series uses successfully), but on a 25-column schema it's easy to mis-click or skip a field without any error or warning — the extraction "completes" successfully either way. A one-paste regex mapping is more auditable and more reliable for wide schemas: the whole mapping is visible and reviewable at once, instead of trusting 25 sequential wizard interactions.

## Field extraction

Manual regex-based Field Extraction (see above), sourcetype `smtp_sample`, Type = Inline.

Fields extracted (25): `ts, uid, src_ip, src_port, dest_ip, dest_port, trans_depth, helo, mailfrom, rcptto, date, from, to, cc, reply_to, msg_id, in_reply_to, subject, x_originating_ip, first_received, last_reply, path, user_agent, fuids, is_webmail`

## Queries used

**1. Top talkers by source IP** (baseline)
```
index=* sourcetype="smtp_sample" earliest=0 | stats count by src_ip | sort -count
```

**2. Most-contacted destination hosts**
```
index=* sourcetype="smtp_sample" earliest=0 | stats count by dest_ip | sort -count
```

**3. SMTP reply code breakdown**
```
index=* sourcetype="smtp_sample" earliest=0 | rex field=last_reply "^(?<reply_code>\d{3})" | stats count by reply_code | sort -count
```

**4. Suspicious MAIL FROM / RCPT TO** (command-injection-style probes)
```
index=* sourcetype="smtp_sample" earliest=0 (rcptto="*|*" OR rcptto="*;*" OR rcptto="*\"*" OR mailfrom="*|*" OR mailfrom="*;*") | table _time src_ip dest_ip helo mailfrom rcptto last_reply | sort _time
```

**5. Known vulnerability-scanner signatures** (headline query — HELO fingerprinting)
```
index=* sourcetype="smtp_sample" earliest=0 (helo="*nmap*" OR helo="*nessus*") | stats count by src_ip, helo, dest_ip | sort -count
```

## Findings

- **A single host is running both reconnaissance and active exploitation-style probing (headline finding)** — `192.168.202.110` generated **111 of the 194 total events (~57%)**, by far the most active source (Query 1). Cross-referencing Queries 4 and 5 shows this isn't just volume: it's the same host behind both the concentrated Nessus-style scanning *and* 10 of the 11 command-injection probes below — a single internal or compromised host running reconnaissance and active testing against the network, not two unrelated actors.
- **Live command-injection probes against SMTP envelope fields** — Query 4 found 11 events with `rcptto` set to `root+:"|sleep 5 #"`, a classic blind shell/command-injection probe (testing whether a mail relay passes the recipient address to a shell and executes `sleep 5` to detect command execution via timing). `mailfrom` was spoofed as `<root@[source-ip]>` in every case. Response codes split three ways: **7 of 11 destinations returned `250 2.1.5 Ok`** — accepting the malformed address without rejecting it, a real hardening gap worth flagging — **2 returned `451 4.3.0` temporary failure**, and **1 returned `501 5.5.4 Invalid Address`** (the only destination that correctly rejected it outright).
- **Two distinct scanning patterns, two different tools** — Query 5 (51 events) shows Nmap's SMTP script (`nmap.scanme.org` HELO) fired from `192.168.202.79`, `.100`, and `.108`, each touching a *different* destination once — a broad one-shot sweep pattern typical of a network-wide port/service scan. Separately, `192.168.202.110` sent Nessus's fingerprint HELO strings (`mail.nessus.org` and bare `nessus`) *repeatedly* against a smaller set of hosts (two separate hits each against `192.168.22.102`) — a more concentrated, vulnerability-scanner-style pattern rather than a one-off sweep.
- **A meaningful share of traffic is malformed or out-of-sequence SMTP, not real mail** — Query 3's reply-code breakdown shows `502` (Command not recognized, 31 events) and `503` (Bad sequence of commands, 13 events) together account for **44 of 194 events (~23%)** — the 3rd and 4th most common codes overall, behind only `221` (Bye, 79) and `250` (Ok, 49). That volume of protocol-violation responses is consistent with scripted/automated tooling issuing commands out of order or unsupported by the target, rather than genuine mail clients.
- **No single mail server was the focus — this looks like network-wide reconnaissance** — Query 2's top destination (`192.168.22.102`) accounts for only 24 of 194 events (~12%), and the top 5 destinations are fairly close in count rather than one host dominating. Combined with the scanning findings above, the picture is broad reconnaissance across many hosts rather than a targeted attack on one mail server.
- **Overall breakdown** — 194 total events, 11 unique source IPs, 20 unique destination IPs, 12 distinct SMTP reply codes observed.

## Alerts

Split the headline scanner-signature finding (Query 5) into two saved Splunk alerts, one per tool, since Nmap and Nessus each have a distinct HELO fingerprint and a visibly different scanning pattern worth tracking separately (a broad one-shot sweep vs. a concentrated repeat-hit pattern).

**SMTP Nmap Scan Signature (HELO Fingerprint)**
```
index=* sourcetype="smtp_sample" earliest=0 helo="*nmap*"
```
- **Trigger condition:** Number of Results is greater than 0 — the query already filters on the Nmap HELO string, so any row returned means the pattern fired.
- **Schedule:** Hourly — no correlation window to match here, so hourly is just a reasonable default cadence.
- **Trigger actions:** Add to Triggered Alerts only — no email action, since there's no outbound mail configured on this lab instance.
- **Permissions:** Private.
- **What it catches:** Nmap's SMTP script identifying itself via the `nmap.scanme.org` HELO string. In this dataset it fired from `192.168.202.79`, `.100`, and `.108`, each touching a different destination once — a broad, network-wide sweep pattern.

**SMTP Nessus Scan Signature (HELO Fingerprint)**
```
index=* sourcetype="smtp_sample" earliest=0 helo="*nessus*"
```
- **Trigger condition:** Number of Results is greater than 0 — same logic, filtering on the Nessus HELO string.
- **Schedule:** Hourly, same reasoning as the Nmap alert.
- **Trigger actions:** Add to Triggered Alerts only.
- **Permissions:** Private.
- **What it catches:** Nessus's fingerprint HELO strings (`mail.nessus.org` and bare `nessus`). In this dataset it fired from `192.168.202.110`, hitting a smaller set of hosts repeatedly (two separate hits each against `192.168.22.102`) — a more concentrated, vulnerability-scanner-style pattern rather than a one-off sweep, and the same host responsible for the command-injection probes in the finding above.

## Screenshots

- `screenshot-1787828086665.png` — post-fix ingestion check: raw Events view (`index=* sourcetype="smtp_sample" earliest=0`, 194 events) confirming the corrected sourcetype and event count after the field-extraction fix
- `screenshot-1787828126892.png` — Query 1 result: top talkers by `src_ip`, headlined by `192.168.202.110` at 111 events
- `screenshot-1787828147273.png` — Query 2 result: most-contacted destination hosts
- `screenshot-1787828179545.png` — Query 3 result: SMTP reply code breakdown (`221`, `250`, `502`, `503`, etc.)
- `screenshot-1787829530517.png` — Query 4 result: the 11 command-injection-style `rcptto`/`mailfrom` probes, with mixed `250`/`451`/`501` responses
- `screenshot-1787829559370.png` — Query 5 result: Nmap/Nessus scanner HELO signatures by source, HELO string, and destination
