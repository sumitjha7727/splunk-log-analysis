# Investigation: Possible DNS Tunneling — `192.168.204.71` → `auth.rssfeeds.com`

## Summary

**Verdict: Unresolved lead, not a confirmed finding. Confidence: Low-to-moderate, pending the queries below.**

Project 1's baseline hunt flagged one pattern worth a dedicated pivot: from a single internal host, `192.168.204.71`, to a single external domain, `auth.rssfeeds.com`, Splunk showed repeated long, base32/base64-looking subdomains (11,189 events matched `qlen > 50` network-wide; this pair was the standout inside that set). Repeated high-entropy-looking subdomains from one source to one domain is a classic DNS-tunneling / C2-beaconing shape, but a shape is not a verdict — Project 1's own writeup was explicit that this was "a lead, not a confirmed conclusion," and this document exists to actually run that pivot down instead of leaving it as a one-line callout.

**Lab context, stated plainly:** this capture is the MACCDC 2012 (Mid-Atlantic Collegiate Cyber Defense Competition) network traffic — a competition capture with deliberately planted red-team activity, run against student blue-team defenders. Anything found here is a lab finding inside a known-adversarial competition environment, not a wild discovery of an active real-world compromise. That context doesn't make the technique analysis below less rigorous, but it does mean the "so what" is "this is what tunneling looks like and how you'd actually confirm it," not "this network is currently compromised."

**No Splunk connector is available to the tooling that produced this document.** Every query below is written to be run by a human operator against the live Splunk instance; none of the entropy values, ratios, timing figures, or event counts in this document are invented — each query carries a `RESULTS: <pending>` placeholder until it's actually executed, and the corresponding action is logged in [`RUNBOOK.md`](../../RUNBOOK.md) at the repo root.

## Timeline

Pending query execution. Once the queries below are run, this section should be filled in with the actual first-seen and last-seen timestamps for the `192.168.204.71` → `auth.rssfeeds.com` traffic, and whether it's a single burst or spread across the capture window. `RESULTS: <pending>`

## Evidence

Six lines of evidence, each a specific technique with a specific query. All are written against `index=main sourcetype=dns_sample` (the same sourcetype and index established in the main [Project 1 README](../README.md)), scoped first to the host/domain pair in question and then, where noted, widened network-wide for comparison.

### 1. Host scoping — total queries vs. distinct queries (the cache-miss tell)

Legitimate applications resolve the same hostname repeatedly but mostly hit the OS/resolver cache — the wire only sees a new query when the TTL expires or the name is genuinely new. A tunneling client, by contrast, encodes a new payload chunk into a new subdomain on every request, so almost every query on the wire is unique: `dc(query)` approaches `count`. That gap (or lack of one) is the "cache-miss tell."

```
index=main sourcetype=dns_sample src_ip="192.168.204.71" earliest=0
| stats count as total_queries, dc(query) as distinct_queries by src_ip, dest
| eval novelty_ratio=round(distinct_queries/total_queries, 3)
| sort -novelty_ratio
```

`RESULTS: <pending>` — a `novelty_ratio` near 1.0 for the `auth.rssfeeds.com` destination specifically (as opposed to this host's other DNS traffic) is what would support tunneling; a ratio well below 1.0 would suggest normal repeat resolution instead.

### 2. Unique-subdomain ratio per parent domain, network-wide

Query 1 only tells us about this one host. This query asks the same cache-miss question network-wide, across every parent domain queried in the capture, to see where `auth.rssfeeds.com` actually ranks — a single host doing something unusual is more convincing when it's also an outlier against the rest of the network's DNS behavior, not just unusual in isolation.

```
index=main sourcetype=dns_sample earliest=0
| rex field=query "(?<subdomain>^[^.]+)\.(?<parent_domain>.+)$"
| stats count as total_queries, dc(subdomain) as unique_subdomains by parent_domain
| where total_queries > 5
| eval subdomain_ratio=round(unique_subdomains/total_queries, 3)
| sort -subdomain_ratio
| head 20
```

`RESULTS: <pending>` — record where `auth.rssfeeds.com` (or `rssfeeds.com`, depending on how `rex` splits it) lands in this top-20, and what ratio the other top domains show, since some legitimate CDN/reputation-service domains will also show high subdomain churn (see "Ruled out," below).

### 3. Shannon entropy of the subdomain label

Primary method — via the `url_toolbox` app's `ut_shannon` macro (new dependency, per this repo's constraint on limiting new dependencies to `url_toolbox`, `sigma-cli`, and `pysigma-backend-splunk`):

```
index=main sourcetype=dns_sample query="*auth.rssfeeds.com" earliest=0
| rex field=query "(?<subdomain>^[^.]+)\."
| `ut_shannon(subdomain)`
| stats avg(ut_shannon) as avg_entropy, max(ut_shannon) as max_entropy, count by src_ip
```

Fallback — pure SPL, for a Splunk instance without `url_toolbox` installed (per-character frequency distribution via `mvexpand`, since SPL has no built-in entropy function):

```
index=main sourcetype=dns_sample query="*auth.rssfeeds.com" earliest=0
| rex field=query "(?<subdomain>^[^.]+)\."
| eval chars=split(subdomain, "")
| mvexpand chars
| eventstats count as total_chars by query
| stats count as char_count by query, chars, total_chars
| eval p=char_count/total_chars
| eval plogp=p * log(p, 2)
| stats sum(plogp) as neg_entropy by query
| eval shannon_entropy=round(-1*neg_entropy, 3)
| stats avg(shannon_entropy) as avg_entropy, max(shannon_entropy) as max_entropy
```

`RESULTS: <pending>` — **interpretation anchors** (not thresholds to hard-code, but reference points for reading the result): a normal English-language hostname label typically sits around **3.0-3.5 bits/char**; base32-encoded payloads typically land around **4.7-5.0 bits/char**; base64-encoded payloads run higher, around **5.5-6.0 bits/char**. Where this sample's `avg_entropy` falls against those anchors is the actual signal — the raw base32/base64 "look" noted in Project 1 is a human eyeball read, this is the quantified version of the same observation.

### 4. Beacon timing — interval regularity and jitter

Regular, machine-timed intervals between queries (low jitter) are more consistent with an automated C2/exfil channel than with human-driven or bursty legitimate traffic.

```
index=main sourcetype=dns_sample src_ip="192.168.204.71" query="*auth.rssfeeds.com" earliest=0
| sort 0 _time
| streamstats current=f last(_time) as prev_time
| eval delta=_time - prev_time
| stats avg(delta) as avg_interval_sec, stdev(delta) as stdev_interval_sec, count as n by src_ip
| eval jitter_ratio=round(stdev_interval_sec/avg_interval_sec, 3)
```

Cross-check as a visual timeline rather than a single aggregate figure:

```
index=main sourcetype=dns_sample src_ip="192.168.204.71" query="*auth.rssfeeds.com" earliest=0
| timechart span=1m count
```

`RESULTS: <pending>` — a `jitter_ratio` close to 0 indicates tight, regular beaconing; a ratio climbing toward roughly 0.3-0.5 or higher suggests deliberately randomized ("jittered") timing, which is itself a known evasion technique, or simply irregular/human traffic — either way, record the actual number and the `timechart` shape rather than asserting "beacon-like" from the ratio alone.

### 5. Estimated payload volume (upper bound, not a measurement)

```
index=main sourcetype=dns_sample src_ip="192.168.204.71" query="*auth.rssfeeds.com" earliest=0
| rex field=query "(?<subdomain>^[^.]+)\."
| eval subdomain_len=len(subdomain)
| stats sum(subdomain_len) as total_encoded_chars, count as total_queries by src_ip
| eval estimated_payload_bytes=round(total_encoded_chars*0.625, 0)
| eval estimated_payload_kb=round(estimated_payload_bytes/1024, 2)
```

`RESULTS: <pending>` — **0.625 bytes/char is the theoretical ceiling for base32** (5 bits of payload per encoded character, ÷ 8 bits/byte), used here as a stated upper bound on possible exfil volume, not a measured transfer size. Real-world efficiency is normally lower once sequence numbers, session identifiers, and protocol framing baked into the subdomain are accounted for — this number tells us "at most how much," not "exactly how much."

### 6. `conn.log` correlation via Zeek `uid` — is DNS the only egress path?

**Data-availability note, stated honestly rather than skipped over:** Project 1 through Project 6 in this repo ingested six specific Zeek/Bro log types (`dns_sample`, `ftp_sample`, `ssh_sample`, `tunnel_sample`, `smtp_sample`, `dhcp_sample`) — Zeek's general-purpose `conn.log` was never ingested as its own sourcetype. The MACCDC 2012 capture does include a `conn.log`, so this correlation is possible, but it requires a new ingestion step first. That step is logged in `RUNBOOK.md` rather than assumed to already exist — this gap is itself worth noting under "Detection gap" below.

Once ingested (proposed sourcetype: `conn_sample`), the correlation query:

```
index=main sourcetype=dns_sample src_ip="192.168.204.71" query="*auth.rssfeeds.com" earliest=0
| table uid
| join uid
    [search index=main sourcetype=conn_sample src_ip="192.168.204.71" earliest=0]
| stats count by proto, dest_port, dest_ip
```

`RESULTS: <pending>` — if this host's only outbound traffic in the capture is DNS (port 53) to this domain, that strengthens a tunneling read (DNS is the only channel this host has out, so if it's exfiltrating anything, this is how). If the same `uid`s also correlate to normal outbound TCP on other ports, the picture changes — this host may simply be a chatty client with one oddly-shaped DNS pattern mixed into otherwise ordinary traffic.

## Ruled out

Nothing is formally ruled out yet — that's the point of running the six queries above rather than stopping at Project 1's single-query lead. Candidates worth checking against the evidence once results come back:

- **Legitimate content-delivery or reputation-service churn.** Query 2 (network-wide subdomain ratio) exists specifically to catch this: CDN edge nodes and reputation/blocklist services (the kind already seen elsewhere in this repo's DNS findings — `*.spamrats.com`, `*.spamcop.net`, `*.dnsbl.tornevall.org`, `*.sorbs.net`) can also produce high subdomain churn per parent domain without it being tunneling. If `auth.rssfeeds.com` doesn't stand out meaningfully against that background, the lead weakens.
- **A single oddly-configured but benign client.** If the `conn.log` correlation (Query 6) shows this host has plenty of other normal outbound traffic, "compromised host tunneling exclusively over DNS" becomes a less likely explanation than "one misbehaving or misconfigured application."
- **A single one-off encoded query rather than a sustained pattern.** If the Timeline section (once filled in) shows this was a handful of events in a narrow window rather than a sustained pattern, the confidence in a beaconing/tunneling read should drop accordingly — a single anomalous query is far weaker evidence than a sustained regular cadence.

## ATT&CK mapping

- **T1071.004 — Application Layer Protocol: DNS.** Using DNS as the carrier channel itself.
- **T1048.003 — Exfiltration Over Alternative Protocol (Non-C2 Protocol).** If the payload-volume and cache-miss evidence supports it, this is exfiltration riding over DNS rather than a standard C2 channel.

Both tags are provisional pending the query results — see the matching Sigma rule, [`dns-tunneling-high-cardinality.yml`](../../07-detection-as-code/dns-tunneling-high-cardinality.yml), which carries the same two tags and is marked "Not configured - pending investigation results" in the Project 7 detections table until this document's queries are actually run.

## Response actions

Pending confirmation, in rough priority order — none of these have been taken; they're the standard next steps if the evidence above does confirm tunneling:

1. Isolate or closely monitor `192.168.204.71` pending further triage.
2. Capture full packet data (not just Zeek-derived logs) for this host's DNS traffic to recover the actual decoded payload, if any.
3. Check `auth.rssfeeds.com`'s registration/reputation history (age, registrar, hosting) — a domain that's genuinely part of an RSS/news service should have a long, unremarkable history; a recently-registered domain squatting on a plausible-sounding name is a much stronger indicator.
4. Cross-reference this host's DHCP lease (Project 6) and any SSH/FTP activity (Projects 2-3) for other signs of compromise on the same host.

## Detection gap

This is the gap this investigation exists to close: Projects 3, 5, and 6 each turned their headline finding into a standing Sigma/SPL detection in `07-detection-as-code/`, but Project 1's DNS tunneling lead never did — until now. [`dns-tunneling-high-cardinality.yml`](../../07-detection-as-code/dns-tunneling-high-cardinality.yml) closes that gap, thresholded on the unique-subdomain ratio and mean subdomain length established by the queries above rather than on raw domain length alone (the metric Project 1's original Query 5 used, which is a weaker signal on its own — see that rule's `falsepositives` field for why raw length alone over-fires on CDN and reputation-service traffic).

The rule is added to the Project 7 detections table as row 6, marked **"Not configured - pending investigation results,"** matching the same honesty convention already used for rows 4 and 5 in that table (documented findings that aren't overstated as live alerts until the underlying groundwork is actually done) — in this case, until the queries in this document are actually run and their results support (or rule out) the tunneling read.

A second, narrower gap: the `conn.log` correlation (Evidence item 6) can't run at all until `conn.log` is ingested as a new sourcetype — that ingestion step itself doesn't exist yet anywhere in this repo's six original projects, and is logged as a prerequisite action in `RUNBOOK.md`.
