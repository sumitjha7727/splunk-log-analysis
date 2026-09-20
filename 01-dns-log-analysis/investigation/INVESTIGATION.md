# Investigation: Possible DNS Tunneling — `192.168.204.71` → `auth.rssfeeds.com`

## Summary

**Verdict (updated 2026-09-18; five of the six evidence queries run for real against a live Splunk instance, the sixth blocked): weak/unconfirmed lead, evidence leans against sustained tunneling. Confidence: Low.**

All five SPL-only evidence queries (Evidence #1-5) were run for real; results are below and in `RUNBOOK.md` items 6-10. None of them support the tunneling read as strongly as the original one-line callout suggested: the host/domain pair is a narrow 118.7-second burst of 12 events (not sustained), ranks #24 of 617 network-wide by subdomain ratio (well behind a cluster of legitimate DNSBL/reputation-list domains at the very top), and its Shannon entropy (avg 2.747 bits/char) is actually *lower* than the "normal English" reference point, not in the base32/base64 range at all. The one genuinely unusual signal that survives is structural, not statistical: the literal `=` character baked into the FQDN itself (`aaaaam0+aa.=auth.rssfeeds.com`) — not valid in an ordinary hostname label — which reads more like a synthetic marker (consistent with MACCDC being a competition capture with deliberately planted indicators) than an artifact of real DNS tunneling traffic. Evidence #6 (`conn.log` correlation) remains genuinely open — the raw `conn.log` for this capture was never located — so this is not being called fully "ruled out," only downgraded from the original framing.

Project 1's baseline hunt flagged one pattern worth a dedicated pivot: from a single internal host, `192.168.204.71`, to a single external domain, `auth.rssfeeds.com`, Splunk showed repeated long, base32/base64-looking subdomains (11,189 events matched `qlen > 50` network-wide in the original run, 11,496 when re-run on the re-ingested data; this pair was the standout inside that set). Repeated high-entropy-looking subdomains from one source to one domain is a classic DNS-tunneling / C2-beaconing shape, but a shape is not a verdict — Project 1's own writeup was explicit that this was "a lead, not a confirmed conclusion," and this document exists to actually run that pivot down instead of leaving it as a one-line callout.

**Lab context, stated plainly:** this capture is the MACCDC 2012 (Mid-Atlantic Collegiate Cyber Defense Competition) network traffic — a competition capture with deliberately planted red-team activity, run against student blue-team defenders. Anything found here is a lab finding inside a known-adversarial competition environment, not a wild discovery of an active real-world compromise. That context doesn't make the technique analysis below less rigorous, but it does mean the "so what" is "this is what tunneling looks like and how you'd actually confirm it," not "this network is currently compromised."

**How the numbers in this document were produced.** This document was first written without Splunk access, with every query carrying a `RESULTS: <pending>` placeholder rather than an invented figure. On 2026-09-18 Evidence #1-5 were run against a live local Splunk instance through its REST API and the placeholders replaced with the real output; the corresponding actions are logged in [`RUNBOOK.md`](../../RUNBOOK.md) at the repo root. Evidence #6 (`conn.log` correlation) is still `RESULTS: <pending>` — the file could not be obtained.

## Timeline

**(2026-09-18, live Splunk, real `_time` values after the sourcetype-wide timestamp fix — see `RUNBOOK.md` item 18):** all 12 `auth.rssfeeds.com` events from `192.168.204.71` fall between **2012-03-17 14:19:00** and **2012-03-17 14:20:59 UTC** — a **118.7-second window**, not spread across the capture. *(Correction, 2026-09-19: an earlier version of this section gave 2012-03-16 21:59–22:00. Those times were wrong — the epoch values had been converted by hand instead of computed. The values above come from a live `stats min(_time), max(_time)`; the window's length, and everything that follows from it, is unchanged.)* This is a single narrow burst, not a sustained pattern — the weakest possible shape for a beaconing/tunneling read, per this document's own "Ruled out" candidate #3 below.

## Evidence

Six lines of evidence, each a specific technique with a specific query. All are written against `index=main sourcetype=dns_sample` (the same sourcetype and index established in the main [Project 1 README](../README.md)), scoped first to the host/domain pair in question and then, where noted, widened network-wide for comparison.

### 1. Host scoping — total queries vs. distinct queries (the cache-miss tell)

Legitimate applications resolve the same hostname repeatedly but mostly hit the OS/resolver cache — the wire only sees a new query when the TTL expires or the name is genuinely new. A tunneling client, by contrast, encodes a new payload chunk into a new subdomain on every request, so almost every query on the wire is unique: `dc(query)` approaches `count`. That gap (or lack of one) is the "cache-miss tell."

```
index=main sourcetype=dns_sample src_ip="192.168.204.71" earliest=0 latest=now
| stats count as total_queries, dc(query) as distinct_queries by src_ip, dest
| eval novelty_ratio=round(distinct_queries/total_queries, 3)
| sort -novelty_ratio
```

`RESULTS (2026-09-18, live Splunk, real data):` grouped by `dest_ip` (the query above's `dest` field is a CIM alias for `dest_ip` — see the note at the end of this document on a live FIELDALIAS quirk found during this pass), this host has two DNS-server destinations: `192.168.203.64` (18 total / 9 distinct queries, novelty_ratio **0.5**) and `192.168.207.4` (32 total / 3 distinct, novelty_ratio **0.094**). Filtering directly on `query="*auth.rssfeeds.com"` regardless of destination server: **12 total queries, 6 distinct, novelty_ratio 0.5** — a real repeat-resolution signature, not the "near 1.0, almost every query unique" pattern that would support tunneling.

### 2. Unique-subdomain ratio per parent domain, network-wide

Query 1 only tells us about this one host. This query asks the same cache-miss question network-wide, across every parent domain queried in the capture, to see where `auth.rssfeeds.com` actually ranks — a single host doing something unusual is more convincing when it's also an outlier against the rest of the network's DNS behavior, not just unusual in isolation.

```
index=main sourcetype=dns_sample earliest=0 latest=now
| rex field=query "(?<subdomain>^[^.]+)\.(?<parent_domain>.+)$"
| stats count as total_queries, dc(subdomain) as unique_subdomains by parent_domain
| where total_queries > 5
| eval subdomain_ratio=round(unique_subdomains/total_queries, 3)
| sort -subdomain_ratio
| head 20
```

`RESULTS (2026-09-18, live Splunk, real data):` 617 parent domains have more than 5 queries network-wide. The top 10 (subdomain_ratio 1.000, 7 queries each) are all legitimate DNSBL/reputation-list lookups: `spamrats.com`, `spamhaus.org`, `sorbs.net`, `spamcop.net`, `apews.org`, `quorum.to`, `tornevall.org`, `nszones.com` — exactly the expected false-positive shape called out below. `rex` splits the query as `=auth.rssfeeds.com` (see note at end of document on the literal `=` character) and `=connect.rssfeeds.com`, ranking **#24** (0.500 ratio, 12 queries, 6 distinct) and **#25** (0.500, 6 queries, 3 distinct) respectively — well back from the top of a 617-domain list, not a network-wide outlier.

### 3. Shannon entropy of the subdomain label

Primary method — via the `url_toolbox` app's `ut_shannon` macro (new dependency, per this repo's constraint on limiting new dependencies to `url_toolbox`, `sigma-cli`, and `pysigma-backend-splunk`):

```
index=main sourcetype=dns_sample query="*auth.rssfeeds.com" earliest=0 latest=now
| rex field=query "(?<subdomain>^[^.]+)\."
| `ut_shannon(subdomain)`
| stats avg(ut_shannon) as avg_entropy, max(ut_shannon) as max_entropy, count by src_ip
```

Fallback — pure SPL, for a Splunk instance without `url_toolbox` installed (per-character frequency distribution via `mvexpand`, since SPL has no built-in entropy function):

```
index=main sourcetype=dns_sample query="*auth.rssfeeds.com" earliest=0 latest=now
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

`RESULTS (2026-09-18, live Splunk, pure-SPL fallback — `url_toolbox` not installed on this instance):` `avg_entropy = 2.747`, `max_entropy = 4.408`, n=12 subdomains. **Below the "normal English" anchor (3.0-3.5), not in the base32 (4.7-5.0) or base64 (5.5-6.0) range at all.** This is lower than Project 1's original eyeball read would suggest — driven by heavy repetition of low-value characters across the 12 samples (e.g. `aaaaam0+aa`, `aaaaamzaaa`, both mostly `a`). Separately worth noting: two of the twelve subdomains (`+s4yj3z+ahnzaa`, `g/jsxf6aahnzaa`) contain `+`/`/` characters, which belong to the base64 alphabet but not base32's — so to the extent this looks encoded at all, base64 is the better-fitting guess than base32.

**interpretation anchors** (not thresholds to hard-code, but reference points for reading the result): a normal English-language hostname label typically sits around **3.0-3.5 bits/char**; base32-encoded payloads typically land around **4.7-5.0 bits/char**; base64-encoded payloads run higher, around **5.5-6.0 bits/char**. Where this sample's `avg_entropy` falls against those anchors is the actual signal — the raw base32/base64 "look" noted in Project 1 is a human eyeball read, this is the quantified version of the same observation.

### 4. Beacon timing — interval regularity and jitter

Regular, machine-timed intervals between queries (low jitter) are more consistent with an automated C2/exfil channel than with human-driven or bursty legitimate traffic.

```
index=main sourcetype=dns_sample src_ip="192.168.204.71" query="*auth.rssfeeds.com" earliest=0 latest=now
| sort 0 _time
| streamstats current=f last(_time) as prev_time
| eval delta=_time - prev_time
| stats avg(delta) as avg_interval_sec, stdev(delta) as stdev_interval_sec, count as n by src_ip
| eval jitter_ratio=round(stdev_interval_sec/avg_interval_sec, 3)
```

Cross-check as a visual timeline rather than a single aggregate figure:

```
index=main sourcetype=dns_sample src_ip="192.168.204.71" query="*auth.rssfeeds.com" earliest=0 latest=now
| timechart span=1m count
```

`RESULTS (2026-09-18, live Splunk, real data):` `avg_interval_sec = 10.79`, `stdev_interval_sec = 24.00`, `jitter_ratio = 2.225`, n=12 events, all within a 118.7-second span (see Timeline above). A `jitter_ratio` this far above the doc's own "0.3-0.5 = jittered" reference point, combined with the narrow overall window, reads as a compact burst rather than either tight beaconing or deliberately randomized C2 timing. `timechart` screenshot not captured — no way to save a rendered browser screenshot to disk with the tooling used for this pass.

A `jitter_ratio` close to 0 indicates tight, regular beaconing; a ratio climbing toward roughly 0.3-0.5 or higher suggests deliberately randomized ("jittered") timing, which is itself a known evasion technique, or simply irregular/human traffic — either way, record the actual number and the `timechart` shape rather than asserting "beacon-like" from the ratio alone.

### 5. Estimated payload volume (upper bound, not a measurement)

```
index=main sourcetype=dns_sample src_ip="192.168.204.71" query="*auth.rssfeeds.com" earliest=0 latest=now
| rex field=query "(?<subdomain>^[^.]+)\."
| eval subdomain_len=len(subdomain)
| stats sum(subdomain_len) as total_encoded_chars, count as total_queries by src_ip
| eval estimated_payload_bytes=round(total_encoded_chars*0.625, 0)
| eval estimated_payload_kb=round(estimated_payload_bytes/1024, 2)
```

`RESULTS (2026-09-18, live Splunk, real data):` `total_encoded_chars = 438`, `estimated_payload_bytes = 274`, `estimated_payload_kb = 0.27`. Trivially small even taken as a stated upper bound — consistent with a narrow burst of short-lived queries, not a meaningful exfiltration channel.

**0.625 bytes/char is the theoretical ceiling for base32** (5 bits of payload per encoded character, ÷ 8 bits/byte), used here as a stated upper bound on possible exfil volume, not a measured transfer size. Real-world efficiency is normally lower once sequence numbers, session identifiers, and protocol framing baked into the subdomain are accounted for — this number tells us "at most how much," not "exactly how much."

### 6. `conn.log` correlation via Zeek `uid` — is DNS the only egress path?

**Data-availability note, stated honestly rather than skipped over:** Project 1 through Project 6 in this repo ingested six specific Zeek/Bro log types (`dns_sample`, `ftp_sample`, `ssh_sample`, `tunnel_sample`, `smtp_sample`, `dhcp_sample`) — Zeek's general-purpose `conn.log` was never ingested as its own sourcetype. The MACCDC 2012 capture does include a `conn.log`, so this correlation is possible, but it requires a new ingestion step first. That step is logged in `RUNBOOK.md` rather than assumed to already exist — this gap is itself worth noting under "Detection gap" below.

Once ingested (proposed sourcetype: `conn_sample`), the correlation query:

```
index=main sourcetype=dns_sample src_ip="192.168.204.71" query="*auth.rssfeeds.com" earliest=0 latest=now
| table uid
| join uid
    [search index=main sourcetype=conn_sample src_ip="192.168.204.71" earliest=0 latest=now]
| stats count by proto, dest_port, dest_ip
```

`RESULTS: <pending>` — still blocked as of 2026-09-18. The MACCDC 2012 `conn.log` was not located during this pass (only the six original per-project raw logs, plus `dns.log`, were available locally) — if this host's only outbound traffic in the capture is DNS (port 53) to this domain, that would strengthen a tunneling read; if the same `uid`s also correlate to normal outbound TCP on other ports, the picture changes toward "chatty client with one oddly-shaped DNS pattern," not a compromised host. Genuinely open until the real `conn.log` file is obtained.

## Ruled out

**(Updated 2026-09-18, Evidence #1-5 run for real; see per-query results above.)**

- **Legitimate content-delivery or reputation-service churn.** Query 2 (network-wide subdomain ratio) exists specifically to catch this: CDN edge nodes and reputation/blocklist services (the kind already seen elsewhere in this repo's DNS findings — `*.spamrats.com`, `*.spamcop.net`, `*.dnsbl.tornevall.org`, `*.sorbs.net`) can also produce high subdomain churn per parent domain without it being tunneling. **Confirmed as the dominant pattern**: the top 10 network-wide domains by subdomain ratio are all exactly this shape, and `auth.rssfeeds.com` ranks a modest #24 of 617 behind them — this candidate doesn't rule the lead out entirely, but it does mean the domain isn't a network-wide outlier the way the original hypothesis implied.
- **A single oddly-configured but benign client.** Still open — the `conn.log` correlation (Query 6) that would confirm or rule this out never ran (data unavailable).
- **A single one-off encoded query rather than a sustained pattern.** **Confirmed**: the Timeline section above shows all 12 events in a 118.7-second window, not a sustained pattern. Per this document's own reasoning, a single anomalous burst is far weaker evidence than a sustained regular cadence — this is the strongest single reason the verdict was downgraded.

## ATT&CK mapping

- **T1071.004 — Application Layer Protocol: DNS.** Using DNS as the carrier channel itself.
- **T1048.003 — Exfiltration Over Alternative Protocol (Non-C2 Protocol).** If the payload-volume and cache-miss evidence supports it, this is exfiltration riding over DNS rather than a standard C2 channel.

Both tags are provisional pending the query results — see the matching Sigma rule, [`dns-tunneling-high-cardinality.yml`](../../07-detection-as-code/dns-tunneling-high-cardinality.yml), which carries the same two tags and is marked "Not configured - pending investigation results" in the Project 7 detections table until this document's queries are actually run.

## Response actions

Pending confirmation, in rough priority order — none of these have been taken; they're the standard next steps if the evidence above does confirm tunneling. Given the 2026-09-18 verdict downgrade, action 3 is now the most relevant one — it targets the one signal (the literal `=` in the FQDN) that the SPL evidence alone can't resolve:

1. Isolate or closely monitor `192.168.204.71` pending further triage.
2. Capture full packet data (not just Zeek-derived logs) for this host's DNS traffic to recover the actual decoded payload, if any.
3. Check `auth.rssfeeds.com`'s registration/reputation history (age, registrar, hosting) — a domain that's genuinely part of an RSS/news service should have a long, unremarkable history; a recently-registered domain squatting on a plausible-sounding name is a much stronger indicator. **Now the highest-value next step**: the actual queried name has `=` prepended directly onto the FQDN (`aaaaam0+aa.=auth.rssfeeds.com`, confirmed in the raw `dns.log` and via live Splunk — see Evidence #1/#2 above), which isn't valid in an ordinary hostname label. That's more consistent with a synthetic/lab-injected marker than with genuine attacker infrastructure, but it hasn't been checked against real domain-registration data.
4. Cross-reference this host's DHCP lease (Project 6) and any SSH/FTP activity (Projects 2-3) for other signs of compromise on the same host.

## Detection gap

This is the gap this investigation exists to close: Projects 3, 5, and 6 each turned their headline finding into a standing Sigma/SPL detection in `07-detection-as-code/`, but Project 1's DNS tunneling lead never did — until now. [`dns-tunneling-high-cardinality.yml`](../../07-detection-as-code/dns-tunneling-high-cardinality.yml) closes that gap, thresholded on the unique-subdomain ratio and mean subdomain length established by the queries above rather than on raw domain length alone (the metric Project 1's original Query 5 used, which is a weaker signal on its own — see that rule's `falsepositives` field for why raw length alone over-fires on CDN and reputation-service traffic).

The rule is added to the Project 7 detections table as row 6, marked **"Not configured - pending investigation results,"** matching the same honesty convention already used for rows 4 and 5 in that table (documented findings that aren't overstated as live alerts until the underlying groundwork is actually done). **(Updated 2026-09-18)**: Evidence #1-5 have now been run for real (see above) and the verdict downgraded — the rule stays **"Not configured"** rather than moving to either "live" or "ruled out": the evidence doesn't support promoting it to a scheduled alert, but Evidence #6 is still genuinely unresolved, so calling it ruled out would overstate what's actually known.

A second, narrower gap: the `conn.log` correlation (Evidence item 6) still can't run — `conn.log` was never located for this capture, not just never ingested. That's logged as an open action in `RUNBOOK.md` (item 11).

## Note on live-instance quirks found running these queries (2026-09-18)

Two things worth recording for anyone re-running these queries: (1) the SPL above groups by `dest` (a CIM `FIELDALIAS` for `dest_ip`) — on this repo's live Splunk instance that alias initially returned nothing at all, traced to a missing `metadata/default.meta` export declaration on `splunk-app/`, now fixed (see `splunk-app/default/README.md`, "Known gotchas"); querying `dest_ip` directly works regardless. (2) `_time` on every sourcetype, including `dns_sample`, was ingestion time rather than the real 2012 capture time before this pass — the Timeline and Evidence #4 timing results above are only meaningful because that's now fixed (`RUNBOOK.md` item 18).
