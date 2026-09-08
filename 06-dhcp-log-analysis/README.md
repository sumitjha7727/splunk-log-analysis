# Project 6: DHCP Log Analysis

## Objective

Hunt for anomalies in DHCP lease activity — hosts dominating the lease pool, address-assignment conflicts, and roaming/multi-lease behavior — that could indicate a misconfigured device, a boot-looping host, or something worth a closer look.

## Data source

[dhcp.log.gz](https://www.secrepo.com/maccdc2012/dhcp.log.gz) — a Zeek/Bro DHCP log from the MACCDC 2012 network capture, using the older Bro-era 10-field schema (`ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, mac, assigned_ip, lease_time, trans_id`).

## Environment

Splunk Enterprise (Docker). Sourcetype `dhcp_sample`.

## Ingestion

1. Extracted `dhcp.log.gz` and uploaded `dhcp.log` (185KB) via **Settings → Add Data → Upload**.
2. Set a custom source type via **Save As**: `dhcp_sample`.
3. Initial verification: `index=* sourcetype="dhcp_sample" earliest=0` returned **333 events**.

## Known limitation — a severe line-breaking bug, caught and quantified against the raw file

**This is the most significant data-quality bug found across this entire project series.** The raw `dhcp.log` file has **1,502 lines** — every one a clean, uniformly-formatted 10-column tab-separated record with a leading Unix-epoch timestamp, confirmed directly (`wc -l`, tab-count check, and a leading-timestamp check all ran clean against the source file). But Splunk only indexed **333 events** from it — fewer than 1 in 4 of the real records.

The raw Events view makes the cause visible directly: individual indexed "events" contain multiple real DHCP lines glued together — one event bundles 8 separate real lines, another 4, another 2, with the group size varying unpredictably. This is Splunk's default line-breaking failing to reliably recognize where each real event starts. The same root cause has been a "known limitation" on every project in this series (Splunk not auto-recognizing the epoch `ts` field as a real timestamp during upload) — but on every prior project that only meant `_time` was wrong. Here, because Splunk had no reliable timestamp anchor to detect "a new event starts here," it fell back to an inconsistent heuristic that merged some batches of consecutive lines into single events.

**A second-order effect:** the field extraction's final capture group (`trans_id`, using `.+` to the end of the line) is greedy, so on a merged event it swallows everything after the first record's `trans_id` — including the additional real lines bundled into that same event. This is why some `table` results showed extra timestamps and IPs bleeding into the `trans_id` column instead of a clean numeric value.

**Impact — measured, not estimated.** Because `stats count by X` counts indexed events, not real records, every merged event hides its extra bundled records from any count-based query. I cross-checked Splunk's SPL results directly against the raw file to quantify exactly how much this distorted the picture:

| Metric | Splunk (as queried) | True (raw file) |
|---|---|---|
| Total DHCP records | 333 | **1,502** |
| Unique assigned IPs | 64 | **99** |
| Unique MAC addresses | 57 | **87** |
| Top MAC's request count | 41 (`08:11:96:8d:be:84`) | **744** (`00:26:9e:83:a2:30`) |
| MACs with >1 assigned IP | 7 | **10** |
| Lease-type split (0s / 86400s) | 131 / 202 | **1,136 / 366** |

The most striking gap: the single most active host on the network by a huge margin, `00:26:9e:83:a2:30`, doesn't even appear in Splunk's own top-count results — because nearly all 744 of its requests were folded into a handful of merged events that each counted as "1." A bug that looks like a cosmetic under-count in the event total actually erased the dataset's single biggest finding from view.

**I chose not to re-ingest** the file with a corrected line-breaker setting, to keep this documented rather than fixed away — same choice made on the Tunnel project when its own data-quality bug turned up. Instead, the findings below report the Splunk-query view (documented as such) alongside the true picture, verified directly against the raw source file the same way the Tunnel project's Query 6 gap was caught: by manually cross-checking raw data rather than trusting a query's output at face value.

## Field extraction

Manual regex-based Field Extraction, sourcetype `dhcp_sample`, Type = Inline:

```
^(?<ts>[^\t]+)\t(?<uid>[^\t]+)\t(?<src_ip>[^\t]+)\t(?<src_port>[^\t]+)\t(?<dest_ip>[^\t]+)\t(?<dest_port>[^\t]+)\t(?<mac>[^\t]+)\t(?<assigned_ip>[^\t]+)\t(?<lease_time>[^\t]+)\t(?<trans_id>.+)$
```

Fields extracted (10): `ts, uid, src_ip, src_port, dest_ip, dest_port, mac, assigned_ip, lease_time, trans_id` (`src_ip`/`src_port` = DHCP client, `dest_ip`/`dest_port` = DHCP server).

**Note on this extraction's own history:** the first attempt was accidentally saved as a "Uses transform" extraction (`REPORT-dhcp_sample_fields`) instead of "Inline" — Splunk tried to resolve a transform stanza that was never created, producing inconsistent partial extraction (some fields populated, others blank, plus orphaned single-field rows). Caught by checking the extraction's saved stanza name directly, deleted, and recreated as a proper Inline extraction.

## Queries used

**1. Most-assigned IPs** (baseline)
```
index=* sourcetype="dhcp_sample" earliest=0 | stats count by assigned_ip | sort -count
```

**2. Top requesting MAC addresses**
```
index=* sourcetype="dhcp_sample" earliest=0 | stats count by mac | sort -count
```

**3. MAC-to-IP consistency check** (one MAC taking multiple different assigned IPs)
```
index=* sourcetype="dhcp_sample" earliest=0 | stats dc(assigned_ip) as unique_ips, values(assigned_ip) as ips by mac | where unique_ips > 1 | sort -unique_ips
```

**4. Lease time breakdown**
```
index=* sourcetype="dhcp_sample" earliest=0 | stats count by lease_time | sort -count
```

(A reverse IP→multiple-MACs query and a full session-detail table were also attempted, but the first hit a screenshot mix-up and the second was unreadable due to the merged-event garbling described above — both dropped rather than reported without real verification. The raw-file cross-check below covers the same ground more reliably.)

## Findings

- **The dataset's single biggest anomaly was invisible in Splunk's own results (headline finding)** — Cross-checking the raw file directly, MAC `00:26:9e:83:a2:30` (assigned `192.168.202.76`) issued **744 of the 1,502 real DHCP records — 49.5% of all traffic in the capture** — yet this address doesn't appear anywhere in Splunk's `stats count by mac` output, because the line-breaking bug folded nearly all of its requests into a small number of merged events that each counted as one. A single host generating half of a network's DHCP traffic for one repeated lease is a textbook signature of a boot-looping or misconfigured device (or worth a closer look for something worse) — exactly the kind of finding a SOC hunt exists to catch, and exactly what a bug like this can silently erase. This is the clearest example in the whole project series of why cross-verifying a query's output against raw data matters.
- **The second- and third-place hosts were similarly distorted or hidden entirely** — `00:23:54:8a:21:78` (assigned `192.168.202.97`) actually made 94 requests, and `00:24:54:eb:dc:f2` (assigned `192.168.202.85`) made 79 — the latter doesn't appear at all in Splunk's visible top results, meaning nearly all of its activity was absorbed into merged events too.
- **Roughly a third of the network's real hosts never surfaced in Splunk at all** — the raw file shows 99 unique assigned IPs and 87 unique MAC addresses; Splunk's indexed view only surfaced 64 and 57 respectively. 35 IPs and 30 MAC addresses that requested a lease during this capture are simply absent from any Splunk search result.
- **The lease-type balance is inverted between the buggy and true view** — Splunk's indexed events showed full 86400-second leases as the majority (202 of 333, ~61%) over zero-lease renewal/ACK events (131, ~39%). The true picture is the opposite: zero-lease events dominate at 1,136 of 1,502 (~75.6%), consistent with the dominant host above repeatedly re-confirming the same existing lease rather than requesting fresh ones.
- **MAC-to-IP roaming is real but modest, and there are no IP-to-MAC conflicts** — 10 MAC addresses took more than one assigned IP over the capture (Splunk's query found 7 of these), consistent with normal DHCP renewal/roaming behavior for rebooted or moving devices — nothing conclusively malicious on its own. Cross-checking the reverse direction directly against the raw file, **zero assigned IPs were ever leased to more than one distinct MAC address** — a clean result, no evidence of DHCP spoofing or address-collision activity in this dataset.
- **Overall breakdown** — 1,502 real DHCP transactions in the source file (only 333 indexed by Splunk due to the bug above), 99 unique assigned IPs, 87 unique MAC addresses, and a lease-type split of 1,136 zero-lease to 366 full-lease events.

## Screenshots

- `screenshot-1787861182437.png` — early verification table showing the merged-event artifact directly: extra timestamps and IPs bleeding into the `trans_id` column
- `screenshot-1787861231694.png` — Query 1 result: top assigned IPs as seen in Splunk (undercounted per the Known Limitations section)
- `screenshot-1787861250944.png` — Query 2 result: top MAC addresses as seen in Splunk (same caveat — the true top talker doesn't appear here)
- `screenshot-1787861276307.png` — Query 3 result: 7 MACs with multiple assigned IPs (true count is 10, per raw-file cross-check)
- `screenshot-1787861305632.png` — raw Events view, directly showing a single indexed event containing 8 real merged DHCP lines ("Show all 8 lines")
- `screenshot-1787861326261.png` — Query 4 result: lease time breakdown as seen in Splunk (131/202 — inverted from the true 1,136/366 split)
- `screenshot-1787861350333.png` — attempted full session-detail table, included to show why it was dropped from the findings (unreadable due to merged-event garbling in multiple columns)
