# Project 1: DNS Log Analysis

## Objective

Ingest a real captured DNS log into Splunk and hunt for signs of malicious activity — DGA-style NXDOMAIN patterns, DNS tunneling indicators (long/high-entropy queries, unusual query types), and general traffic baselining (top domains, top clients).

## Data source

[dns.log.gz](https://www.secrepo.com/maccdc2012/dns.log.gz) — a Zeek/Bro DNS log from the MACCDC 2012 network capture.

## Environment

Splunk Enterprise (Docker), sourcetype `dns_sample`.

## Ingestion

1. Extracted `dns.log.gz` and uploaded the raw `dns.log` via **Settings → Add Data → Upload**.
2. Set a custom source type: `dns_sample`.
3. Verified events landed with `index=* sourcetype=dns_sample`.

## Field extraction — and a bug I caught

Zeek's `dns.log` is tab-separated. I initially wrote a 24-field extraction regex based on the modern Zeek `dns.log` schema (which includes an `rtt` field). That produced bad output: the `query` field was capturing numeric `qclass` values instead of actual domain names, and searches for long or rarely-seen domains returned zero results — a red flag, since that's statistically unlikely across any real traffic capture.

Checking the file's own `#fields` header line (`Select-String -Path dns.log -Pattern "^#fields"`) confirmed the cause: this capture is from an older Bro version (2012), and its `dns.log` **doesn't include an `rtt` column** — that field was added in later Zeek releases. Every column after `trans_id` was shifted by one position as a result. Fixed the extraction to match the real 23-field schema:

```
^(?<ts>[^\t]+)\t(?<uid>[^\t]+)\t(?<src_ip>[^\t]+)\t(?<src_port>[^\t]+)\t(?<dest_ip>[^\t]+)\t(?<dest_port>[^\t]+)\t(?<proto>[^\t]+)\t(?<trans_id>[^\t]+)\t(?<query>[^\t]+)\t(?<qclass>[^\t]+)\t(?<qclass_name>[^\t]+)\t(?<qtype>[^\t]+)\t(?<qtype_name>[^\t]+)\t(?<rcode>[^\t]+)\t(?<rcode_name>[^\t]+)\t(?<AA>[^\t]+)\t(?<TC>[^\t]+)\t(?<RD>[^\t]+)\t(?<RA>[^\t]+)\t(?<Z>[^\t]+)\t(?<answers>[^\t]+)\t(?<TTLs>[^\t]+)\t(?<rejected>.+)$
```

**Takeaway:** never assume a log's field schema from generic documentation or an older extraction template — confirm it against the source file's own header before building a parser. A wrong field mapping doesn't error out loudly; it silently produces empty or misleading results, which is a worse failure mode in real detection engineering work than an outright crash.

## Queries used

Modernized for the detection-as-code pass (Project 7): `index=*` is now pinned to `index=main`, and the `NOT _raw="#*"` filter that used to strip Zeek's `#`-prefixed header/comment lines client-side at search time is gone — that filtering now happens at index time instead, via `props.conf`'s `TRANSFORMS-nullqueue` routing those lines to `nullQueue` before they're ever indexed (see [`splunk-app/default/props.conf`](../splunk-app/default/props.conf)). Same effect, but the exclusion no longer has to be repeated in every single query by hand.

### Baseline queries

**1. Top queried domains** (baseline)
```
index=main sourcetype=dns_sample | stats count by query | sort -count | head 20
```

**2. Top clients by query volume**
```
index=main sourcetype=dns_sample | stats count by src_ip | sort -count | head 20
```

**3. NXDOMAIN lookups** (possible DGA / malware beaconing — repeated failed resolutions to algorithmically-generated domain names)
```
index=main sourcetype=dns_sample rcode_name="NXDOMAIN" | stats count by src_ip, query | sort -count | head 20
```

**4. Query type distribution** (an unusual volume of TXT/NULL records can indicate DNS tunneling)
```
index=main sourcetype=dns_sample | stats count by qtype_name | sort -count
```

**5. Long domain names** (tunneling / data exfiltration indicator — legitimate domains are rarely 50+ characters)
```
index=main sourcetype=dns_sample | dedup query | eval qlen=len(query) | table query qlen | sort -qlen | head 15
```

**6. Domain rarity distribution** (how many domains were seen exactly N times — a cleaner check than hard-filtering to `count=1`)
```
index=main sourcetype=dns_sample | stats count by query | stats count by count | sort count
```

### Extended queries (added in the detection-as-code pass)

**7. First-seen domain detection** — ranks domains by how late in the capture window they first appear, as a proxy for "newly observed" in the absence of a longer rolling historical baseline (a caveat worth stating plainly: this is a one-time static capture, not a live production feed with weeks of prior history to diff against — a real deployment would compare against a rolling lookback, not just rank within one capture's own timespan):
```
index=main sourcetype=dns_sample | stats earliest(_time) as first_seen, latest(_time) as last_seen, count as total_count by query | eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S") | sort -first_seen | head 20
```

**8. Domain rarity scoring** — extends Query 6 from a raw frequency histogram into a per-domain inverse-frequency score, so individual rare domains can be sorted and triaged directly instead of only seeing the shape of the distribution:
```
index=main sourcetype=dns_sample | stats count as domain_count by query | eventstats sum(domain_count) as total_queries | eval domain_freq=domain_count/total_queries | eval rarity_score=round(-1*log(domain_freq, 10), 3) | sort -rarity_score | head 20
```

## Findings

- **NXDOMAIN / REFUSED traffic**: the general event sample shows scattered `NXDOMAIN` responses (e.g. reverse-DNS lookups like `44.206.168.192.in-addr.arpa`) and `REFUSED` responses to internal `_dns-sd._udp` service-discovery PTR queries. This lines up with normal internal network chatter — mDNS/Bonjour-style service discovery and reverse lookups for private ranges — rather than DGA-style beaconing.
- **Domain rarity (`count=1` hard filter)**: mostly automated IP-reputation/blocklist lookups (`*.spamrats.com`, `*.spamcop.net`, `*.dnsbl.tornevall.org`, `*.sorbs.net`) plus one long IPv6 reverse-DNS query. This is typical background noise from mail/security tooling checking sender reputation, not attacker-controlled infrastructure.
- **Long domain names (tunneling indicator) — most notable result**: several queries over 80 characters were observed. One pattern stands out: repeated long, base32/base64-looking subdomains (e.g. `+s6fgaabadrbmdcwnzbbqzcxrdzgouy4nenbnje4mdgxmtgwmdqxnku0m0fdq0e.=auth.rssfeeds.com`) all from a single host, `192.168.204.71`, to `auth.rssfeeds.com`. Repeated high-entropy-looking subdomains from one source to one domain is a classic DNS-tunneling / C2-beaconing shape. It's worth a follow-up pivot on `src_ip=192.168.204.71` before drawing a firm conclusion — this single query flags it as a lead, not a confirmed verdict.
- **Top domains / clients and query-type distribution** (Queries 1, 2, 4): reproduce with the SPL above — not captured in a saved screenshot for this run.

## Screenshots

**1. Domain rarity — `count=1` hard filter** (variant of Query 6)
![Domains queried exactly once](./screenshots/domain-rarity-count1.png)
Every domain that appears exactly once in the capture window. Dominated by reverse-DNS (`*.ip6.arpa`) and DNSBL/reputation-checking lookups — routine, not attacker traffic.

**2. Long domain names — tunneling indicator** (Query 5, extended with `_time`/`src_ip` and an 80-char threshold)
![Long domain names, sorted by length](./screenshots/long-domain-names-tunneling-indicator.png)
11,189 events matched `qlen > 50`. The repeated encoded-looking subdomains from `192.168.204.71` to `auth.rssfeeds.com` are the standout — see Findings above.

**3. Sample raw events — field-extraction check**
![Sample of raw DNS events with all extracted fields](./screenshots/sample-events-raw-table.png)
`_time`, `src_ip`, `dest_ip`, `query`, `qtype_name`, and `rcode_name` all populate correctly after the schema fix above — confirms the 23-field regex is extracting cleanly, including `NXDOMAIN`/`REFUSED` rcodes and NetBIOS/mDNS-style broadcast queries (`NB`, `SRV` with null-byte-padded names).
