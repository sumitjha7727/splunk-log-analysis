# Project 4: Tunnel Log Analysis (GRE / IPv4 / IPv6)

## Objective

Hunt for tunneling activity — GRE, 6to4, Teredo, and other IP-in-IP encapsulation — that could indicate either legitimate IPv6-transition mechanisms or an attempt to smuggle traffic past IPv4-focused network controls.

## Data source

The original plan was to use [tunnel.log.gz](https://www.secrepo.com/maccdc2012/tunnel.log.gz) from the MACCDC 2012 capture, matching every other project in this series. That download wouldn't complete, and secrepo.com was returning rate-limit errors on repeated attempts, so this project uses a different, real data source instead: three small IPv6-tunneling packet captures (`Teredo.pcap`, `6to4.pcap`, `6in4.pcap.gz`) from [Wireshark's official sample-capture archive](https://github.com/briliant-ben/SampleCaptures/tree/main/specific-protocols-and-protocol-families/ipv6-and-tunneling-mechanism), run through Zeek myself to generate an original `tunnel.log`.

## Environment

Splunk Enterprise (Docker), same as every other project. Sourcetype `tunnel_sample`.

**New for this project:** Zeek itself, run via the official `zeek/zeek` Docker image, to generate the log from raw packet captures rather than downloading a pre-made one.

## Generating the log with Zeek

1. Downloaded the three pcaps into a `pcaps/` folder.
2. Pulled the Zeek image: `docker pull zeek/zeek:latest`.
3. **Bug #1 — Zeek can't take multiple trace files in one run.** My first attempt passed all three pcaps to a single `-r` flag as a comma-separated list (`zeek -r a.pcap,b.pcap,c.pcap`) — Zeek tried to open that whole string as one literal filename and failed. A second attempt repeated the `-r` flag (`-r a.pcap -r b.pcap -r c.pcap`), which is valid syntax on older Bro/Zeek releases but this Zeek version rejected it outright: *"Only a single readfile option (-r) is allowed."* Ended up running Zeek three separate times, once per pcap, each into its own output folder.
4. Pulled the `tunnel.log` out of each of the three output folders and merged the real data rows into one file myself, in chronological order.

Result: 8 real tunnel events — 3 Teredo tunnel setups (open + close each) from one host, plus 2 standalone `Tunnel::IP` events (the 6to4 and 6in4 captures).

## Known limitation — a self-inflicted data quality bug, and what it broke

**Bug #2 — Splunk's default line-breaking swallowed my file's header, and glued its footer onto real data.** My merged `tunnel.log` included the standard Zeek header block (`#separator`, `#fields`, `#types`, etc.) and a trailing `#close` line, same as a normal Zeek-produced file. Splunk's default behavior is to treat any line that doesn't start with a recognizable timestamp as a *continuation* of the previous event rather than a new one. Since none of the 8 header lines have a timestamp, Splunk merged all of them into a single bogus event at ingest time — and merged the trailing `#close` line onto the *last* real data row instead of treating it separately. Net result: **9 indexed events for 8 real tunnel records**, and one real row's `action` field silently corrupted from `Tunnel::DISCOVER` to `Tunnel::DISCOVER\n#close`.

I caught this from the event count (9 instead of the expected 8) and rebuilt a header-free version of the file, but chose to keep working with the already-ingested data rather than delete and re-upload. That decision had a real consequence, caught by comparing query output against the raw event table rather than trusting the query alone:

**Query 6 (the "tunnels that never closed" hunt) silently missed one of the two tunnels it should have caught.** The query flags any tunnel where `action="Tunnel::DISCOVER"` count exceeds `action="Tunnel::CLOSE"` count. The 6to4 tunnel (`70.55.213.211 → 192.88.99.1`) correctly shows up (1 discover, 0 closes). The 6in4 tunnel (`213.141.154.170 → 213.79.83.1`) — which *also* never closed, since plain `Tunnel::IP` events in Zeek don't get an explicit close the way Teredo does — dropped out of the result entirely, because its `action` field no longer exactly matches the string `"Tunnel::DISCOVER"` after the header-merge bug appended `#close` to it. The query didn't error, it just quietly under-reported. Caught this by manually cross-checking the full 9-row event table (Query 3) against the query 6 output, rather than assuming the query's silence meant nothing was there. Findings below include both tunnels, corrected for this.

**Takeaway:** a data-hygiene bug that looks cosmetic (an inflated event count) can silently break the exact-match logic in a downstream hunting query without any error message — worth re-verifying automated detection output against raw data, especially on a self-built or reprocessed source.

## Field extraction

Interactive Field Extractor, Delimiters → Tab — same method as every other project.

Fields extracted: `ts, uid, src_ip, src_port, dest_ip, dest_port, tunnel_type, action`

## Queries used

**1. Tunnel type breakdown** (baseline)
```
index=* sourcetype="tunnel_sample" earliest=0 | stats count by tunnel_type | sort -count
```

**2. Action breakdown** (DISCOVER vs. CLOSE)
```
index=* sourcetype="tunnel_sample" earliest=0 | stats count by action | sort -count
```

**3. Full tunnel session detail**
```
index=* sourcetype="tunnel_sample" earliest=0 tunnel_type=* | table _time uid src_ip src_port dest_ip dest_port tunnel_type action | sort _time
```

**4. Most-contacted tunnel endpoints**
```
index=* sourcetype="tunnel_sample" earliest=0 tunnel_type=* | stats count by dest_ip | sort -count
```

**5. Tunnel-initiating source hosts**
```
index=* sourcetype="tunnel_sample" earliest=0 tunnel_type=* | stats dc(dest_ip) as unique_endpoints, values(tunnel_type) as types by src_ip | sort -unique_endpoints
```

**6. Tunnels that never closed** (headline query)
```
index=* sourcetype="tunnel_sample" earliest=0 tunnel_type=* | stats count(eval(action="Tunnel::DISCOVER")) as opens, count(eval(action="Tunnel::CLOSE")) as closes by uid, src_ip, dest_ip, tunnel_type | where opens > closes
```

Note: the `tunnel_type=*` filter I added to queries 3–6 to exclude the header artifact turned out not to fully work — the artifact event's `tunnel_type` field extracted a non-empty (but garbage) value of literally `ts`, so it still passed the filter and shows up as a distorted row in several of the results (visible in the screenshots). It's easy to spot — garbled field values with fragments like `#unset_field` or `#open` instead of real IPs/tunnel types — and doesn't affect the real 8-row findings below.

## Findings

- **Two IP-in-IP tunnels opened and never closed (headline finding)** — `70.55.213.211 → 192.88.99.1` and `213.141.154.170 → 213.79.83.1` (both `Tunnel::IP`) each show exactly one `DISCOVER` event and no corresponding `CLOSE`. This is expected Zeek behavior for plain IP-in-IP tunnels (they don't get an explicit close event the way Teredo does), not necessarily malicious — but it's exactly the kind of tunnel a SOC hunt should surface for manual review, since IP-in-IP encapsulation is a known technique for smuggling traffic past IPv4-focused firewalls and DLP tooling. Only the first of these two was actually caught by Query 6 as run — the second only surfaced by manually reviewing the full 9-row event table, because of the data-quality bug described above. Both are reported here since both are real.
- **One of the two tunnels touches known infrastructure, not an unknown host** — `192.88.99.1` is the IANA-assigned global anycast address for public 6to4 relays, used for legitimate automatic IPv6-over-IPv4 tunneling. Worth recognizing on sight so it isn't mistaken for a suspicious unknown IP during triage — but 6to4 traffic is still worth tracking, since it's a well-documented way to carry IPv6 traffic through networks that only inspect or filter IPv4.
- **The second tunnel has no such recognizable public-infrastructure destination** — `213.79.83.1` doesn't correspond to any well-known relay address the way `192.88.99.1` does, which makes this the more interesting of the two to actually pull a full packet capture on in a real investigation.
- **Teredo tunneling from a single internal host is otherwise clean baseline activity** — `192.168.2.16` opened and cleanly closed three separate Teredo tunnels to three different Teredo relay/server IPs (`65.55.158.80`, `65.55.158.81`, `83.170.1.38`), all on source port 3797 (Teredo's standard client behavior). Every one of these has a matching `DISCOVER` and `CLOSE` pair — normal NAT-traversal tunnel setup/teardown, useful as a contrast baseline against the two tunnels above that never closed.
- **Overall breakdown** — of the 8 real events: 6 `Tunnel::TEREDO` (all from the one host above) and 2 `Tunnel::IP` (the two never-closed tunnels). 5 `DISCOVER` actions total, 3 `CLOSE` actions total (one `DISCOVER` value corrupted by the header-merge bug, as noted above).

## Screenshots

- `screenshot-1787679013953.png` — raw Events view of all 9 indexed events (Time range: All time), showing the header-artifact event (bottom) alongside the 8 real tunnel rows
- `sssssss.png` — `index=* sourcetype="tunnel_sample" earliest=0 | table _raw`, showing the raw text of all 9 events including the merged header block and the corrupted `#close`-appended row
- `screenshot-1787679571056.png` — Query 1 result: tunnel type breakdown (`Tunnel::TEREDO`=6, `Tunnel::IP`=2, plus the `ts` artifact bucket)
- `screenshot-1787679602046.png` — Query 2 result: action breakdown, showing the corrupted `Tunnel::DISCOVER\n#close` value from the header-merge bug
- `screenshot-1787679624583.png` — Query 3 result: full 8-row tunnel session table plus the visibly garbled artifact row
- `screenshot-1787679650586.png` — Query 4 result: destination endpoint counts
- `screenshot-1787679666990.png` — Query 5 result: source hosts and their unique tunnel endpoints
- `screenshot-1787679685502.png` — Query 6 result: only the 6to4 tunnel (`192.88.99.1`) shows up as never-closed, due to the data-quality bug described in Known Limitations — the second never-closed tunnel (6in4) was found by manually reviewing the full event table instead
