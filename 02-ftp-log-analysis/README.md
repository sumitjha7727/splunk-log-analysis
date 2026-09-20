# Project 2: FTP Log Analysis

## Objective

Ingest a real captured FTP log into Splunk and hunt for signs of malicious activity — malware staging/distribution via file transfers, credential/login patterns, and denied or anomalous operations.

## Data source

[ftp.log.gz](https://www.secrepo.com/maccdc2012/ftp.log.gz) — a Zeek/Bro FTP log from the MACCDC 2012 network capture.

## Environment

Splunk Enterprise (Docker). Sourcetype ended up as `ftp.logs` (see bug #1 below).

## Ingestion

1. Extracted `ftp.log.gz` and uploaded the raw `ftp.log` via **Settings → Add Data → Upload**.
2. Verified events landed with `index=* sourcetype="ftp.logs" earliest=0`.

## Update (2026-09-18) — the original numbers were double-counted; corrected here

Re-running every query against a fresh ingest exposed a data-quality problem in this project's *original* run that nothing at the time caught: the first upload (sourcetype `ftp.logs`) indexed **11,592 events from a raw file that has 5,796 lines** — exactly 2x, with no duplicate lines in the file itself (`sort ftp.log | uniq -d` is empty). Every count in the original findings was therefore doubled, and a few were also misattributed. The data was re-ingested via `splunk add oneshot -sourcetype ftp_sample` (CLI, which also sidesteps Bug #1 below) — **5,796 events, matching the raw file line for line** — and every figure below was cross-checked against the raw `ftp.log` with `awk`, not just against Splunk.

| Claim in the original findings | Corrected (raw file and live Splunk agree) |
|---|---|
| 10 executable transfers of `svchost.exe`, in "two waves" | **5** transfers, by the same 3 hosts, across two days |
| "Thousands" of `530 ... account has been disabled` responses from `192.168.202.102` | **28** `530` responses in the whole log; **12** are "account has been disabled" (all from `.102`), 9 more from `.102` are "Login or password incorrect!" |
| "Thousands" of `STOR` attempts | **1,353** `STOR` commands in the whole log (1,351 from `.102`), **1,352** of them rejected |
| (not previously called out) | The log's large failure signal is **2,711** `550 Operation not permitted` responses — the `STOR` and `DELE` denials |

The conclusions survive; the magnitudes don't. Screenshots below are as originally captured and show the doubled counts. Queries are pinned to `index=main` (was `index=*`) and to `ftp_sample` (was `ftp.logs`) — the old `ftp.logs` data no longer exists in the rebuilt index.

## Bug #1 — Splunk silently overrode the custom sourcetype

I set the source type to a custom name (`ftp_sample`) during upload, matching the convention from Project 1. Every subsequent search returned "No results found," even after fixing the time range. The cause: Splunk maintains a list of built-in "known" sourcetypes, and it auto-matched this upload to one of its own bundled definitions, `ftp.logs` (Network & Security category), instead of keeping the custom name typed into the wizard. Confirmed via **Settings → Sourcetypes**, where only `ftp.logs` appeared — not `ftp_sample`.

**Takeaway:** don't assume a custom sourcetype name "stuck" just because you typed it — check **Settings → Sourcetypes** immediately after upload, before building anything on top of it. This cost real debugging time chasing a phantom "no results" that had nothing to do with the search logic itself.

## Bug #2 — No `#fields` header in this log

Unlike the DNS log, `ftp.log` from this dataset has no `#fields`/`#types` header lines at all — it starts straight into tab-separated data. There was nothing to verify the schema against directly. Reconstructed the field order from Zeek/Bro's documented `ftp.log` schema and cross-checked it against multiple raw rows (a `PORT` command row and a `RETR` file-transfer row) until the field count (19) and types lined up consistently across both.

## Field extraction

Two approaches used, on purpose — to compare them:
1. An inline regex extraction (later removed).
2. Splunk's **Interactive Field Extractor**, using the **Delimiters** method (tab-delimited), which auto-splits each event into columns and lets you rename them visually rather than hand-writing a regex. Saved as a permanent extraction on sourcetype `ftp.logs`.

Fields extracted: `ts, uid, src_ip, src_port, dest_ip, dest_port, user, password, command, arg, mime_type, file_size, reply_code, reply_msg, passive, data_orig_h, data_resp_h, data_resp_p, fuid`

## Queries used

**1. Command breakdown** (baseline)
```
index=main sourcetype="ftp_sample" earliest=0 latest=now | stats count by command | sort -count
```

**2. Login activity — users and source IPs**
```
index=main sourcetype="ftp_sample" earliest=0 latest=now | stats count by user, src_ip | sort -count | head 20
```

**3. Failed / denied operations**
```
index=main sourcetype="ftp_sample" earliest=0 latest=now reply_code>=500 | stats count by src_ip, command, reply_msg | sort -count | head 20
```

**4. File transfers involving executables**
```
index=main sourcetype="ftp_sample" earliest=0 latest=now command=RETR mime_type="application/x-dosexec" | table _time src_ip dest_ip arg mime_type file_size reply_msg | sort _time
```

**5. Same file, multiple downloaders** (malware-staging indicator)
```
index=main sourcetype="ftp_sample" earliest=0 latest=now command=RETR | stats dc(src_ip) as unique_downloaders, values(src_ip) as downloader_ips by dest_ip, arg | where unique_downloaders > 1 | sort -unique_downloaders
```

**6. Upload activity**
```
index=main sourcetype="ftp_sample" earliest=0 latest=now command=STOR | table _time src_ip dest_ip arg reply_msg | sort _time
```

## Findings

- **Malware staging pattern (headline finding)** — `ftp://192.168.202.92/./svchost.exe` (`application/x-dosexec`, 6656 bytes) was pulled via `RETR` by **three** distinct internal hosts — `192.168.24.100`, `192.168.25.100`, and `192.168.27.100` — using the same `user=ftp` / `password=password` credentials, — **five transfers in total** (2012-03-16 13:37 and 13:40 UTC; 2012-03-17 13:27, 13:28 and 15:40 UTC; two of the three hosts pulled it twice). All five completed successfully ("Transfer complete."). Three unrelated internal hosts pulling the identical executable from one FTP server, repeatedly and across two days, is a textbook malware-distribution/staging pattern rather than routine file-sharing — this is the clearest indicator in the whole dataset and would justify an EDR/AV pivot on all three hosts plus a hash lookup on `svchost.exe` (note: legitimate `svchost.exe` never ships via anonymous FTP, so the filename alone is a red flag for masquerading).
- **Internal source/config exfiltration pattern** — a second host, `192.168.25.101`, served up application source files (Flask app modules, `schema.sql`, `.pyc` files, `qdept.db`, `qdept.conf`) — **106 `RETR` events across 92 distinct files, 13 of them pulled by both** of two source IPs, `192.168.202.138` and `192.168.202.94` — using anonymous logins with fabricated-looking emails (e.g. `justinwray@justinwray.com`). Two unrelated hosts systematically pulling a full internal application's source and config from an FTP server reads like reconnaissance/staging rather than a legitimate deploy — worth flagging even though it's lower-confidence than the `svchost.exe` finding.
- **Failed-login probing — small, but clear** — `192.168.202.102` accounts for 21 of the log's 28 `530` responses: 12 × `Not logged in, user account has been disabled` and 9 × `Login or password incorrect!`, all on the `APPE` command (the other 7 are two hosts sending commands before logging in). Consistent with automated credential guessing, but the volume is modest — the log's *large* failure signal is the `550` denials in the next finding, not this one. (The original writeup called this "thousands"; that figure did not survive the re-check.)
- **Blocked upload (STOR) attempts targeting a Python web app** — `192.168.202.102` sent **1,351 `STOR` attempts to 6 servers** (1,353 in the whole log), **210 of them into paths under `.../site-packages/flask/testsuite/...`** (Flask framework internals) with an odd appended suffix (e.g. `.ftpduBnga4`); **1,352 of the 1,353** `STOR` replies were "Operation not permitted", alongside 1,351 `DELE` commands — together the bulk of the log's 2,711 `550` responses. This pattern — trying to drop files into a Python web application's package directories via FTP — is consistent with an attempted webshell/file-write attack against the app, blocked by filesystem permissions rather than by FTP itself.

## Screenshots

*Captured before the 2026-09-18 re-ingest (see Update above): they show the original doubled counts and the original `index=*` / `ftp.logs` query form.*

- `screenshot-1787491032858.png` — Query 5 result: `svchost.exe` with 3 unique downloaders (the headline finding)
- `screenshot-1787491021514.png` — Query 4 result: all 10 executable-transfer events, all `svchost.exe`
- `screenshot-1787490975195.png` — raw events for the `svchost.exe` downloads, showing `user=ftp` / `password=password`
- `screenshot-1787490955313.png` — Query 3 result (filtered to `src_ip=192.168.202.102`): repeated `530 Not logged in, user account has been disabled`
- `screenshot-1787491054079.png` — Query 6 result: blocked `STOR` attempts into Flask/Python site-packages paths
