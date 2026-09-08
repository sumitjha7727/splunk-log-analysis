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
index=* sourcetype="ftp.logs" earliest=0 | stats count by command | sort -count
```

**2. Login activity — users and source IPs**
```
index=* sourcetype="ftp.logs" earliest=0 | stats count by user, src_ip | sort -count | head 20
```

**3. Failed / denied operations**
```
index=* sourcetype="ftp.logs" earliest=0 reply_code>=500 | stats count by src_ip, command, reply_msg | sort -count | head 20
```

**4. File transfers involving executables**
```
index=* sourcetype="ftp.logs" earliest=0 command=RETR mime_type="application/x-dosexec" | table _time src_ip dest_ip arg mime_type file_size reply_msg | sort _time
```

**5. Same file, multiple downloaders** (malware-staging indicator)
```
index=* sourcetype="ftp.logs" earliest=0 command=RETR | stats dc(src_ip) as unique_downloaders, values(src_ip) as downloader_ips by dest_ip, arg | where unique_downloaders > 1 | sort -unique_downloaders
```

**6. Upload activity**
```
index=* sourcetype="ftp.logs" earliest=0 command=STOR | table _time src_ip dest_ip arg reply_msg | sort _time
```

## Findings

- **Malware staging pattern (headline finding)** — `ftp://192.168.202.92/./svchost.exe` (`application/x-dosexec`, 6656 bytes) was pulled via `RETR` by **three** distinct internal hosts — `192.168.24.100`, `192.168.25.100`, and `192.168.27.100` — using the same `user=ftp` / `password=password` credentials, in two separate waves (~11:47 and ~12:42). All ten transfer attempts across the three hosts completed successfully ("Transfer complete."). Three unrelated internal hosts pulling the identical executable from one FTP server, on a repeated schedule, is a textbook malware-distribution/staging pattern rather than routine file-sharing — this is the clearest indicator in the whole dataset and would justify an EDR/AV pivot on all three hosts plus a hash lookup on `svchost.exe` (note: legitimate `svchost.exe` never ships via anonymous FTP, so the filename alone is a red flag for masquerading).
- **Internal source/config exfiltration pattern** — a second host, `192.168.25.101`, served up application source files (Flask app modules, `schema.sql`, `.pyc` files, `qdept.db`, `qdept.conf`) that were each pulled by two source IPs, `192.168.202.138` and `192.168.202.94`, using anonymous logins with fabricated-looking emails (e.g. `justinwray@justinwray.com`). Two unrelated hosts systematically pulling a full internal application's source and config from an FTP server reads like reconnaissance/staging rather than a legitimate deploy — worth flagging even though it's lower-confidence than the `svchost.exe` finding.
- **Repeated account-lockout probing** — a single source IP, `192.168.202.102`, generated thousands of `530 Not logged in, user account has been disabled` responses against anonymous/`Cuno`-style logins in a tight time window. A high-volume, single-source stream of failed logins against a disabled account looks like automated/scripted probing rather than a real user retrying a login by hand.
- **Blocked upload (STOR) attempts targeting a Python web app** — thousands of `STOR` attempts from `192.168.202.102` tried to write files into paths under `.../site-packages/flask/testsuite/...` (Flask framework internals) with an odd appended suffix (`.ftpde854Us`), all uniformly rejected with "Operation not permitted." This pattern — trying to drop files into a Python web application's package directories via FTP — is consistent with an attempted webshell/file-write attack against the app, blocked by filesystem permissions rather than by FTP itself.

## Screenshots

- `screenshot-1787491032858.png` — Query 5 result: `svchost.exe` with 3 unique downloaders (the headline finding)
- `screenshot-1787491021514.png` — Query 4 result: all 10 executable-transfer events, all `svchost.exe`
- `screenshot-1787490975195.png` — raw events for the `svchost.exe` downloads, showing `user=ftp` / `password=password`
- `screenshot-1787490955313.png` — Query 3 result (filtered to `src_ip=192.168.202.102`): repeated `530 Not logged in, user account has been disabled`
- `screenshot-1787491054079.png` — Query 6 result: blocked `STOR` attempts into Flask/Python site-packages paths
