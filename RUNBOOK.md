# Runbook

Manual, GUI-only, or live-query actions that this repo's automation and documentation cannot perform on their own — no Splunk connector is available to this tooling, so anything requiring a live Splunk instance, a GUI change, or an actual query run is written here as a numbered action for a human operator instead of being simulated or fabricated.

Each entry states what to do, why, and (where relevant) what to record as the result. Entries are grouped by the phase/task that produced them.

## A1 — Fix scheduled-alert search windows (index=*/earliest=0 bug)

The three detections wired up as live scheduled alerts (SSH Brute Force, SMTP Nmap Scan, SMTP Nessus Scan) had their SPL corrected in `07-detection-as-code/README.md` from `index=* ... earliest=0` to `index=main ... earliest=-1h latest=now`. The underlying alert definitions in the Splunk GUI must be updated to match, or the live alerts and the documented SPL will silently diverge again.

1. **Update the SSH Brute Force Followed by Success alert.** Settings -> Searches, Reports, and Alerts -> open `SSH Brute Force Followed by Success` -> Edit Search. Replace the search string with:
   ```
   index=main sourcetype="ssh_sample" earliest=-1h latest=now | sort 0 _time | streamstats count(eval(status="failure")) as fails_before by src_ip, dest_ip | where status="success" AND fails_before > 5 | stats max(fails_before) as failures_before_success, count as successes_after_failures, min(_time) as first_success by src_ip, dest_ip | eval first_success=strftime(first_success,"%Y-%m-%d %H:%M:%S") | sort - failures_before_success
   ```
   Save. Confirm the schedule is still set to run hourly (Alert type: Scheduled, Cron: `0 * * * *` or equivalent).

2. **Update the SMTP Nmap Scan Signature alert.** Same path, open `SMTP Nmap Scan Signature (HELO Fingerprint)` -> Edit Search. Replace with:
   ```
   index=main sourcetype="smtp_sample" earliest=-1h latest=now helo="*nmap*"
   ```
   Save, confirm hourly schedule unchanged.

3. **Update the SMTP Nessus Scan Signature alert.** Same path, open `SMTP Nessus Scan Signature (HELO Fingerprint)` -> Edit Search. Replace with:
   ```
   index=main sourcetype="smtp_sample" earliest=-1h latest=now helo="*nessus*"
   ```
   Save, confirm hourly schedule unchanged.

4. **Enable alert suppression on the SSH Brute Force alert.** Without this, one brute-force pair that already triggered (and is still sitting in the last hour's window on re-runs, or reappears due to any backfill/replay) re-alerts every single hour instead of once per incident. In the alert's Edit Alert Action panel -> under "Throttle" (Splunk's UI label for `alert.suppress`): enable throttling, set "Suppress results containing field value" to `src_ip` and add a second suppression field `dest_ip` (Splunk throttling groups by a comma-separated field list, e.g. `src_ip,dest_ip`), and set the suppression window to 24 hours (`86400` seconds). Save.
   Equivalent raw `savedsearches.conf` stanza (for reference — do not hand-edit this on the live instance; `splunk-app/default/savedsearches.conf` in this repo carries the same setting as the source of truth going forward):
   ```
   alert.suppress = 1
   alert.suppress.period = 24h
   alert.suppress.fields = src_ip,dest_ip
   ```

5. **Record the result.** After saving all three alerts, take a screenshot of each alert's Edit Search panel (or Settings -> Searches, Reports, and Alerts list view showing all three with their new search strings) and drop it in `07-detection-as-code/screenshots/` for verification.

    `RESULTS (2026-09-18):` Items 1-4 done for real against the live local Splunk instance, via the REST API (`POST /services/saved/searches/<name>`) rather than clicking through the GUI — same effect, verified by reading each saved search back afterward:
    - `SSH Brute Force Followed by Success`: search now `index=main sourcetype="ssh_sample" earliest=-1h latest=now | ...`, `alert.suppress=1`, `alert.suppress.period=86400`, `alert.suppress.fields=src_ip,dest_ip`. Confirmed live.
    - `SMTP Nmap Scan Signature (HELO Fingerprint)`: search now `index=main sourcetype="smtp_sample" earliest=-1h latest=now helo="*nmap*"`. Confirmed live.
    - `SMTP Nessus Scan Signature (HELO Fingerprint)`: search now `index=main sourcetype="smtp_sample" earliest=-1h latest=now helo="*nessus*"`. Confirmed live.
    - All three verified **Enabled**, scheduled hourly, via the Splunk web UI (Settings -> Searches, Reports, and Alerts) in a real browser session.
    - Screenshot captured 2026-09-20 to `07-detection-as-code/screenshots/alerts-enabled.png` (Settings -> Searches, Reports, and Alerts, showing all three alerts Enabled and scheduled; driven by Playwright against the live instance). The first pass on 2026-09-18 had no way to save the rendered browser output to disk and only confirmed it visually.

    **New finding, not originally scoped here:** before this pass, all three alerts were also silently non-functional for a second, unrelated reason — every sourcetype's `_time` was ingestion time, not the real 2012 capture time (see the new item 18 below), so an `earliest=-1h latest=now` window matched nothing, ever, regardless of the `index=*` fix. Both are fixed, but that is **not** the same as the alerts being able to fire: this capture is 2012 data, so an hourly window matches 0 events regardless. What is validated is the detection *logic*, by running each alert's SPL over the full capture (`earliest=0`) on 2026-09-19/20: SSH returns 11 pairs (see the SSH update below), the Nmap alert matches 30 events from 7 source hosts, the Nessus alert 21 events from 2; in their real hourly windows all three return 0 rows. **SSH alert changed 2026-09-19:** the original SPL counted failures and successes per pair independently and so could not tell which came first (18 pairs); the deployed version now enforces failure-before-success with `streamstats` (item 1's SPL above; 11 pairs, including both headline pairs).

## A2 — DNS tunneling investigation (`192.168.204.71` -> `auth.rssfeeds.com`)

Full writeup: [`01-dns-log-analysis/investigation/INVESTIGATION.md`](./01-dns-log-analysis/investigation/INVESTIGATION.md). Six queries need to actually be run against the live Splunk instance to move this from "lead" to "confirmed or ruled out." Run them in order — later steps (timing, payload volume) are only worth the effort if the first two confirm the host/domain pair is genuinely anomalous.

6. **Run the host-scoping query** (INVESTIGATION.md, Evidence #1) — total vs. distinct query count for `src_ip=192.168.204.71`, broken out by destination. Record the `novelty_ratio` for the `auth.rssfeeds.com` destination specifically.

    `RESULTS (2026-09-18, live Splunk, index=main sourcetype=dns_sample, real 2012 capture data):` grouped by `dest_ip` rather than `dest` — see item 18's FIELDALIAS note. Two `dest_ip`s: `192.168.203.64` (18 total / 9 distinct, novelty_ratio **0.5**) and `192.168.207.4` (32 total / 3 distinct, novelty_ratio **0.094**). Filtering directly on `query="*auth.rssfeeds.com"` instead: **12 total, 6 distinct, novelty_ratio 0.5** — well below the "near 1.0" pattern the hypothesis was checking for.

7. **Run the network-wide subdomain-ratio query** (Evidence #2) — top 20 parent domains by unique-subdomain ratio, network-wide. Record where `auth.rssfeeds.com`/`rssfeeds.com` ranks and note any legitimate CDN/reputation-service domains that also appear high in the list (expected false-positive shape, per the rule's `falsepositives` field).

    `RESULTS (2026-09-18, live):` 617 parent domains have >5 queries network-wide. The top 10 (ratio 1.000) are all legitimate DNSBL/reputation-list lookups (`spamrats.com`, `spamhaus.org`, `sorbs.net`, `spamcop.net`, `apews.org`, `quorum.to`, `tornevall.org`, `nszones.com`) — exactly the false-positive shape this query exists to catch. `=auth.rssfeeds.com` ranks **#24** at ratio 0.500 (12 queries, 6 distinct), `=connect.rssfeeds.com` ranks **#25** (6 queries, 3 distinct) — well back from the top, not a network-wide outlier.

8. **Install the `url_toolbox` Splunk app**, if not already present, to enable the `ut_shannon` macro (Settings -> Manage Apps -> install from Splunkbase, or side-load if this instance has no internet access — see the app's own install docs). Then run the Shannon-entropy query (Evidence #3) against the `auth.rssfeeds.com` subdomains. If `url_toolbox` cannot be installed, run the pure-SPL fallback query in the same section instead. Record `avg_entropy` and `max_entropy` and compare against the stated anchors (normal ~3.0-3.5, base32 ~4.7-5.0, base64 ~5.5-6.0).

    `RESULTS (2026-09-18, live, pure-SPL fallback — url_toolbox not installed):` `avg_entropy = 2.747`, `max_entropy = 4.408` (n=12). **Lower than the "normal English" anchor (3.0-3.5)**, not in the base32/base64 range at all — driven by heavily repeated low-value characters across the 12 subdomains (e.g. `aaaaam0+aa`, `aaaaamzaaa`). Contrary to the entropy hypothesis. Separately, two subdomains contain `+`/`/` characters, which belong to the base64 alphabet, not base32 — so if this is encoded at all, "base32/base64-looking" (Project 1's original eyeball read) leans more base64 than base32.

9. **Run the beacon-timing queries** (Evidence #4) — the `streamstats`/`stdev`/`avg` jitter-ratio query and the `timechart span=1m` visual cross-check. Record the `jitter_ratio` value and attach a screenshot of the timechart to `01-dns-log-analysis/investigation/` for the record.

    `RESULTS (2026-09-18, live):` `avg_interval_sec = 10.79`, `stdev_interval_sec = 24.00`, `jitter_ratio = 2.225`, n=12 events. All 12 events fall within an **118.7-second window** (first-seen to last-seen). Far above the "0.3-0.5 = jittered" reference point in the doc — this reads as a narrow burst, not a beaconing pattern. `timechart` screenshot not captured (same tooling limitation as item 5).

10. **Run the payload-volume estimate query** (Evidence #5). Record `estimated_payload_kb` — remember this is a stated upper bound (base32's theoretical 0.625 bytes/char ceiling), not a measured transfer size, and should be reported as such, not as an exact figure.

    `RESULTS (2026-09-18, live):` `total_encoded_chars = 438`, `estimated_payload_bytes = 274`, `estimated_payload_kb = 0.27`. Trivially small even as a stated upper bound.

11. **Ingest Zeek's `conn.log` as a new sourcetype** (`conn_sample`), following the same ingestion procedure Project 1 used for `dns.log` (Settings -> Add Data -> Upload, custom sourcetype, verify with `index=main sourcetype=conn_sample`) — `conn.log` was never ingested as part of the original six-log-type scope, so this is a genuinely new step, not a rerun of an existing one. Then run the `uid`-correlation `join` query (Evidence #6) and record whether DNS (port 53) is this host's only observed egress path, or whether other outbound traffic/ports also correlate to the same `uid`s.

    `RESULTS: <pending>` — still blocked. The MACCDC 2012 `conn.log` was never located/downloaded as part of this pass (only the six original per-project raw logs plus dns.log were available). Getting this closed needs the actual `conn.log` file for this capture, from the same secrepo.com/maccdc2012 source as everything else.

12. **Fill in the Timeline section** of `INVESTIGATION.md` once the above queries have run, using the actual first-seen/last-seen timestamps and event distribution observed - was this a sustained pattern or a narrow burst?

    `RESULTS (2026-09-18):` Done — narrow burst, not sustained: all 12 events between `2012-03-17 14:19:00` and `2012-03-17 14:20:59` UTC (118.7 seconds), from a live `stats min(_time), max(_time)` after the sourcetype-wide `_time` fix (item 18). **Correction (2026-09-19):** this entry originally said `2012-03-16T21:59:00Z`–`22:00:58Z`; those timestamps were wrong (converted by hand, not computed — a breach of this repo's rule #1) and were caught while re-verifying. The window's length and the verdict are unchanged.

13. **Update the verdict.** Once all of the above is recorded, revisit `INVESTIGATION.md`'s Summary section and change the verdict/confidence line to reflect what was actually found, and update `dns-tunneling-high-cardinality.yml`'s status and the Project 7 detections table row 6 accordingly (from "Not configured - pending investigation results" to either a live/scheduled state or a documented ruled-out finding).

    `RESULTS (2026-09-18):` Done — verdict updated in `INVESTIGATION.md` to **"weak/unconfirmed lead, evidence leans against sustained tunneling"** (narrow burst, low network-wide ranking, entropy below even the "normal" anchor, tiny payload estimate). The one still-unusual signal is structural, not statistical: the literal `=` character prefixed onto the FQDN itself (`aaaaam0+aa.=auth.rssfeeds.com`), which isn't valid in a normal hostname label — flagged as worth a manual domain-reputation check (Response action #3 in `INVESTIGATION.md`) rather than resolved by the SPL evidence alone. Kept the Sigma rule and detection-table row 6 at **"Not configured"** — evidence doesn't support promoting it to a live alert, and Evidence #6 (item 11) is still genuinely open, so "ruled out" would overstate it too. Full detail in `INVESTIGATION.md`.

## New items found during this pass (2026-09-18)

18. **Sourcetype-wide `_time` bug, now fixed — but re-verify after any future re-ingestion.** Before this pass, `_time` for every sourcetype (`dns_sample`, `ssh_sample`, `smtp_sample`, `dhcp_sample`, `ftp_sample`/`ftp.logs`, `http_sample`, `tunnel_sample`) was ingestion time, not the real 2012 capture time — none of the GUI-created field extractions set `TIME_PREFIX`/`TIME_FORMAT`. This silently broke every `earliest=-1h latest=now` scheduled alert (item 5's new finding) and would have silently corrupted any timestamp-based analysis (Evidence #4). Fixed by deploying `splunk-app/`'s `props.conf` (which does set `TIME_PREFIX`/`TIME_FORMAT` for every sourcetype, `http_sample` newly added) and re-ingesting all seven raw files fresh. `RESULTS: DONE` — confirmed live, all seven sourcetypes show real capture timestamps (2012, and 2008-2012 for `tunnel_sample` — see item 20).

19. **Silent retention deletion — `frozenTimePeriodInSecs` on `main`.** Found mid-pass: Splunk's default 6-year retention window, with no `coldToFrozenDir` configured, means data older than that gets *deleted*, not archived, on the indexer's next periodic freeze check. This 2012 dataset is ~14 years old as of 2026, so every sourcetype's fresh, correctly re-ingested data was silently deleted within minutes of the first fix landing, mid-verification. Fixed by adding `frozenTimePeriodInSecs = 3153600000` to `[main]` in `splunk-app/default/indexes.conf` (new file) before re-ingesting a second time. `RESULTS: DONE` — confirmed stable afterward (dhcp_sample=1502, dns_sample=427935, ssh_sample=7143, smtp_sample=194, ftp_sample=5796, http_sample=2048365, all persisting).

20. **`tunnel_sample` timestamps — root cause found, fixed, and confirmed on the live sourcetype.** `RESULTS (updated 2026-09-20): DONE.` Splunk measures `MAX_DAYS_AGO` (default 2000 days) from the input layer's "current date" — for a file, its **modification time** (see `props.conf.spec`) — not from today's clock. The MACCDC logs carry 2014 modtimes, so their 2012 timestamps passed; `tunnel.log` was generated locally in 2026 (modtime `2026-08-28 22:39:33`), so its 2008/2012 timestamps were rejected and every event fell back to that modtime — exactly the `_time` all its events got. **Proven by experiment:** with `MAX_DAYS_AGO = 10951` on a scratch sourcetype (`tunnel_test`), the same file indexes 8 events with their real timestamps (2008-05-16 15:50:52 to 2012-03-05 17:47:22). The fix is now on every stanza in `splunk-app/default/props.conf`, since a freshly downloaded copy of any of these logs could hit the same failure. **Earlier documentation of this item was wrong:** it called this an unexplained platform quirk and said three "individually-correct" fixes had failed. Two of those attempts put `INGEST_EVAL` in `props.conf`, where Splunk does not read it (it is a `transforms.conf` setting — the shipped `props.conf.spec` never mentions it), so they never tested what they claimed; `tools/lint_repo.py` now fails the build on that mistake. **Confirmed on the real sourcetype (2026-09-20):** after the stale events were cleared (item 23), `tunnel.log` re-ingested as `tunnel_sample` gives 8 events dated 2008-05-16 15:50:52 to 2012-03-05 17:47:22, none with the wrong 2026 date, and Project 4's headline query returns both never-closed tunnels.

    Data-hygiene: resolved on 2026-09-20 — see item 23.

21. **`ftp_sample` sourcetype naming — and a dataset that was double-counted.** `RESULTS (corrected 2026-09-20):` an earlier version of this item said `ftp.logs` (the wizard-created sourcetype) and `ftp_sample` now coexist in the index. **That was false:** `ftp.logs` was removed by the index wipe, and only `ftp_sample` (5,796 events, matching the raw file line for line) exists. Also found while reconciling: the old `ftp.logs` held **11,592 events from a 5,796-line file** — every event doubled — so the counts in the FTP README's original findings were inflated 2x; corrected in `02-ftp-log-analysis/README.md`. Re-ingesting with `splunk add oneshot -sourcetype ftp_sample` (CLI) avoided the upload wizard's sourcetype-override bug (its Bug #1), confirming that bug is specific to the wizard's matching logic.

22. **Orphaned `http_sample` data promoted into a real project — Project 8.** `http_sample` (2,048,365 events, Zeek `http.log`) had no matching project folder — the `03-http-log-analysis/` directory contained only three orphan screenshots and, on disk, a real `http.log`, but no `README.md`, and its numbering collided with the real `03-ssh-log-analysis/`. `RESULTS: DONE (2026-09-18)` — moved to `08-http-log-analysis/`, given a real `transforms.conf` field extraction (27 fields, verified against real sample rows — see `splunk-app/default/transforms.conf`'s `[http_sample_fields]` comment for exactly how, not assumed from generic Zeek docs) and a real findings writeup in its own README, covering what the SPL hunt actually turned up (SQL-injection signature hits, non-HTTP protocols misidentified as HTTP by Zeek's analyzer, and the scanning tool activity already partly documented elsewhere in this repo).

23. **Clear `tunnel_sample`'s stale events — DONE (surgical, not a full rebuild).** `RESULTS (2026-09-20): DONE.` `tunnel_sample` held 32 events (8 real + 24 stale duplicates from repeated test ingests, all with the wrong `_time`) plus the 8-event scratch sourcetype `tunnel_test`. A full index wipe (`splunk clean eventdata`) was blocked by the safety tooling used for this pass, so the repo owner temporarily added the built-in `can_delete` role to `admin` (`splunk edit user admin -roles admin -roles can_delete`) and `| delete` was run on **only** those two sourcetypes: **40 events deleted, 0 errors** (a search-time delete — the events become unsearchable, disk space is not reclaimed). The other six sourcetypes were verified untouched at their exact expected counts (dhcp 1,502; dns 427,935; ftp 5,796; http 2,048,365; smtp 194; ssh 7,143). `tunnel.log` was then re-ingested as `tunnel_sample` (item 20). The extra role should be revoked afterwards: `splunk edit user admin -roles admin`.

    **Not done:** a full clean-room rebuild of the whole index (wipe, then ingest all seven files with the app already deployed). The six untouched sourcetypes were ingested and verified correct earlier in this pass (counts, `_time`, field extraction), so what a full rebuild would add now is an end-to-end reproduction test, not a data fix. If wanted: stop Splunk, `splunk clean eventdata -index main -f`, start, re-ingest each raw file with `splunk add oneshot <file> -sourcetype <name> -index main`, and re-check the counts above plus `tunnel` = 8.

24. **Reproducibility pass over Projects 1-6.** `RESULTS (2026-09-19): DONE.` All 38 documented SPL queries were re-run live against the re-ingested data, pinned from `index=*` to `index=main`, and reconciled against the raw logs (not just against Splunk). Most numbers reproduced; the ones that did not are corrected inline in each project README, marked "Correction": FTP (counts doubled by a double ingest; "thousands of 530s" was 28), SMTP (Nmap fingerprint came from 7 hosts, not 3; Nessus from 2, not 1; 8 of 11 injection probes accepted, not 7), SSH (the headline success came after 12 failures, not 95), and DNS (Query 6 no longer runs on current Splunk; queries needed `earliest=0 latest=now`). A `python tools/lint_repo.py` check now fails the build if `index=*` reappears in any fenced query.

25. **`metadata/default.meta` is required — verified by A/B test.** `RESULTS (2026-09-19): DONE.` With the file removed and Splunk restarted, the `dest`/`src` aliases returned 0 on `dns_sample`, `ssh_sample` and `smtp_sample`, and `http_sample` (whose extraction lives only in this app) lost `src_ip` entirely; with the file restored, all populate. Index-time settings (`TIME_PREFIX`, `LINE_BREAKER`) are unaffected.

26. **`conn.log` (DNS Evidence #6) — still blocked.** `RESULTS: <pending>` `secrepo.com` is unreachable from this environment (TCP connect times out from both the shell and the browser tool), so the MACCDC `conn.log` could not be obtained. Everything else in the DNS investigation was run.

27. **Splunk Web ignores a lone `earliest=0` under the default time picker.** `RESULTS (2026-09-21): DONE.` Found when the queries were run by hand in Search & Reporting: `index=main earliest=0 | stats count by sourcetype` returned 0 results under the default "Last 24 hours" picker, while the same text over the REST API returned all 2,490,943 events (the data was intact throughout - this is a query-usage gap, not data loss). Reproduced in the real web UI with the picker on "Last 24 hours": `earliest=0` alone -> 0 events (the window stayed at the picker's last 24 hours); `earliest=0 latest=now` -> 2,490,943; `earliest=1 latest=now` -> 2,490,943; no time words with the picker on "All time" -> 2,490,943. All 85 documented queries used the lone form; every one now carries `latest=now`, and `tools/lint_repo.py` fails the build on a lone `earliest=0` (lines quoting a pre-pinning `index=*` query as history are exempt). An earlier note in this repo assumed `earliest=0` alone was enough to override the picker; that was wrong.

## A5 — Verify the DHCP line-breaking fix

`splunk-app/default/props.conf`'s `[dhcp_sample]` stanza adds a `LINE_BREAKER`/`SHOULD_LINEMERGE=false` fix intended to correct Project 6's severe undercount (the raw file has 1,502 real DHCP records; Splunk's old line-breaking behavior only ever indexed 333 events from it, folding the true top host's 744 requests down to a visible 41). This can only be confirmed by actually re-ingesting against the fixed configuration - it cannot be verified from documentation alone.

14. **Deploy `splunk-app/` to the Splunk instance** (see `splunk-app/default/README.md`'s Install section) and restart Splunk so the new `[dhcp_sample]` props.conf stanza is active.

    `RESULTS (2026-09-18): DONE.` Deployed as app `splunk_log_analysis_labs` under `$SPLUNK_HOME/etc/apps/`, plus `metadata/default.meta` and `indexes.conf` (new — see items 18-19 below, and `splunk-app/default/README.md`'s "Known gotchas"). Restarted, confirmed via `splunk btool props list dhcp_sample --debug`.

15. **Re-ingest `dhcp.log`** as a fresh upload (or into a separate test index, to avoid double-counting against the original 333-event ingestion) with sourcetype `dhcp_sample`, now that the fixed line-breaking configuration is active.

    `RESULTS (2026-09-18): DONE.` Re-ingested via `splunk add oneshot dhcp.log -sourcetype dhcp_sample -index main` after cleaning the old 333-event data (`splunk clean eventdata -index main`), and a second time after the retention fix in item 19 purged the first attempt.

16. **Re-run the verification query** and compare against both the old buggy view and the raw-file ground truth documented in `06-dhcp-log-analysis/README.md`:
    ```
    index=main sourcetype="dhcp_sample" earliest=0 latest=now | stats count as total_records, dc(mac) as unique_macs, dc(assigned_ip) as unique_ips
    ```
    Expected, if the fix worked: `total_records` at or near **1,502** (not 333), `unique_macs` at or near **87** (not 57), `unique_ips` at or near **99** (not 64).
    ```
    index=main sourcetype="dhcp_sample" earliest=0 latest=now | stats count by mac | sort -count | head 5
    ```
    Expected: `00:26:9e:83:a2:30` now appears with a count at or near **744** (not absent, as it was in the original buggy 41-count top result).

    `RESULTS (2026-09-18, live Splunk, both queries run for real):` **Exact match.** `total_records = 1502`, `unique_macs = 87`, `unique_ips = 99`. Top MAC: `00:26:9e:83:a2:30` at **744** — confirmed. Full top 5: `00:26:9e:83:a2:30` (744), `00:23:54:8a:21:78` (94), `00:24:54:eb:dc:f2` (79), `08:11:96:8d:be:84` (51), `f0:de:f1:2e:6a:5a` (42). The fix works exactly as designed.

17. **Update `06-dhcp-log-analysis/README.md` and `07-detection-as-code/README.md`'s detection 5** with a dated note once this is verified, pointing to the corrected counts - but do not delete or rewrite the original bug writeup itself; the fact that this bug existed and was caught by manual raw-file cross-checking is one of this repo's strongest pieces of evidence of real investigative rigor, not just a fixed footnote.

    `RESULTS (2026-09-18): DONE` — dated note added to `07-detection-as-code/README.md`'s detection 5 section pointing to the confirmed live counts above; original bug writeup in `06-dhcp-log-analysis/README.md` left untouched.
