# Runbook

Manual, GUI-only, or live-query actions that this repo's automation and documentation cannot perform on their own — no Splunk connector is available to this tooling, so anything requiring a live Splunk instance, a GUI change, or an actual query run is written here as a numbered action for a human operator instead of being simulated or fabricated.

Each entry states what to do, why, and (where relevant) what to record as the result. Entries are grouped by the phase/task that produced them.

## A1 — Fix scheduled-alert search windows (index=*/earliest=0 bug)

The three detections wired up as live scheduled alerts (SSH Brute Force, SMTP Nmap Scan, SMTP Nessus Scan) had their SPL corrected in `07-detection-as-code/README.md` from `index=* ... earliest=0` to `index=main ... earliest=-1h latest=now`. The underlying alert definitions in the Splunk GUI must be updated to match, or the live alerts and the documented SPL will silently diverge again.

1. **Update the SSH Brute Force Followed by Success alert.** Settings -> Searches, Reports, and Alerts -> open `SSH Brute Force Followed by Success` -> Edit Search. Replace the search string with:
   ```
   index=main sourcetype="ssh_sample" earliest=-1h latest=now | stats count(eval(status="failure")) as failures, count(eval(status="success")) as successes by src_ip, dest_ip | where failures > 5 AND successes > 0 | sort -failures
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

5. **Record the result.** After saving all three alerts, take a screenshot of each alert's Edit Search panel (or Settings -> Searches, Reports, and Alerts list view showing all three with their new search strings) and drop it in `07-detection-as-code/screenshots/` for verification. `RESULTS: <pending>`

## A2 — DNS tunneling investigation (`192.168.204.71` -> `auth.rssfeeds.com`)

Full writeup: [`01-dns-log-analysis/investigation/INVESTIGATION.md`](./01-dns-log-analysis/investigation/INVESTIGATION.md). Six queries need to actually be run against the live Splunk instance to move this from "lead" to "confirmed or ruled out." Run them in order — later steps (timing, payload volume) are only worth the effort if the first two confirm the host/domain pair is genuinely anomalous.

6. **Run the host-scoping query** (INVESTIGATION.md, Evidence #1) — total vs. distinct query count for `src_ip=192.168.204.71`, broken out by destination. Record the `novelty_ratio` for the `auth.rssfeeds.com` destination specifically. `RESULTS: <pending>`

7. **Run the network-wide subdomain-ratio query** (Evidence #2) — top 20 parent domains by unique-subdomain ratio, network-wide. Record where `auth.rssfeeds.com`/`rssfeeds.com` ranks and note any legitimate CDN/reputation-service domains that also appear high in the list (expected false-positive shape, per the rule's `falsepositives` field). `RESULTS: <pending>`

8. **Install the `url_toolbox` Splunk app**, if not already present, to enable the `ut_shannon` macro (Settings -> Manage Apps -> install from Splunkbase, or side-load if this instance has no internet access — see the app's own install docs). Then run the Shannon-entropy query (Evidence #3) against the `auth.rssfeeds.com` subdomains. If `url_toolbox` cannot be installed, run the pure-SPL fallback query in the same section instead. Record `avg_entropy` and `max_entropy` and compare against the stated anchors (normal ~3.0-3.5, base32 ~4.7-5.0, base64 ~5.5-6.0). `RESULTS: <pending>`

9. **Run the beacon-timing queries** (Evidence #4) — the `streamstats`/`stdev`/`avg` jitter-ratio query and the `timechart span=1m` visual cross-check. Record the `jitter_ratio` value and attach a screenshot of the timechart to `01-dns-log-analysis/investigation/` for the record. `RESULTS: <pending>`

10. **Run the payload-volume estimate query** (Evidence #5). Record `estimated_payload_kb` — remember this is a stated upper bound (base32's theoretical 0.625 bytes/char ceiling), not a measured transfer size, and should be reported as such, not as an exact figure. `RESULTS: <pending>`

11. **Ingest Zeek's `conn.log` as a new sourcetype** (`conn_sample`), following the same ingestion procedure Project 1 used for `dns.log` (Settings -> Add Data -> Upload, custom sourcetype, verify with `index=main sourcetype=conn_sample`) — `conn.log` was never ingested as part of the original six-log-type scope, so this is a genuinely new step, not a rerun of an existing one. Then run the `uid`-correlation `join` query (Evidence #6) and record whether DNS (port 53) is this host's only observed egress path, or whether other outbound traffic/ports also correlate to the same `uid`s. `RESULTS: <pending>`

12. **Fill in the Timeline section** of `INVESTIGATION.md` once the above queries have run, using the actual first-seen/last-seen timestamps and event distribution observed - was this a sustained pattern or a narrow burst?

13. **Update the verdict.** Once all of the above is recorded, revisit `INVESTIGATION.md`'s Summary section and change the verdict/confidence line to reflect what was actually found, and update `dns-tunneling-high-cardinality.yml`'s status and the Project 7 detections table row 6 accordingly (from "Not configured - pending investigation results" to either a live/scheduled state or a documented ruled-out finding).

## A5 — Verify the DHCP line-breaking fix

`splunk-app/default/props.conf`'s `[dhcp_sample]` stanza adds a `LINE_BREAKER`/`SHOULD_LINEMERGE=false` fix intended to correct Project 6's severe undercount (the raw file has 1,502 real DHCP records; Splunk's old line-breaking behavior only ever indexed 333 events from it, folding the true top host's 744 requests down to a visible 41). This can only be confirmed by actually re-ingesting against the fixed configuration - it cannot be verified from documentation alone.

14. **Deploy `splunk-app/` to the Splunk instance** (see `splunk-app/default/README.md`'s Install section) and restart Splunk so the new `[dhcp_sample]` props.conf stanza is active.

15. **Re-ingest `dhcp.log`** as a fresh upload (or into a separate test index, to avoid double-counting against the original 333-event ingestion) with sourcetype `dhcp_sample`, now that the fixed line-breaking configuration is active.

16. **Re-run the verification query** and compare against both the old buggy view and the raw-file ground truth documented in `06-dhcp-log-analysis/README.md`:
    ```
    index=main sourcetype="dhcp_sample" earliest=0 | stats count as total_records, dc(mac) as unique_macs, dc(assigned_ip) as unique_ips
    ```
    Expected, if the fix worked: `total_records` at or near **1,502** (not 333), `unique_macs` at or near **87** (not 57), `unique_ips` at or near **99** (not 64).
    ```
    index=main sourcetype="dhcp_sample" earliest=0 | stats count by mac | sort -count | head 5
    ```
    Expected: `00:26:9e:83:a2:30` now appears with a count at or near **744** (not absent, as it was in the original buggy 41-count top result). `RESULTS: <pending>`

17. **Update `06-dhcp-log-analysis/README.md` and `07-detection-as-code/README.md`'s detection 5** with a dated note once this is verified, pointing to the corrected counts - but do not delete or rewrite the original bug writeup itself; the fact that this bug existed and was caught by manual raw-file cross-checking is one of this repo's strongest pieces of evidence of real investigative rigor, not just a fixed footnote.
