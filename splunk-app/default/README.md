# splunk-app

A deployable Splunk app packaging Projects 1-6's field extractions and Project 7's detections as `.conf` files, instead of leaving them as GUI clicks and copy-pasted SPL. Ingestion still has to happen through **Settings → Add Data → Upload** (there's no way to script the actual file upload without a real Splunk instance to point at), but everything downstream of that - parsing, field extraction, alerting, CIM tagging - is defined here and versioned in this repo, not stored only inside a Splunk instance's own configuration.

## What's in here

- **`props.conf`** — per-sourcetype timestamp recognition (`TIME_PREFIX`/`TIME_FORMAT` for Zeek's epoch `ts` field), line-breaking fixes, null-queue routing for `#`-prefixed Zeek header/footer lines, and CIM field aliasing.
- **`transforms.conf`** — the field extractions themselves: named-capture regexes for the three sourcetypes with variable-width text fields (`dns_sample`, `smtp_sample`, `dhcp_sample`), and tab-delimiter field lists for the three with fixed-position columns (`ftp_sample`, `ssh_sample`, `tunnel_sample`).
- **`savedsearches.conf`** — the six Project 7 detections as alert definitions, generated from the Sigma rules in `07-detection-as-code/` and their hand-translated SPL. **Do not hand-edit this file** — see its header comment.
- **`eventtypes.conf`** / **`tags.conf`** — CIM data-model tagging for the three sourcetypes A5 scoped for it (DNS → Network Resolution, tunnel → Network Traffic, SSH → Authentication).

## Install

1. Copy this `splunk-app/` directory into your Splunk instance's `$SPLUNK_HOME/etc/apps/` directory (rename the top-level folder to something like `splunk_log_analysis_labs` if you want a specific app name — Splunk uses the directory name as the app's internal ID).
2. Restart Splunk, or run `splunk restart`, to pick up the new `.conf` files.
3. Ingest each of the six raw logs via **Settings → Add Data → Upload**, setting the sourcetype explicitly to match one of the six stanzas in `props.conf` (`dns_sample`, `ftp_sample`, `ssh_sample`, `tunnel_sample`, `smtp_sample`, `dhcp_sample`) at upload time.
   - **Note on the FTP sourcetype specifically:** Project 2's original ingestion hit a bug where Splunk's classic upload wizard silently overrode the custom `ftp_sample` name with a built-in sourcetype, `ftp.logs` (see `02-ftp-log-analysis/README.md`, Bug #1). That override happens in the interactive wizard's own matching logic; it shouldn't recur here as long as `props.conf`'s `[ftp_sample]` stanza is already deployed and active *before* upload, since Splunk checks for a matching configured sourcetype first. Confirm under **Settings → Sourcetypes** after upload regardless, per this repo's own standing practice since that bug was found.
4. Verify each sourcetype landed correctly and with the expected event count, and that `_time` now reflects the real 2012 capture time rather than ingestion time (the fix this whole app exists to apply — see the `props.conf` header comment).
5. Re-run the DHCP verification step in `RUNBOOK.md` to confirm the line-breaking fix actually corrects the undercount documented in Project 6 (expect the true top host's 744-of-1,502 request count to now be visible, not the buggy 41-of-333 view).

## Why the schema differs from modern Zeek

Every regex in `transforms.conf` is tied to this specific dataset's Zeek/Bro version, not to Zeek's current schema — and that's deliberate, not an oversight. The MACCDC 2012 capture predates several schema changes in later Zeek releases:

- **`dns.log`** here is 23 fields, not the 24-field schema a current Zeek installation produces — this 2012-era capture has no `rtt` (round-trip time) column, which was added later. Every field after `trans_id` sits one position earlier than it would in a modern log (see `01-dns-log-analysis/README.md` for the exact bug this caused when a modern-schema regex was tried first).
- **`smtp.log`** here is 25 fields; a current Zeek release adds `second_received` and `tls` fields on top of this.
- **`dhcp.log`** here uses the older Bro-era 10-field schema (`ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, mac, assigned_ip, lease_time, trans_id`) rather than the substantially different, richer DHCP transaction schema modern Zeek produces.

The general lesson, carried over from Project 1's own writeup: never assume a log's field schema from current documentation or a generic template — confirm it against the source file's own header (or, when there is no header, against multiple raw sample rows) before building a parser. A wrong field mapping doesn't error out loudly here; it silently produces empty or misaligned results, which is a worse failure mode than an outright crash. If this app is ever pointed at a newer Zeek deployment's logs instead of this archival capture, every regex in `transforms.conf` needs to be re-verified against that version's actual schema first, not assumed to still apply.

## New dependencies

This app assumes the `url_toolbox` Splunk app is installed for the `ut_shannon` macro used in the DNS tunneling investigation (`01-dns-log-analysis/investigation/INVESTIGATION.md`) — install it separately from Splunkbase, or side-load it if this instance has no internet access. `sigma-cli` and `pysigma-backend-splunk` are Python packages used by CI (`.github/workflows/validate.yml`) to lint and convert the Sigma rules in `07-detection-as-code/`, not by the Splunk instance itself.
