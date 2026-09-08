# splunk-app (detection-lab copy)

Carried forward from `splunk-app/default/` at the repo root (built in Project 7's A5 pass) as this lab's starting point, not rebuilt from scratch. That means every file in this directory is currently scoped to the **static MACCDC-2012 replay sourcetypes** (`dns_sample`, `ftp_sample`, `ssh_sample`, `tunnel_sample`, `smtp_sample`, `dhcp_sample`) — it does not yet know anything about this lab's own live data sources.

## What still needs to change here

This lab's victims produce genuinely different data than Projects 1-6's static capture replay:

- **`win-victim`** forwards Sysmon events via `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` — a structured Windows event log sourcetype, not a tab-delimited Zeek TSV. No extraction work needed (Splunk parses Windows event XML natively), but CIM tagging (Endpoint data model) and any process-creation/network-connection detections built against it are new work, not present here yet.
- **`linux-victim`** forwards live Zeek logs (`conn.log`, and potentially `dns.log`, `ssh.log`, etc., depending on what traffic actually crosses it during a campaign) — these overlap conceptually with Projects 1-6's sourcetypes but are **live current-Zeek-schema output**, not the archival Bro-2012 schema Projects 1-6 were built against (see the root `splunk-app/default/README.md`'s "Why the schema differs from modern Zeek" section — the field-count mismatches documented there mean the `transforms.conf` regexes in *this* copy will not correctly parse a modern Zeek log without being re-verified field-by-field first).

Per this repo's `CLAUDE.md`: parsing and alert configuration belong here, in `splunk-app/`, never only described in a markdown file or clicked together in the GUI — so as detection-lab's build order (see the lab's top-level README) reaches "port one detection" and "scale to ~15 rules," the corresponding sourcetype definitions, field extractions, and CIM mappings for Sysmon and live Zeek output need to land in this directory's `.conf` files, the same discipline Project 7 already established for the static-capture side.

## Install

Same mechanism as the root `splunk-app/` (see its own `README.md` for the general pattern) — copy into `$SPLUNK_HOME/etc/apps/`, or, in this lab, mount directly into the `docker-compose.yml` Splunk container (already wired up in `../lab/docker-compose.yml`, which bind-mounts this directory in).
