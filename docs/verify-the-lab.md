# Verify the lab yourself

Seven checks you can paste into Splunk's **Search & Reporting** app to confirm the data is loaded, the fields are extracted, and the alerts are registered and running. Each was run in the real Splunk web UI on 2026-09-21 with the default time picker, and each returned the result listed.

## The one rule: state both time bounds

The data is from 2012, so every query here carries `earliest=0 latest=now`. Splunk Web's default time picker is "Last 24 hours", and a lone `earliest=0` is **ignored** under it: the search silently stays on the last day and returns nothing. Either keep both bounds, as below, or set the picker to All time. (Found 2026-09-21 by running the docs' own queries by hand; see `RUNBOOK.md` item 27.)

## 1. Is all the data loaded?

```
index=main earliest=0 latest=now | stats count by sourcetype
```

Expect 7 rows: `dhcp_sample` 1,502, `dns_sample` 427,935, `ftp_sample` 5,796, `http_sample` 2,048,365, `smtp_sample` 194, `ssh_sample` 7,143, `tunnel_sample` 8 (2,490,943 in total).

## 2. Are the timestamps the real 2012 capture times?

```
| tstats count min(_time) as first max(_time) as last where index=main earliest=0 latest=now by sourcetype | eval first=strftime(first,"%Y-%m-%d"), last=strftime(last,"%Y-%m-%d")
```

Expect 2012-03-16 to 2012-03-17 for every sourcetype except `tunnel_sample` (2008-05-16 to 2012-03-05, three separate sample captures). If `first` is today's date instead, `props.conf` was not deployed before ingest.

## 3. Are the fields extracted?

```
index=main sourcetype=ssh_sample earliest=0 latest=now | head 5 | table _time src_ip dest_ip status direction client server
```

Expect every column populated. The CIM aliases (`src`, `dest`) depend on `metadata/default.meta`; see `splunk-app/default/README.md`.

## 4. Does the SSH alert's logic find the compromises?

This is the live alert's search with its hourly window replaced by all time, because the alert itself cannot match 2012 events.

```
index=main sourcetype="ssh_sample" earliest=0 latest=now | sort 0 _time | streamstats count(eval(status="failure")) as fails_before by src_ip, dest_ip | where status="success" AND fails_before > 5 | stats max(fails_before) as failures_before_success, count as successes_after_failures, min(_time) as first_success by src_ip, dest_ip | eval first_success=strftime(first_success,"%Y-%m-%d %H:%M:%S") | sort - failures_before_success
```

Expect 11 rows, including `192.168.204.45` to `192.168.28.203` and to `192.168.21.253`, each with 12 failures before the success.

## 5. Do the SMTP alerts' logic find the scanners?

```
index=main sourcetype="smtp_sample" earliest=0 latest=now helo="*nmap*"
```

Expect 30 events from 7 source hosts.

```
index=main sourcetype="smtp_sample" earliest=0 latest=now helo="*nessus*"
```

Expect 21 events from 2 source hosts.

## 6. Are the alerts registered and enabled?

```
| rest /servicesNS/-/-/saved/searches splunk_server=local | where (like(title,"SSH Brute%") OR like(title,"SMTP%") OR like(title,"DHCP Lease%") OR like(title,"DNS Tunneling%") OR like(title,"HTTP %") OR like(title,"VMware%")) | eval state=if(disabled=1,"disabled","ENABLED") | table title eai:acl.app state is_scheduled cron_schedule | sort eai:acl.app title
```

Expect, under the app `splunk_log_analysis_labs`, three ENABLED alerts scheduled `0 * * * *` (SSH Brute Force, SMTP Nmap, SMTP Nessus) and six `disabled` documented findings. If you also created the three alerts by hand before deploying the app, you will see a second copy of each under the `search` app; that is harmless.

## 7. Have the alerts actually been running?

```
index=_internal sourcetype=scheduler earliest=-24h latest=now (savedsearch_name="SSH Brute*" OR savedsearch_name="SMTP Nmap*" OR savedsearch_name="SMTP Nessus*") | stats count as runs, latest(status) as last_status, latest(result_count) as last_result_count, latest(_time) as last_run by app, savedsearch_name | eval last_run=strftime(last_run,"%Y-%m-%d %H:%M:%S") | sort app savedsearch_name
```

Expect `last_status` = `success` and `last_result_count` = 0 for each alert, with a `last_run` within the last hour. (Splunk keeps the scheduler log for about 30 days, and only hours the instance was actually running count as runs.)

## Why the alerts return 0 rows

The alerts look at the last hour and this capture is from 2012, so they match nothing by design. **Activity, then Triggered Alerts** stays empty. Checks 4 and 5 are what show the detection logic works; the schedule itself is proven by check 7.
