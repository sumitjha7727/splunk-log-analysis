# Fixtures

Empty on purpose, in both subdirectories below. These get populated
from real Atomic Red Team campaign runs (`attacks/run_campaign.py`)
correlated against actual Splunk query results — a JSON event pulled
from a real alert firing (or not firing) against a real, timestamped
attack, saved here alongside its expected outcome.

Deliberately **not** populated with hand-written or synthetic sample
events. The entire point of `detection-lab` is to produce fixtures
with real, campaign-verified ground truth — a synthetic fixture would
just be a guess about what an event "should" look like, dressed up as
validation. That defeats the purpose as surely as fabricating a query
result would, and this repo's `CLAUDE.md` says so explicitly.

- `true_positive/` — events from a campaign run where the mapped
  attack technique actually executed and the detection fired.
- `benign/` — events that resemble the trigger pattern but come from
  normal lab activity, not an attack run (used to check for false
  positives).

`test_detections.py` is written to run against whatever's here — it
currently runs against nothing, and reports that plainly via a
documented skip (see its own module docstring) rather than passing
trivially with zero fixtures found.

## Fixture format, once these are populated

One JSON file per fixture, named `<rule-basename>__<short-label>.json`
(e.g. `ssh-failed-login-threshold__campaign-20260901.json`), containing:

```json
{
  "rule": "ssh-failed-login-threshold.yml",
  "campaign_manifest": "attacks/manifests/campaign-20260901T140000Z.json",
  "expected": "true_positive",
  "event": { "...": "the actual Splunk event fields, e.g. src_ip, dest_ip, status, _time" }
}
```

`expected` should be `true_positive` for anything under `true_positive/`
and `false_positive` for anything under `benign/` that unexpectedly
matched — a benign event that correctly does *not* match doesn't need
a fixture at all, since the point is capturing surprises and confirmed
hits, not exhaustively logging every non-event.
