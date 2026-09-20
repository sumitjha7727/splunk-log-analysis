#!/usr/bin/env python3
"""Repo lint: turns CLAUDE.md's standing rules, and the mistakes this repo has actually made,
into checks that run on every push. Standard library only - no install step.

Exit code 1 if any check fails.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "splunk-app"
FAILS = []
TOTAL = 0

# sourcetype -> (transforms stanza holding its field list, tab-separated column count of the raw
# Zeek log). Every count was verified against every line of the real raw file with
# `awk -F'\t' '{print NF}' file | sort -u`, not taken from documentation.
EXPECTED = {
    "dns_sample": ("dns_sample_fields", 23),
    "ftp_sample": ("ftp_sample_fields", 19),
    "ssh_sample": ("ssh_sample_fields", 15),
    "tunnel_sample": ("tunnel_sample_fields", 8),
    "smtp_sample": ("smtp_sample_fields", 25),
    "dhcp_sample": ("dhcp_sample_fields", 10),
    "http_sample": ("http_sample_fields", 27),
}


def check(ok, label, detail=""):
    global TOTAL
    TOTAL += 1
    if ok:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}" + (f"\n          {detail}" if detail else ""))
        FAILS.append(label)


def parse_conf(path):
    stanzas, cur = {}, None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^\[(.+)\]$", line)
        if m:
            cur = m.group(1)
            stanzas.setdefault(cur, {})
        elif cur is not None and "=" in line:
            key, value = line.split("=", 1)
            stanzas[cur][key.strip()] = value.strip()
    return stanzas


def lint_props_and_transforms():
    print("props.conf / transforms.conf")
    props = parse_conf(APP / "default" / "props.conf")
    transforms = parse_conf(APP / "default" / "transforms.conf")
    for st, (fields_stanza, ncols) in EXPECTED.items():
        p = props.get(st)
        check(p is not None, f"[{st}] stanza exists in props.conf")
        if p is None:
            continue
        missing = [k for k in ("TIME_PREFIX", "TIME_FORMAT", "LINE_BREAKER") if k not in p]
        check(not missing, f"[{st}] sets TIME_PREFIX, TIME_FORMAT and LINE_BREAKER", f"missing: {missing}")
        check(p.get("SHOULD_LINEMERGE", "").lower() == "false", f"[{st}] SHOULD_LINEMERGE = false")
        try:
            days = int(p.get("MAX_DAYS_AGO", "0"))
        except ValueError:
            days = 0
        check(days >= 10000, f"[{st}] MAX_DAYS_AGO >= 10000 (Splunk's 2000-day default rejects 2008-2012 "
              "timestamps whenever a file's modtime is recent)", f"got {p.get('MAX_DAYS_AGO')!r}")
        check("INGEST_EVAL" not in p, f"[{st}] no INGEST_EVAL in props.conf (Splunk only reads it from transforms.conf)")
        for key, value in p.items():
            if key.startswith(("REPORT-", "TRANSFORMS-")):
                for name in [v.strip() for v in value.split(",")]:
                    check(name in transforms, f"[{st}] {key} -> [{name}] exists in transforms.conf")
        t = transforms.get(fields_stanza)
        check(t is not None and t.get("DELIMS") == '"\\t"', f"[{fields_stanza}] is a tab-DELIMS extraction")
        fields = re.findall(r'"([^"]+)"', (t or {}).get("FIELDS", ""))
        check(len(fields) == ncols, f"[{fields_stanza}] lists {ncols} fields (the raw log has {ncols} columns)",
              f"lists {len(fields)}")
        check(len(set(fields)) == len(fields), f"[{fields_stanza}] field names are unique")


def lint_indexes_and_metadata():
    print("indexes.conf / metadata")
    idx = parse_conf(APP / "default" / "indexes.conf")
    try:
        frozen = int(idx.get("main", {}).get("frozenTimePeriodInSecs", "0"))
    except ValueError:
        frozen = 0
    check(frozen >= 946080000, "[main] frozenTimePeriodInSecs >= 30 years (the default ~6 years silently deletes "
          "this 2012 dataset)", f"got {frozen}")
    meta = APP / "metadata" / "default.meta"
    exported = meta.exists() and re.search(r"^\s*export\s*=\s*system\s*$", meta.read_text(encoding="utf-8"), re.M)
    check(bool(exported), "metadata/default.meta exports the app's knowledge objects globally (export = system)")


def lint_savedsearches():
    print("savedsearches.conf")
    for name, s in parse_conf(APP / "default" / "savedsearches.conf").items():
        search = s.get("search", "")
        check("index=main" in search and not re.search(r"index\s*=\s*\*", search),
              f"[{name}] pins index=main (CLAUDE.md rule 2)")
        # `is_scheduled` is a computed REST field, not a conf key: `splunk btool check` rejects it, and only
        # `enableSched` actually schedules a saved search. An empty `actions =` is rejected the same way.
        bad_keys = [k for k in ("is_scheduled", "actions") if k in s and (k == "is_scheduled" or not s[k].strip())]
        check(not bad_keys, f"[{name}] uses no key that `splunk btool check` rejects", ", ".join(bad_keys))
        if s.get("enableSched", "0") == "1":
            check("earliest=-" in search and "latest=now" in search,
                  f"[{name}] scheduled search uses a relative window (CLAUDE.md rule 3)")
            check(s.get("disabled", "1") == "0", f"[{name}] scheduled search is enabled")
        else:
            check(s.get("disabled", "0") == "1" and len(s.get("description", "")) > 40,
                  f"[{name}] unscheduled search is disabled and explains why in its description (CLAUDE.md rule 3)")


def lint_markdown_spl():
    print("SPL in documentation")
    bad, lone_earliest = [], []
    for md in sorted(ROOT.rglob("*.md")):
        if ".git" in md.parts:
            continue
        in_fence = False
        for n, line in enumerate(md.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            # lines quoting a pre-pinning `index=*` query are history (a screenshot caption, what was typed at the
            # time), not something to paste, so they keep their original wording
            if re.search(r"earliest=0(?![\w.])", line) and "latest=" not in line and "index=*" not in line:
                lone_earliest.append(f"{md.relative_to(ROOT).as_posix()}:{n}")
            if line.strip().startswith("```"):
                in_fence = not in_fence
            elif in_fence and re.search(r"index\s*=\s*\*", line):
                bad.append(f"{md.relative_to(ROOT).as_posix()}:{n}")
    check(not bad, "no fenced SPL block uses index=* (CLAUDE.md rule 2)", ", ".join(bad[:10]))
    # Splunk Web ignores a lone `earliest=0` and keeps the time picker's window (default "Last 24 hours"), so a
    # pasted query silently returns nothing on this 2012 dataset. Both bounds must be stated. (Found 2026-09-21.)
    check(not lone_earliest, "every `earliest=0` in the docs also states `latest=` (Splunk Web ignores a lone "
          "earliest=0 under the default time picker)", ", ".join(lone_earliest[:10]))


def lint_sigma():
    print("Sigma rules")
    folder = ROOT / "07-detection-as-code"
    readme = (folder / "README.md").read_text(encoding="utf-8")
    seen = {}
    for rule in sorted(folder.glob("*.yml")):
        text = rule.read_text(encoding="utf-8")
        m = re.search(r"^id:\s*([0-9a-fA-F-]{36})\s*$", text, re.M)
        check(bool(m), f"{rule.name}: has a UUID id")
        if m:
            seen.setdefault(m.group(1).lower(), []).append(rule.name)
        underscored = re.findall(r"^\s*-\s*(attack\.[a-z]+_[a-z_]+)\s*$", text, re.M)
        check(not underscored, f"{rule.name}: ATT&CK tactic tags are hyphenated", f"found {underscored}")
        check(rule.name in readme, f"{rule.name}: is documented in 07-detection-as-code/README.md")
    dupes = {k: v for k, v in seen.items() if len(v) > 1}
    check(not dupes, "rule ids are unique across all rule files", str(dupes))


def lint_lab_parity():
    print("detection-lab rule copies")
    for lab in sorted((ROOT / "detection-lab" / "detections").glob("*.yml")):
        main = ROOT / "07-detection-as-code" / lab.name
        same = main.exists() and main.read_bytes().replace(b"\r\n", b"\n") == lab.read_bytes().replace(b"\r\n", b"\n")
        check(same, f"detection-lab/detections/{lab.name} is identical to 07-detection-as-code/{lab.name}")


if __name__ == "__main__":
    lint_props_and_transforms()
    lint_indexes_and_metadata()
    lint_savedsearches()
    lint_markdown_spl()
    lint_sigma()
    lint_lab_parity()
    print(f"\n{TOTAL} checks, {len(FAILS)} failed")
    sys.exit(1 if FAILS else 0)
