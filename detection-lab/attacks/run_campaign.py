#!/usr/bin/env python3
"""run_campaign.py — orchestrates an Atomic Red Team test campaign
against detection-lab's victim hosts and records a timestamped
manifest of what ran, so results can later be correlated against
which Sigma detections actually fired in Splunk.

SAFETY: this script executes REAL attack techniques against REAL hosts
when run with --execute. Several Atomic Red Team tests leave
persistence mechanisms behind (scheduled tasks, registry run keys,
cron entries, new user accounts) that are NOT automatically cleaned
up by this script. Never run this against anything but the isolated
lab network described in this project's README.md - snapshot every
VM before a live run, and restore from that snapshot afterward rather
than trusting any test's own cleanup steps.

This script orchestrates and records; it does not reimplement Atomic
Red Team's own test executors. It currently only supports a dry run
end to end - `run_test_live` is a deliberate stub (see below) that
needs to be wired up to this lab's actual remote-execution path
(WinRM/PSRemoting for win-victim, SSH for linux-victim) before
--execute can do anything real. That wiring is lab-build work, not
something safe to fabricate here without a real lab to test it
against.

Usage:
    python run_campaign.py --plan atomics.yml                 # dry run (default)
    python run_campaign.py --plan atomics.yml --execute --i-understand-the-risk
"""
from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import sys

try:
    import yaml
except ImportError:
    sys.exit("Missing dependency: pip install pyyaml")


def load_plan(path: pathlib.Path) -> dict:
    with path.open() as f:
        return yaml.safe_load(f)


def run_test_dry(test: dict) -> dict:
    """Records what *would* run, without touching any host."""
    return {
        "id": test.get("id"),
        "name": test.get("name"),
        "platform": test.get("platform"),
        "target_host": test.get("target_host"),
        "status": "dry_run_not_executed",
    }


def run_test_live(test: dict) -> dict:
    """
    Actually invoke the atomic test against its target host.

    Deliberately left as a stub. The real invocation is
    platform-specific:
      - Windows victim: Invoke-AtomicTest over PowerShell remoting
        (WinRM), using the Invoke-AtomicRedTeam module cloned by
        lab/ansible/playbooks/attacker.yml.
      - Linux victim / attacker-initiated tests: a direct SSH
        invocation of the relevant atomics/<technique>/*.sh, or the
        Linux-compatible path through Invoke-AtomicRedTeam.
      - Tests marked with a `note` instead of an `id` in atomics.yml
        have no canonical Atomic Red Team test at all and need a
        manual script - see the note text in atomics.yml for what
        each of those actually requires.

    Wire this up against your own lab's actual remote-execution setup
    (the WinRM/SSH credentials your Ansible run configured) before
    using --execute - this stub intentionally refuses to guess at
    that, rather than silently doing nothing while claiming success.
    """
    raise NotImplementedError(
        f"run_test_live is a stub - wire up remote execution for "
        f"test {test.get('id') or '(manual)'} on {test.get('target_host')} "
        f"before using --execute. See this function's docstring."
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--plan", type=pathlib.Path, default=pathlib.Path(__file__).parent / "atomics.yml"
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually run the tests instead of a dry run. Requires --i-understand-the-risk.",
    )
    parser.add_argument(
        "--i-understand-the-risk",
        action="store_true",
        dest="ack_risk",
        help="Required alongside --execute, to make an accidental live run harder.",
    )
    parser.add_argument(
        "--manifest-dir",
        type=pathlib.Path,
        default=pathlib.Path(__file__).parent / "manifests",
    )
    args = parser.parse_args()

    if args.execute and not args.ack_risk:
        sys.exit(
            "Refusing to --execute without --i-understand-the-risk. "
            "Read the isolation warning in this project's README.md first."
        )

    plan = load_plan(args.plan)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    manifest = {
        "timestamp_utc": timestamp,
        "plan_file": str(args.plan),
        "executed": args.execute,
        "results": [],
    }

    for detection in plan.get("detections", []):
        for test in detection.get("atomic_tests", []):
            if not args.execute:
                result = run_test_dry(test)
            else:
                try:
                    result = run_test_live(test)
                except NotImplementedError as e:
                    result = {
                        "id": test.get("id"),
                        "status": "not_implemented",
                        "error": str(e),
                    }
            result["rule"] = detection.get("rule")
            result["technique"] = detection.get("technique")
            manifest["results"].append(result)

    args.manifest_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.manifest_dir / f"campaign-{timestamp}.json"
    with out_path.open("w") as f:
        json.dump(manifest, f, indent=2)

    print(f"Manifest written to {out_path}")
    if not args.execute:
        print("This was a dry run - no hosts were touched. Pass --execute --i-understand-the-risk for a real campaign.")


if __name__ == "__main__":
    main()
