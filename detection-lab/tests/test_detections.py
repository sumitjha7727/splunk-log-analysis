"""test_detections.py — lightweight local Sigma-rule matcher for
fixture replay in CI.

This is NOT a real SPL execution engine and does not talk to a Splunk
service container - it evaluates each Sigma rule's `detection` block
directly against JSON fixture events in Python, as a fast,
dependency-light proxy for "would Splunk's search have matched this
event."

FIDELITY LIMITATION, stated plainly (see detection-lab/README.md's CI
section for the same note): this matcher only evaluates a rule's
single-event `selection` criteria. It does NOT evaluate:
  - aggregation conditions (count(), dc(), avg(), a comparison against
    a `timeframe` window) - e.g. ssh-failed-login-threshold.yml,
    dhcp-lease-anomaly.yml, dns-tunneling-high-cardinality.yml
  - correlation rules (a `correlation:` block instead of `detection:`)
    - e.g. ssh-bruteforce-then-success.yml, which has no `detection:`
      block for this matcher to evaluate at all
A "pass" against one of those rules only confirms the per-event
selection criteria matched, not the full grouped/windowed condition a
real Splunk alert would evaluate. Real coverage on those rules needs
either a real Splunk instance in CI (out of scope per B2) or a
purpose-built aggregation simulator - this lightweight matcher is
neither.

Fixtures are intentionally empty as of this scaffold (see
fixtures/README.md) - this suite is written to report that plainly via
a skip, not to pass trivially by finding nothing to check.
"""
from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest
import yaml

DETECTIONS_DIR = pathlib.Path(__file__).parent.parent / "detections"
FIXTURES_DIR = pathlib.Path(__file__).parent / "fixtures"

# Rules with no evaluable `detection.selection` block for this
# lightweight matcher (correlation rules) - listed explicitly rather
# than inferred, so a new rule added later doesn't silently fall into
# partial evaluation without a reviewer noticing.
CORRELATION_RULES = {"ssh-bruteforce-then-success.yml"}

# Rules whose `condition` involves aggregation (count/dc/avg plus a
# comparison, scoped by a `timeframe`) - this matcher checks their
# `selection` block only, not the aggregation threshold itself.
AGGREGATION_RULES = {
    "ssh-failed-login-threshold.yml",
    "dhcp-lease-anomaly.yml",
    "dns-tunneling-high-cardinality.yml",
}


def load_rule(path: pathlib.Path) -> dict:
    with path.open() as f:
        return yaml.safe_load(f)


def _field_matches(event: dict, field_spec: str, expected: Any) -> bool:
    """Evaluates one `field` or `field|modifier` selection key against an event."""
    if "|" in field_spec:
        field, modifier = field_spec.split("|", 1)
    else:
        field, modifier = field_spec, None

    if modifier == "exists":
        present = field in event
        return present if expected else not present

    value = event.get(field)
    if value is None:
        return False
    value = str(value)

    expected_list = expected if isinstance(expected, list) else [expected]
    for exp in expected_list:
        exp = str(exp)
        if modifier == "contains":
            if exp in value:
                return True
        elif modifier == "endswith":
            if value.endswith(exp):
                return True
        elif modifier == "startswith":
            if value.startswith(exp):
                return True
        elif modifier is None:
            # Sigma wildcards ('*') aren't translated here - exact
            # match only, on purpose, to keep this matcher simple and
            # auditable rather than reimplementing Sigma's full value
            # grammar.
            if exp == value:
                return True
    return False


def selection_matches(event: dict, selection: dict) -> bool:
    """AND across every key in one selection block."""
    return all(_field_matches(event, k, v) for k, v in selection.items())


def evaluate_rule(rule: dict, event: dict) -> bool:
    """
    Best-effort evaluation of a rule's `detection` block against one
    event. Only handles the two condition shapes actually used in
    detections/ as of this writing: a bare `selection`, and
    `1 of selection_*`. Raises for anything else, rather than
    guessing at an unfamiliar condition shape.
    """
    detection = rule.get("detection")
    if detection is None:
        raise ValueError(f"{rule.get('title')}: no `detection` block - correlation rule?")

    condition = detection.get("condition", "")
    if condition.strip() == "selection":
        return selection_matches(event, detection["selection"])

    if condition.strip().startswith("1 of selection_"):
        prefix = condition.strip().split("1 of ")[1].rstrip("*")
        sub_selections = [v for k, v in detection.items() if k.startswith(prefix)]
        return any(selection_matches(event, sel) for sel in sub_selections)

    raise NotImplementedError(
        f"condition shape {condition!r} not handled by this lightweight matcher"
    )


def discover_fixtures() -> list[pathlib.Path]:
    if not FIXTURES_DIR.exists():
        return []
    return sorted(FIXTURES_DIR.glob("*/*.json"))


FIXTURE_FILES = discover_fixtures()


def test_fixtures_present_or_explicitly_skipped():
    """
    Exists so a fixture-less run reports *why* nothing else ran,
    instead of the suite quietly reporting "0 passed" with no
    explanation. See fixtures/README.md - fixtures are populated only
    from real campaign runs, never generated synthetically, so an
    empty result here is expected until attacks/run_campaign.py has
    actually been run against a real lab.
    """
    if not FIXTURE_FILES:
        pytest.skip(
            "No fixtures yet under tests/fixtures/{true_positive,benign}/ - "
            "populated only from real Atomic Red Team campaign runs "
            "(attacks/run_campaign.py), not generated synthetically. "
            "This is expected for a freshly scaffolded detection-lab."
        )


@pytest.mark.parametrize("fixture_path", FIXTURE_FILES, ids=lambda p: p.stem)
def test_fixture_matches_expected_outcome(fixture_path: pathlib.Path):
    with fixture_path.open() as f:
        fixture = json.load(f)

    rule_name = fixture["rule"]
    rule_path = DETECTIONS_DIR / rule_name
    assert rule_path.exists(), f"{rule_name} referenced by {fixture_path.name} not found in detections/"

    if rule_name in CORRELATION_RULES:
        pytest.skip(
            f"{rule_name} is a correlation rule - not evaluable by this "
            f"lightweight single-event matcher. See this file's module "
            f"docstring for the fidelity limitation."
        )

    rule = load_rule(rule_path)
    matched = evaluate_rule(rule, fixture["event"])

    if rule_name in AGGREGATION_RULES:
        # We can only confirm the per-event selection criteria matched,
        # not the full aggregation threshold - report as an explicit
        # partial check rather than a full pass/fail.
        assert matched, (
            f"{fixture_path.name}: event doesn't even match {rule_name}'s "
            f"per-event selection - the full aggregation condition was "
            f"never going to be checkable by this matcher, but the "
            f"selection-level mismatch is still a real finding."
        )
        pytest.skip(
            f"{rule_name}: selection-level match confirmed, but this is an "
            f"aggregation rule - the count/avg threshold itself isn't "
            f"evaluated by this lightweight matcher (see module docstring)."
        )

    expected = fixture["expected"]
    if expected == "true_positive":
        assert matched, f"{fixture_path.name}: expected a match against {rule_name}, got none"
    elif expected == "false_positive":
        assert matched, (
            f"{fixture_path.name}: fixture is filed as an (unwanted) false "
            f"positive match, but this matcher doesn't reproduce it - "
            f"re-check whether the fixture or the rule has drifted"
        )
    else:
        pytest.fail(f"{fixture_path.name}: unrecognized `expected` value {expected!r}")
