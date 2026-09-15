"""Tests for c7n_kit/trace.py. No credentials, no network.

The contract that matters is the last one: for a policy with no unknown
nodes, the root of the trace has to agree with what c7n's own engine says
about the whole policy. A per-node view that disagrees with the real
verdict is worse than no view at all, because it looks like an explanation.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from c7n_kit.testing import run_policy
from c7n_kit.trace import MATCH, NO_MATCH, UNKNOWN, Node, flatten, trace, _combine

POLICY = {
    "name": "rds-storage-unencrypted",
    "resource": "aws.rds",
    "filters": [
        {"or": [
            {"type": "value", "key": "StorageEncrypted", "value": False},
            {"type": "value", "key": "StorageEncrypted", "value": "absent"},
        ]}
    ],
}

NEEDS_AWS = {
    "name": "rds-snapshot-shared-cross-account",
    "resource": "aws.rds-snapshot",
    "filters": [{"type": "cross-account"}],
}


def _leaves(root: Node) -> list[Node]:
    return [n for n in flatten(root) if not n.children]


def test_the_branch_that_fired_is_the_one_reported():
    root = trace(POLICY, {"DBInstanceIdentifier": "b", "StorageEncrypted": False})

    first, second = _leaves(root)
    assert first.result == MATCH
    assert second.result == NO_MATCH
    assert root.result == MATCH


def test_the_absent_branch_is_the_only_reason_this_one_is_reported():
    """The case the whole catalogue is about: AWS never sent the field, so
    the `value: false` branch does not match (None == False is False) and
    only the `absent` branch does."""
    root = trace(POLICY, {"DBInstanceIdentifier": "c"})

    value_branch, absent_branch = _leaves(root)
    assert value_branch.result == NO_MATCH
    assert absent_branch.result == MATCH
    assert root.result == MATCH


def test_nothing_matches_when_the_resource_is_clean():
    root = trace(POLICY, {"DBInstanceIdentifier": "a", "StorageEncrypted": True})

    assert [n.result for n in _leaves(root)] == [NO_MATCH, NO_MATCH]
    assert root.result == NO_MATCH


def test_a_filter_that_needs_aws_is_unknown_not_a_pass():
    root = trace(NEEDS_AWS, {"DBSnapshotIdentifier": "snap-1"})

    assert root.result == UNKNOWN
    assert _leaves(root)[0].result == UNKNOWN


def test_unknown_propagates_the_way_a_missing_answer_should():
    unknown = Node("value", UNKNOWN, {})
    match = Node("value", MATCH, {})
    no_match = Node("value", NO_MATCH, {})

    # an `and` that already has a false child is false, whatever else is
    # unreadable: one condition failing is enough
    assert _combine("and", [no_match, unknown]) == NO_MATCH
    assert _combine("and", [match, unknown]) == UNKNOWN
    # an `or` that already has a true child is true
    assert _combine("or", [match, unknown]) == MATCH
    assert _combine("or", [no_match, unknown]) == UNKNOWN
    # the negation of "we could not look" is still "we could not look"
    assert _combine("not", [unknown]) == UNKNOWN
    assert _combine("not", [match]) == NO_MATCH


def test_root_agrees_with_c7n_when_nothing_is_unknown(tmp_path):
    """The contract: a trace with no unknown node reports exactly what the
    policy itself reports. If these ever disagree, the per-node view is
    wrong and the site built on it would be showing an explanation of an
    answer nobody gave."""
    import yaml

    path = tmp_path / "policies.yml"
    path.write_text(yaml.safe_dump({"policies": [POLICY]}), encoding="utf-8")

    resources = [
        {"DBInstanceIdentifier": "matches", "StorageEncrypted": False},
        {"DBInstanceIdentifier": "clean", "StorageEncrypted": True},
        {"DBInstanceIdentifier": "key-absent"},
        {"DBInstanceIdentifier": "weird", "StorageEncrypted": "no"},
    ]

    matched = {r["DBInstanceIdentifier"] for r in
               run_policy(str(path), POLICY["name"], resources)}

    for resource in resources:
        root = trace(POLICY, resource)
        assert UNKNOWN not in [n.result for n in flatten(root)]
        expected = MATCH if resource["DBInstanceIdentifier"] in matched else NO_MATCH
        assert root.result == expected, resource
