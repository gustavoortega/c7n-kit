"""Tests for kit/cadence.py. No credentials, no network.

`_Policy` is a local double, deliberately NOT imported from
kit/policies.py: cadence.py's contract is duck typing on `.name` /
`.resource` / `.metadata` (see the module docstring), precisely so the
file can be copied alone. Using the real dataclass here would tie it back
together.
"""
import os
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from kit.cadence import policy_cadence, cadence_by_type, promoted_to_fast


@dataclass
class _Policy:
    name: str
    resource: str
    metadata: dict = field(default_factory=dict)


def _p(name, resource, frequency=None):
    return _Policy(name, resource, {"frequency": frequency} if frequency else {})


def test_undeclared_runs_on_the_fast_cadence_by_default():
    assert policy_cadence(_p("x", "aws.ec2")) == "4h"


def test_declared_frequency_is_respected():
    assert policy_cadence(_p("x", "aws.ec2", "daily")) == "daily"


def test_type_with_rules_on_both_cadences_resolves_to_the_fast_one():
    """c7n-org enumerates once per type: if a type with rules in both 4h
    and daily resolved to daily (or if both were left running
    separately), the whole point of separating by cadence is lost -- or
    the type gets enumerated twice, which is more expensive than not
    separating at all.
    """
    policies = [
        _p("rule-rapida", "aws.s3", "4h"),
        _p("rule-lenta-1", "aws.s3", "daily"),
        _p("rule-lenta-2", "aws.s3", "daily"),
    ]

    by_type = cadence_by_type(policies)

    assert by_type["aws.s3"] == "4h"


def test_uniform_type_is_not_promoted():
    policies = [_p("a", "aws.ec2", "daily"), _p("b", "aws.ec2", "daily")]

    assert cadence_by_type(policies) == {"aws.ec2": "daily"}
    assert promoted_to_fast(policies) == {}


def test_invalid_frequency_raises():
    with pytest.raises(ValueError):
        policy_cadence(_p("x", "aws.ec2", "dayly"))  # real typo, not a cadence


def test_invalid_frequency_does_not_fall_back_to_default_or_pass_unnoticed():
    """A typo in frequency has to raise as soon as that policy is
    evaluated, not slip through as if it were '4h' (would run too often,
    expensive) or as 'daily' (would run too rarely, invisible). Checked
    against `cadence_by_type`, which is the function actually used in
    production.
    """
    policies = [_p("con-typo", "aws.rds", "dayly")]

    with pytest.raises(ValueError):
        cadence_by_type(policies)


def test_promoted_to_fast_names_the_culprit_policy():
    """The concrete cost lever: a mostly-slow type dragged into the
    expensive cadence by a single rule has to say WHICH rule it is, so
    lowering its cadence is an actionable move and not a guessing game.
    """
    policies = [
        _p("la-culpable", "aws.lambda", "4h"),
        _p("rule-lenta-1", "aws.lambda", "daily"),
        _p("rule-lenta-2", "aws.lambda", "daily"),
        _p("otro-tipo-sin-mezcla", "aws.ec2", "daily"),
    ]

    promoted = promoted_to_fast(policies)

    assert promoted == {"aws.lambda": ["la-culpable"]}
    assert "aws.ec2" not in promoted


def test_promoted_to_fast_lists_several_culprits_when_there_is_more_than_one():
    policies = [
        _p("culpable-1", "aws.lambda", "4h"),
        _p("culpable-2", "aws.lambda", "4h"),
        _p("rule-lenta", "aws.lambda", "daily"),
    ]

    promoted = promoted_to_fast(policies)

    assert promoted["aws.lambda"] == ["culpable-1", "culpable-2"]


def test_cadences_are_configurable_not_just_4h_daily():
    """The order of `cadences` defines which is the fastest: whoever uses
    the kit with their own frequencies doesn't have to touch the code,
    just pass their own tuple ordered from fastest to slowest.
    """
    cadences = ("hourly", "4h", "weekly")
    policies = [_p("a", "aws.s3", "weekly"), _p("b", "aws.s3", "hourly")]

    assert cadence_by_type(policies, cadences=cadences) == {"aws.s3": "hourly"}


def test_missing_metadata_is_an_empty_dict_not_an_error():
    """A Policy object with no `metadata` at all (not `metadata: {}`, but
    the attribute entirely absent) has to be treated as undeclared, not
    explode: `metadata` is an optional block in a real c7n policy.
    """
    class _NoMetadata:
        name = "x"
        resource = "aws.ec2"

    assert policy_cadence(_NoMetadata()) == "4h"
