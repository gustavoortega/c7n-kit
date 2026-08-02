"""Tests for kit/dashboard.py. No credentials, no network.

`_Policy` is a local double, deliberately NOT imported from kit/policies.py:
`generate`/`orphans` duck-type on `.name` / `.metadata` / `.resource` (see
the module docstring), so the file can be copied standalone, same pattern
as tests/test_coverage.py.
"""
import json
from dataclasses import dataclass, field

import pytest

from kit.dashboard import (
    AmbiguousMetadataError,
    IncompatibleMarkerError,
    MissingManifestError,
    TemplateWithoutMarkersError,
    UnresolvedMarkerError,
    generate,
    orphans,
)


@dataclass
class _Policy:
    name: str
    resource: str = "aws.ec2"
    metadata: dict = field(default_factory=dict)


def _p(name, resource="aws.ec2", **metadata):
    return _Policy(name, resource=resource, metadata=metadata)


POLICIES = [
    _p("ec2-imdsv2-not-enforced", severity="high", category="identity", frameworks=["FSBP EC2.8"]),
    _p("rds-storage-unencrypted", resource="aws.rds", severity="high", category="encryption",
       frameworks=["PCI 3.5.1"]),
]


# ────────────────────────────────────────── generate(): unresolved marker


def test_unknown_marker_fails():
    # Typo on purpose: "rule" in singular isn't a valid field (the real
    # field is "rules"). This has to fail, not leave the string as-is in
    # the output dashboard.
    template = {"names": "@@c7n:rule@@"}
    with pytest.raises(UnresolvedMarkerError):
        generate(POLICIES, template)


def test_known_field_with_typo_in_delimiter_also_fails():
    # A typo in the DELIMITER (missing the second "@") doesn't match the
    # regex at all, so it doesn't count as a marker, and a template with
    # NO valid marker falls into the other check (see below). Documented
    # here on purpose so it's clear "almost matches" counts neither as
    # resolved nor as a field error: it counts as "no marker at all."
    template = {"names": "@@c7n:rules@"}
    with pytest.raises(TemplateWithoutMarkersError):
        generate(POLICIES, template)


# ─────────────────────────────────────── generate(): template with no markers


def test_template_without_markers_fails():
    # 100% static template: it didn't cite a single datum from the repo.
    # Generating it "successfully" would produce a dashboard that looks
    # valid but depends on nothing real, worse than not generating it.
    template = {"title": "Security dashboard", "rules": ["hardcoded-1", "hardcoded-2"]}
    with pytest.raises(TemplateWithoutMarkersError):
        generate(POLICIES, template)


def test_template_with_a_single_marker_does_not_fail():
    template = {"title": "Dashboard", "rules": "@@c7n:rules@@"}
    dashboard = generate(POLICIES, template)
    assert dashboard["rules"] == ["ec2-imdsv2-not-enforced", "rds-storage-unencrypted"]


# ───────────────────────────────────────────── generate(): types and content


def test_marker_that_is_the_whole_string_preserves_the_type():
    # "@@c7n:severities@@" alone, with no surrounding text -> the value
    # has to be a real dict, not its text representation.
    template = {"severities": "@@c7n:severities@@"}
    dashboard = generate(POLICIES, template)
    assert dashboard["severities"] == {"ec2-imdsv2-not-enforced": "high", "rds-storage-unencrypted": "high"}


def test_marker_embedded_in_longer_text_gets_replaced_as_text():
    template = {"rules": "@@c7n:rules@@", "summary": "There are @@c7n:total_rules@@ active rules."}
    dashboard = generate(POLICIES, template)
    assert dashboard["summary"] == "There are 2 active rules."


def test_missing_severity_is_none_not_a_default():
    # Rule of the kit: an absence is not a zero (nor a made-up "low").
    policies = [_p("no-metadata")]
    template = {"severities": "@@c7n:severities@@"}
    dashboard = generate(policies, template)
    assert dashboard["severities"] == {"no-metadata": None}


def test_dict_embedded_in_longer_text_fails():
    template = {"rules": "@@c7n:rules@@", "summary": "Severities: @@c7n:severities@@"}
    with pytest.raises(IncompatibleMarkerError):
        generate(POLICIES, template)


def test_framework_and_frameworks_at_once_raises():
    policies = [_Policy("ambiguous-rule", metadata={"framework": "PCI 3.5.1", "frameworks": ["FSBP EC2.8"]})]
    template = {"frameworks": "@@c7n:frameworks@@"}
    with pytest.raises(AmbiguousMetadataError):
        generate(policies, template)


# ───────────────────────────────── generate(): a renamed rule comes out with
#                                     the NEW name (the original problem)


def test_renamed_rule_shows_up_in_the_dashboard_with_the_new_name():
    # This is the problem that motivates the ENTIRE module: if the
    # dashboard had the old name written by hand, the day of the rename
    # the row silently disappears. generate() reads the policy repo at the
    # moment it runs, so the new name shows up on its own, with no need to
    # touch the template.
    policies_before = [_p("sg-ssh-open-to-world", resource="aws.security-group", severity="critical")]
    policies_after = [_p("sg-public-access", resource="aws.security-group", severity="critical")]

    template = {"rules": "@@c7n:rules@@"}
    dashboard_before = generate(policies_before, template)
    dashboard_after = generate(policies_after, template)

    assert dashboard_before["rules"] == ["sg-ssh-open-to-world"]
    assert dashboard_after["rules"] == ["sg-public-access"]
    assert "sg-ssh-open-to-world" not in dashboard_after["rules"]


# ──────────────────────────────────────────────────────────────── orphans


def test_orphans_empty_when_nothing_was_renamed():
    template = {"rules": "@@c7n:rules@@"}
    dashboard = generate(POLICIES, template)
    assert orphans(dashboard, POLICIES) == []


def test_orphans_without_manifest_raises_instead_of_saying_zero():
    # A dashboard that never went through generate() (or that had its
    # manifest deleted) has no honest way to answer "no orphans", that
    # would read the missing datum as if it were a zero.
    unrelated_dashboard = {"title": "some dashboard", "panels": []}
    with pytest.raises(MissingManifestError):
        orphans(unrelated_dashboard, POLICIES)


def test_orphans_finds_a_renamed_rule_over_the_real_structure():
    """THE case that matters most (see the module docstring, "THE REAL
    TRAP"): a real tool (OpenSearch/Kibana) stores a panel's definition as
    JSON *serialized inside a string field*, not as a nested sub-object.
    If `orphans` searched for the manifest by doing `json.dumps(dashboard)`
    and a regex over that text, the quotes that were already escaped from
    coming out of that string field would get escaped a SECOND time, and
    the search would find nothing, exactly the real bug that motivated
    this module ("detected zero names on a real dashboard"). This
    dashboard reproduces that shape on purpose.
    """
    manifest = {"other_field": "whatever", "__c7n_manifest__": ["sg-ssh-open-to-world", "rds-storage-unencrypted"]}
    opensearch_style_dashboard = {
        "title": "real dashboard",
        "panel_1": {
            # This value is a STRING that contains serialized JSON, the
            # real pattern of searchSourceJSON/visState in OpenSearch/Kibana.
            "searchSourceJSON": json.dumps(manifest),
        },
    }
    current_policies = [_p("sg-public-access"), _p("rds-storage-unencrypted")]

    result = orphans(opensearch_style_dashboard, current_policies)

    # "sg-ssh-open-to-world" was renamed to "sg-public-access": it has to
    # show up as an orphan. "rds-storage-unencrypted" still exists: it
    # shouldn't.
    assert result == ["sg-ssh-open-to-world"]

    # Explicit proof of THE TRAP: the naive approach (re-serializing the
    # whole dashboard and searching for the key between quotes) finds
    # nothing, because `searchSourceJSON` already comes escaped and a
    # second round of `json.dumps` escapes it again. This is exactly what
    # made the old check a no-op that stayed green.
    reserialized_text = json.dumps(opensearch_style_dashboard)
    assert '"__c7n_manifest__"' not in reserialized_text


def test_orphans_does_not_report_rules_that_are_still_active():
    template = {"rules": "@@c7n:rules@@"}
    dashboard = generate(POLICIES, template)
    # No rename at all: nothing should show up as an orphan.
    assert orphans(dashboard, POLICIES) == []
