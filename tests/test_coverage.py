"""Tests for c7n_kit/coverage.py. No credentials, no network.

`_Policy` is a local double, deliberately NOT imported from
c7n_kit/policies.py: `coverage()` duck types on `.name` / `.metadata` /
`.file` (see the module docstring), so the file can be copied alone.
"""
from dataclasses import dataclass, field

import pytest

from c7n_kit.coverage import (
    InvalidCatalogError,
    AmbiguousMetadataError,
    load_catalog,
    coverage,
)


@dataclass
class _Policy:
    name: str
    file: str = "test.yaml"
    metadata: dict = field(default_factory=dict)


def _p(name, frameworks=None, framework=None):
    metadata = {}
    if frameworks is not None:
        metadata["frameworks"] = frameworks
    if framework is not None:
        metadata["framework"] = framework
    return _Policy(name, metadata=metadata)


CATALOG = ["FSBP RDS.1", "FSBP RDS.3", "CIS 2.1.1", "PCI 3.5.1"]
FSBP_ONLY_CATALOG = ["FSBP RDS.1", "FSBP RDS.3"]


def test_cited_control_missing_from_catalog_is_orphan():
    # This is THE case that justifies the module: a policy citing a
    # nonexistent control cannot add to coverage without it being noticed.
    policies = [_p("rule-1", frameworks=["FSBP RDS.99"])]
    result = coverage(policies, CATALOG)
    assert "FSBP RDS.99" in result.orphans
    assert result.covered == {}


def test_cited_control_that_exists_is_not_orphan_and_covers():
    policies = [_p("rule-1", frameworks=["FSBP RDS.1"])]
    result = coverage(policies, CATALOG)
    assert result.orphans == []
    assert result.covered == {"FSBP RDS.1": ["rule-1"]}


def test_catalog_controls_with_no_policy_are_missing():
    policies = [_p("rule-1", frameworks=["FSBP RDS.1"])]
    result = coverage(policies, CATALOG)
    assert set(result.missing) == {"FSBP RDS.3", "CIS 2.1.1", "PCI 3.5.1"}


def test_framework_and_frameworks_at_the_same_time_raises():
    policies = [_p("ambiguous-rule", frameworks=["FSBP RDS.1"], framework="PCI 3.5.1")]
    with pytest.raises(AmbiguousMetadataError):
        coverage(policies, CATALOG)


def test_singular_framework_is_accepted_like_frameworks():
    policies = [_p("rule-1", framework="FSBP RDS.1")]
    result = coverage(policies, CATALOG)
    assert result.covered == {"FSBP RDS.1": ["rule-1"]}


def test_policy_without_frameworks_covers_nothing_and_does_not_explode():
    policies = [_p("rule-sin-metadata")]
    result = coverage(policies, CATALOG)
    assert result.covered == {}
    assert result.orphans == []


def test_two_policies_cover_the_same_control():
    policies = [
        _p("rule-1", frameworks=["FSBP RDS.1"]),
        _p("rule-2", frameworks=["FSBP RDS.1"]),
    ]
    result = coverage(policies, CATALOG)
    assert result.covered == {"FSBP RDS.1": ["rule-1", "rule-2"]}


def test_by_family_counts_covered_over_catalog_total():
    policies = [_p("rule-1", frameworks=["FSBP RDS.1"])]
    result = coverage(policies, CATALOG)
    # catalog has 2 FSBP controls (RDS.1, RDS.3), 1 covered
    assert result.by_family["FSBP"] == (1, 2)
    assert result.by_family["CIS"] == (0, 1)
    assert result.by_family["PCI"] == (0, 1)


def test_control_from_a_family_not_in_the_catalog_is_ignored():
    # A family the catalog doesn't evaluate (e.g. "ISO", when the catalog
    # is FSBP/CIS/PCI) can't invent an entry in by_family -- that would
    # report a total that isn't the real catalog's.
    policies = [_p("rule-1", frameworks=["ISO A.5.1"])]
    result = coverage(policies, CATALOG)
    assert "ISO" not in result.by_family
    # And it's NOT an orphan either: "ISO" isn't this catalog's business,
    # so it doesn't even get evaluated (see the next test for the case
    # this exists to fix).
    assert result.orphans == []


def test_control_from_another_family_is_not_orphan_it_is_ignored_silently():
    # THE bug that motivated this test: a real policy cites several
    # frameworks at once (`frameworks: ['CIS 5.6', 'FSBP EC2.8']`). If
    # coverage() runs with only the FSBP catalog, "PCI 3.4" isn't a
    # nonexistent control -- it's a control that isn't this cross-check's
    # business. Before this fix, any control outside the catalog passed
    # in (regardless of family) was marked orphan, and `orphans`
    # screamed on every real run with noise from the OTHER frameworks the
    # policy also cites -- useless for exactly the case it exists for.
    policies = [_p("rule-multiframework", frameworks=["FSBP RDS.99", "PCI 3.4"])]
    result = coverage(policies, FSBP_ONLY_CATALOG)
    assert result.orphans == ["FSBP RDS.99"]
    assert result.covered == {}
    assert result.missing == ["FSBP RDS.1", "FSBP RDS.3"]


def test_evaluated_families_reflects_the_families_of_the_catalog_passed():
    result = coverage([], CATALOG)
    assert result.families_evaluated == ["CIS", "FSBP", "PCI"]

    result_fsbp_only = coverage([], FSBP_ONLY_CATALOG)
    assert result_fsbp_only.families_evaluated == ["FSBP"]


def test_two_word_family_sox_itgc_is_recognized_whole():
    # If "SOX ITGC" weren't treated as a single family, `_family` would
    # read only "SOX," and a real SOX ITGC.1 control would never match
    # the SOX catalog's family ("SOX ITGC") -- it would get silently
    # dropped from the cross-check even though it cites a legitimate
    # control.
    sox_catalog = ["SOX ITGC 1.1", "SOX ITGC 1.2"]
    policies = [_p("rule-sox", frameworks=["SOX ITGC 1.1"])]
    result = coverage(policies, sox_catalog)
    assert result.covered == {"SOX ITGC 1.1": ["rule-sox"]}
    assert result.families_evaluated == ["SOX ITGC"]


def test_catalog_with_two_word_family_sox_itgc_loads_fine(tmp_path):
    # A "SOX ITGC 1.1" line has TWO spaces -- without the special case in
    # _CATALOG_LINE_RE, this would be rejected as malformed and the SOX
    # catalog could never load.
    file = tmp_path / "sox.txt"
    file.write_text("SOX ITGC 1.1\nSOX ITGC 1.2\n", encoding="utf-8")
    assert load_catalog(str(file)) == ["SOX ITGC 1.1", "SOX ITGC 1.2"]


# --- load_catalog() ---


def test_catalog_with_duplicate_lines_raises(tmp_path):
    file = tmp_path / "cat.txt"
    file.write_text("FSBP RDS.1\nFSBP RDS.3\nFSBP RDS.1\n", encoding="utf-8")
    with pytest.raises(InvalidCatalogError):
        load_catalog(str(file))


def test_catalog_with_malformed_line_raises(tmp_path):
    file = tmp_path / "cat.txt"
    # tab instead of space: doesn't match the "<FAMILY> <ID>" format
    file.write_text("FSBP\tRDS.1\n", encoding="utf-8")
    with pytest.raises(InvalidCatalogError):
        load_catalog(str(file))


def test_valid_catalog_ignores_comments_and_blank_lines(tmp_path):
    file = tmp_path / "cat.txt"
    file.write_text(
        "# comment\nFSBP RDS.1\n\nFSBP RDS.3\n",
        encoding="utf-8",
    )
    assert load_catalog(str(file)) == ["FSBP RDS.1", "FSBP RDS.3"]


def test_the_kits_real_catalogs_load_without_error():
    # Doesn't validate the CONTENT (that's covered by the manual
    # investigation, see each file's header), only that the format is
    # valid: without this, a real catalog with a broken line would only
    # be caught in production, running coverage() against real policies.
    for name in ("fsbp.txt", "cis-aws.txt", "pci-4.0.txt"):
        controls = load_catalog(f"catalogs/{name}")
        assert len(controls) > 0


# ── catalog completeness travels with the data ──────────────────────────────

def test_catalog_declares_whether_it_is_complete(tmp_path):
    """An incomplete catalog produces false orphans and coverage that lies
    low. Whoever reads the percentage needs to be able to tell which
    denominator it was computed over, and that can't depend on someone
    remembering to check the file's comment."""
    complete = tmp_path / "c.txt"
    complete.write_text("# complete: yes\nFSBP RDS.1\nFSBP RDS.2\n")
    partial = tmp_path / "p.txt"
    partial.write_text("# complete: no  (2 of 40)\nFSBP RDS.1\nFSBP RDS.2\n")
    silent = tmp_path / "m.txt"
    silent.write_text("# no declaration\nFSBP RDS.1\n")

    assert load_catalog(str(complete)).complete is True
    assert load_catalog(str(partial)).complete is False
    # `None` means unknown, NOT complete: the default can never be the
    # optimistic claim.
    assert load_catalog(str(silent)).complete is None


def test_completeness_reaches_the_report(tmp_path):
    partial = tmp_path / "p.txt"
    partial.write_text("# complete: no\nFSBP RDS.1\n")
    pol = [_p("p1", frameworks=["FSBP RDS.1"])]

    assert coverage(pol, load_catalog(str(partial))).catalog_complete is False
    # a plain list declares nothing, and that is NOT read as complete
    assert coverage(pol, ["FSBP RDS.1"]).catalog_complete is None
