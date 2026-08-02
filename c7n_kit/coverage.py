"""Cross-checks what policies CLAIM to cover against a catalog of controls.

This module doesn't measure whether a policy works: it measures whether
the policy -> control mapping is honest. There are two ways it can be
dishonest, and both are detectable without running anything:

  1. A policy cites a control, FROM THE FAMILY OF THE CATALOG PASSED IN,
     that doesn't exist in that catalog (typo, ID of a retired control,
     an old version of the framework). If that were ignored, the
     reported coverage would look higher than it really is and nobody
     would notice until an external audit. That's why `orphans` is a
     required field of `Coverage`, not an optional detail.
  2. A policy declares `metadata.framework` (singular, a string) AND
     `metadata.frameworks` (plural, a list) at the same time. There's no
     reasonable "who wins" rule: whichever one the code picks, someone
     is going to edit the other thinking it has an effect, and nothing
     will happen. That's why this raises instead of resolving silently.

THE FAMILY FILTER (why it exists)
A real policy maps to several frameworks at once, e.g.
`frameworks: ['CIS 5.6', 'FSBP EC2.8']`. If `coverage()` is called with
only the FSBP catalog, `CIS 5.6` can't be treated as an orphan: it's not
that the control doesn't exist, it's that this control isn't this
cross-check's business. The first version of this module didn't make
this distinction and treated any control missing from the catalog passed
in as an orphan -- the result was that `orphans` screamed on EVERY run
(with the controls from the other frameworks the policy also cites), it
became useless as a signal, and whoever consumed it ended up muting it.
That's why `coverage()` first computes which families the catalog has
(`evaluated_families`) and discards, without adding them to
covered/missing/orphans, any control cited from ANY OTHER family. Only
what is the catalog's own business enters the cross-check.

Rule of the kit: AN ABSENCE IS NOT A ZERO. If the catalog has no control
from a given family, that family simply doesn't appear in `by_family` --
it doesn't show up as "(0, 0)" mixed in with families that do exist and
are at real zero coverage. For the same reason, `evaluated_families`
exists so a "21% coverage" figure is never read without knowing over
which universe that percentage was computed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# Special case: "SOX ITGC" is a TWO-word family (unlike "FSBP", "CIS",
# "PCI"). Without this special case, `_family("SOX ITGC 1.1")` would
# return "SOX" alone, that "family" would never match the real family of
# the SOX catalog ("SOX ITGC"), and any policy citing a SOX control would
# end up silently dropped from the cross-check -- exactly the kind of
# "absence read as zero" this kit exists to prevent. It's declared HERE
# (not only in `_family`) because it's also needed to validate a catalog
# line: a "SOX ITGC 1.1" line has TWO spaces, and without this special
# case the SOX catalog couldn't even load.
_TWO_WORD_FAMILIES = ("SOX ITGC",)

# A catalog line is "<FAMILY> <ID>" with one separating space, except for
# the two-word-family special case (`_TWO_WORD_FAMILIES`), where it's two
# spaces: "SOX ITGC" + " " + "<ID>".
# FAMILY: letters (possibly with digits/dashes, e.g. "PCI", "CIS-AWS").
# ID: alphanumeric with dots (e.g. "RDS.1", "2.1.1", "3.5.1"). Any other
# shape (no space, with tabs, extra columns) is a formatting error:
# better to raise now than let a control through that will never match in
# `coverage()` and shows up as "missing" forever.
_TWO_WORD_FAMILY_ALT = "|".join(re.escape(f) for f in _TWO_WORD_FAMILIES)
_CATALOG_LINE_RE = re.compile(
    rf"^(?:{_TWO_WORD_FAMILY_ALT}|[A-Za-z][A-Za-z0-9_-]*) [A-Za-z0-9][A-Za-z0-9.]*$"
)


class AmbiguousMetadataError(ValueError):
    """A policy declares `framework` and `frameworks` at the same time.

    See the module docstring: there's no safe tiebreaker rule, so instead
    of picking one and surprising whoever edits the other, loading stops
    here.
    """


class InvalidCatalogError(ValueError):
    """The catalog file has duplicate or malformed lines.

    A duplicate inflates `by_family` (it counts the same control twice
    as "total"). A malformed line will never match any real
    `metadata.frameworks`, so the control is doomed to appear in
    `missing` forever even if it's covered -- neither case is allowed to
    pass quietly.
    """


class Catalog(list):
    """The list of controls, which ALSO knows whether it's complete.

    It's a subclass of `list` on purpose: the contract says
    `load_catalog` returns `list[str]`, and that's still true, but this
    way completeness travels attached to the data instead of being a
    separate parameter the caller can forget to pass.

    And forgetting it wouldn't be a minor detail. An incomplete catalog
    produces false orphans (a policy cites a control that exists but
    isn't in the file) and coverage that lies low. If completeness
    traveled as a separate boolean, the day someone doesn't pass it the
    report claims a completeness that nobody verified.

    `complete is None` means the catalog doesn't declare it. It does
    NOT mean complete.
    """
    __slots__ = ("complete", "path")

    def __init__(self, items, complete=None, path=None):
        super().__init__(items)
        self.complete = complete
        self.path = path


@dataclass
class Coverage:
    covered: dict[str, list[str]]  # control -> names of the policies covering it
    missing: list[str]  # catalog controls with no policy at all
    orphans: list[str]  # controls cited from the catalog's own family/families that are NOT in it
    by_family: dict[str, tuple[int, int]]  # family -> (covered, total)
    families_evaluated: list[str]  # families the catalog passed to this run had
    # `True`/`False` as declared by the catalog, `None` if it doesn't declare it.
    # A percentage computed over an incomplete catalog is not comparable to
    # one computed over a complete one, and whoever reads the number needs
    # to be able to tell which of the two they're looking at.
    catalog_complete: bool | None = None


_COMPLETE_RE = re.compile(r'^#\s*complete:\s*(yes|no)\b', re.I | re.M)


def load_catalog(path: str) -> list[str]:
    """Reads a catalog file (one control per line) and validates it.

    Doesn't delegate validation to `coverage()` because by the time the
    catalog gets there it's too late to tell whether a "missing" control
    is a real, unimplemented control or a control that could never match
    because the file had a tab instead of a space. It's validated here,
    with the file in view, so the error can point at the line number.
    """
    controls: list[str] = []
    seen: set[str] = set()
    duplicates: set[str] = set()
    malformed: list[tuple[int, str]] = []

    with Path(path).open("r", encoding="utf-8") as f:
        for number, raw_line in enumerate(f, start=1):
            line = raw_line.rstrip("\n")
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue  # blank line or comment: not a control
            if not _CATALOG_LINE_RE.match(stripped):
                malformed.append((number, line))
                continue
            if stripped in seen:
                duplicates.add(stripped)
            seen.add(stripped)
            controls.append(stripped)

    if malformed or duplicates:
        parts = []
        if malformed:
            detail = ", ".join(f"line {n}: {l!r}" for n, l in malformed)
            parts.append(f"malformed ({detail})")
        if duplicates:
            parts.append(f"duplicated ({', '.join(sorted(duplicates))})")
        raise InvalidCatalogError(f"{path}: " + "; ".join(parts))

    _m = _COMPLETE_RE.search(Path(path).read_text(encoding="utf-8"))
    _complete = None if _m is None else _m.group(1).lower() == 'yes'
    return Catalog(controls, complete=_complete, path=path)


def _family(control: str) -> str:
    """Returns the family of a control ("FSBP", "CIS", "PCI", "SOX ITGC").

    Used both to classify what a policy cites and to see which families a
    catalog has -- both sides of `coverage()` have to use the same rule
    to be comparable.
    """
    for family in _TWO_WORD_FAMILIES:
        if control == family or control.startswith(family + " "):
            return family
    return control.split(" ", 1)[0]


def _declared_controls(policy) -> list[str]:
    """Returns the controls a policy claims to cover, or [] if it claims none."""
    frameworks = policy.metadata.get("frameworks")
    framework = policy.metadata.get("framework")

    if frameworks is not None and framework is not None:
        raise AmbiguousMetadataError(
            f"{policy.name} ({policy.file}) declares 'framework' and "
            "'frameworks' at the same time"
        )
    if frameworks is not None:
        return list(frameworks)
    if framework is not None:
        return [framework]
    return []


def coverage(policies, catalog: list[str]) -> Coverage:
    """Cross-checks `policies` against `catalog` and builds the coverage report.

    `catalog` is the source of truth for which controls exist FOR ITS
    OWN FAMILY/FAMILIES (see `families_evaluated`). A real policy cites
    controls from several frameworks at once
    (`frameworks: ['CIS 5.6', 'FSBP EC2.8']`); if this function is called
    with only the FSBP catalog, `CIS 5.6` is neither orphan nor missing
    nor covered -- it's a control from a family this run never evaluated.
    Only what belongs to the catalog's own family/families enters the
    cross-check; everything else is ignored ON PURPOSE (see the module
    docstring, section "THE FAMILY FILTER").
    """
    catalog_set = set(catalog)  # defensive dedup; the real validation lives in load_catalog
    catalog_families = {_family(c) for c in catalog_set}

    covered: dict[str, list[str]] = {}
    orphans_set: set[str] = set()

    for policy in policies:
        for control in _declared_controls(policy):
            if _family(control) not in catalog_families:
                continue  # not this catalog's business: neither covers, nor is missing, nor an orphan
            if control in catalog_set:
                covered.setdefault(control, []).append(policy.name)
            else:
                orphans_set.add(control)

    missing = sorted(c for c in catalog_set if c not in covered)
    orphans = sorted(orphans_set)

    families_total: dict[str, int] = {}
    families_covered: dict[str, int] = {}
    for control in catalog_set:
        family = _family(control)
        families_total[family] = families_total.get(family, 0) + 1
        if control in covered:
            families_covered[family] = families_covered.get(family, 0) + 1

    by_family = {
        family: (families_covered.get(family, 0), total)
        for family, total in families_total.items()
    }

    # Completeness travels with the catalog, not as a separate parameter:
    # if it were a parameter, the day someone doesn't pass it the report
    # would claim a completeness nobody verified.
    return Coverage(
        covered=covered,
        missing=missing,
        orphans=orphans,
        by_family=by_family,
        families_evaluated=sorted(catalog_families),
        # `getattr`, not direct access: `coverage()` accepts any iterable
        # of controls, not just a `Catalog`. If a plain list is passed,
        # completeness stays `None`, which means "unknown," not
        # "complete."
        catalog_complete=getattr(catalog, "complete", None),
    )


def _cli(argv=None):
    """Coverage report from the command line.

    Without this, `python -m c7n_kit.coverage` imports the module, does
    nothing and exits 0. A command that exits clean without having done
    anything is the same shape of bug this kit chases, and this repo's
    README had it until this got run.
    """
    import sys
    from c7n_kit.policies import load

    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        sys.exit("usage: python -m c7n_kit.coverage <catalog.txt> <policies-directory>")

    catalog = load_catalog(argv[0])
    c = coverage(load(argv[1]), catalog)
    total = len(c.covered) + len(c.missing)

    for fam in c.families_evaluated:
        cov, tot = c.by_family.get(fam, (0, 0))
        pct = f"{100 * cov // tot}%" if tot else "-"
        print(f"{fam}  {cov}/{tot} controls ({pct})")

    # Completeness is ALWAYS printed, even when it's True. A percentage
    # without its declared denominator can't be taken to an audit, and
    # only showing the notice in the bad case trains people not to look
    # for it.
    if c.catalog_complete is True:
        print(f"catalog complete: yes")
    elif c.catalog_complete is False:
        print(f"catalog complete: NO -- the percentage is a floor, not the real number")
    else:
        print(f"catalog complete: undeclared -- the denominator cannot be asserted")

    if c.orphans:
        print(f"\norphans ({len(c.orphans)}) -- cited by a policy and "
              f"absent from the catalog, they add coverage that doesn't exist:")
        for h in c.orphans:
            print(f"  {h}")
    else:
        print("orphans: none")

    return 0 if not c.orphans else 1


if __name__ == "__main__":
    raise SystemExit(_cli())
