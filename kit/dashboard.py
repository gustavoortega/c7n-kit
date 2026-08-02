"""kit/dashboard.py: dashboard templates that don't lie when a rule gets
renamed.

THE PROBLEM
A dashboard (Splunk, Grafana, OpenSearch, whatever) that has policy names
hardcoded in its panels/queries ages badly: the day someone renames a rule
in the repo, the rows that referenced it by its old name simply stop
matching. No exception, no alert, the panel just shows FEWER rows, and on
a security dashboard "fewer findings" reads as "we improved," not as "the
dashboard is broken." This module attacks both ends of the problem:
`generate` builds the dashboard FROM the policy repo (so there's never a
hardcoded name that can go stale), and `orphans` audits an ALREADY
generated dashboard against the CURRENT state of the policies to catch the
drift if it happens anyway (someone hand-edited it afterwards, or the
dashboard just went stale without being regenerated).

WHY THE MARKER FORMAT IS `@@c7n:field@@`
The kit can't marry itself to Splunk, or Grafana, or OpenSearch, someone
has to be able to paste this into any of the three. The problem is all
three already use their own variable syntax inside the same file type
(JSON) this module also has to touch:

  - Splunk (Dashboard Studio / tokens): `$field$`, `$env:token$`
  - Grafana (dashboard variables): `${field}`, `$field`, `[[field]]`
  - OpenSearch/Kibana (Mustache in some fields): `{{field}}`

Any of those four delimiters used as our own marker would collide with the
tool's native syntax: a `$total$` the user already uses as a Splunk token
would be indistinguishable from a marker of ours, and either we'd
overwrite it by mistake, or Splunk would try to resolve OUR marker as if
it were one of its own tokens. `@@c7n:field@@` isn't valid syntax in any
of the three tools, nor in JSON: it's inert until this module touches it,
and it stays a plain, ordinary string to any other parser that sees it
first.

AVAILABLE FIELDS (what can go after `@@c7n:`)
  rules            list of policy names (list[str])
  total_rules      policy count (int)
  severities       {name: severity}       -- severity is `None` if the
                                              policy didn't declare it
                                              (see below)
  categories       {name: category}       -- `None` if not declared
  frameworks       {name: [controls]}     -- `[]` if none declared
  resources        {name: resource}       -- resource type, canonical

`None` for a missing severity/category, not a silent default (e.g. "low"),
for the same rule as the rest of the kit: AN ABSENCE IS NOT A ZERO. If a
policy didn't declare a severity, the dashboard has to be able to
DISTINGUISH that from "declared low severity", they're different facts,
and one gets fixed by writing `severity:` in the YAML, the other means
nothing.

TWO WAYS TO REPLACE, DEPENDING ON WHERE THE MARKER SHOWS UP
If the marker is the ENTIRE string value of a JSON field (`"field":
"@@c7n:rules@@"`, nothing else around it), the replacement preserves the
data's real TYPE: that value becomes an actual list, not the text "['a',
'b']". So a Grafana panel expecting a real array for a template variable
gets it as an array, not as a string.

If the marker is EMBEDDED in a longer piece of text (`"summary": "Dashboard
with @@c7n:total_rules@@ rules"`), it's replaced with its text
representation: a number or string as-is, a list as its values joined by
comma. A `dict` (severities, categories, frameworks, resources) has no
reasonable text representation to embed mid-sentence, so THAT raises
instead of producing unreadable JSON, the marker is meant to be used as a
field's complete value, not mixed into a string.

THE TWO THINGS THIS MODULE CANNOT LET SLIDE SILENTLY
1. A marker the template writes but `generate` doesn't know how to resolve
   (a typo, a field that doesn't exist) can't be left as-is in the output
   dashboard. A `re.sub` that doesn't match returns the text untouched:
   the dashboard looks fine, imports fine, and the panel that depended on
   that field ends up leaking the literal string "@@c7n:rulez@@" (or,
   worse, whatever hardcoded example the template shipped with) into
   production. That's why every unresolved marker raises
   `UnresolvedMarkerError` on the spot.
2. A template with NO markers at all is a dashboard that pulled in exactly
   zero data from the repo, probably a hand-pasted file, or the wrong
   template for the wrong dashboard by mistake. Generating it "successfully"
   is worse than failing: it looks like a valid dashboard and doesn't have
   a single row that depends on reality. That's why
   `TemplateWithoutMarkersError` exists.

THE CITATIONS MANIFEST, AND WHY `orphans` NEEDS IT
`orphans(dashboard, policies)` has to say which rule names show up in
`dashboard` but no longer exist in `policies`. The problem is a generic
dashboard has no universal convention for "this is where a rule name
goes": Splunk, Grafana and OpenSearch structure their JSON in completely
different ways, so guessing "which string is a reference to a rule" by
its shape (a hyphenated slug? "us-east-1" also has hyphens and isn't a
rule) produces false positives that make the signal useless, exactly the
problem `kit/coverage.py` already solved for control orphans with its
family filter.

The solution here is simpler: `generate` leaves, inside the dashboard it
returns, a manifest with the exact names of ALL the policies it received
(reserved key `__c7n_manifest__`, always added, whether the template uses
it or not). `orphans` reads that manifest back and compares it against
the current policies. No heuristics about what strings look like: it's
the real list that generated that dashboard, not one more, not one less.

THE REAL TRAP (the one that motivated this module)
A dashboard gets handled as an already-parsed dict, but several tools
(OpenSearch/Kibana in particular: `searchSourceJSON`, `visState`,
`uiStateJSON`) store a panel's definition as *JSON serialized INSIDE a
string field*, not as a nested sub-object. If the manifest search did
`json.dumps(dashboard)` and then ran a regex over that text, any quote
that was already escaped because it came from one of those string fields
would get escaped a SECOND time (`\"` becomes `\\\"`), and a pattern
looking for `"__c7n_manifest__"` with plain quotes would never match
anything, the check runs, doesn't blow up, and always returns zero
orphans, on any real dashboard. It's exactly the no-op that looks like it
works.

The correct approach is to walk the STRUCTURE: descend through actual
dicts and lists, and when a string is reached, test whether it IS valid
JSON (with `json.loads`) and, if so, keep descending inside THAT result
too. That way the manifest gets found no matter how many levels of
"JSON inside a string" it has to cross, without depending on how some
text ended up escaped when it's never re-serialized.
"""
from __future__ import annotations

import json
import re
from typing import Any

# See the "WHY THE MARKER FORMAT IS @@c7n:field@@" section above.
_MARKER_RE = re.compile(r"@@c7n:(?P<field>[a-zA-Z_][a-zA-Z0-9_]*)@@")

# Reserved key where `generate` leaves the manifest of cited names, so
# `orphans` can read it back later without guessing the dashboard's shape.
# The `__` prefix/suffix is the same convention Python uses for "this is
# internal bookkeeping, not business data", chosen so the odds of it
# colliding with a real dashboard key are effectively zero.
_MANIFEST_KEY = "__c7n_manifest__"


class UnresolvedMarkerError(ValueError):
    """The template uses `@@c7n:field@@` with a `field` that doesn't exist.

    See section 1 of "THE TWO THINGS..." in the module docstring: letting
    this slide means a dashboard that looks fine and leaks bad data.
    """


class IncompatibleMarkerError(ValueError):
    """A marker that resolves to a `dict` showed up embedded in a longer
    piece of text, where there's no reasonable way to turn it into text.
    """


class TemplateWithoutMarkersError(ValueError):
    """The template has no `@@c7n:...@@` at all.

    See section 2 of "THE TWO THINGS..." in the module docstring.
    """


class AmbiguousMetadataError(ValueError):
    """A policy declares both `framework` and `frameworks` at once.

    Same problem `kit/coverage.py` documents: there's no safe tiebreaker,
    so this bails out instead of picking one silently. The class is
    repeated (not imported from `kit.coverage`) because each module in
    this kit is meant to be used standalone, see CONTRATOS.md.
    """


class MissingManifestError(ValueError):
    """The dashboard doesn't have the manifest `generate` leaves behind.

    Without that manifest there's no honest way to know which rules the
    dashboard cites, returning `[]` here would read a missing datum as
    "zero orphans", which is exactly what this kit exists to prevent.
    """


def _frameworks_of(policy) -> list[str]:
    """The controls a policy declares it covers, or `[]` if it declares none.

    Accepts `metadata.framework` (singular, a string) or
    `metadata.frameworks` (plural, a list), but not both at once, see
    `AmbiguousMetadataError`.
    """
    metadata = getattr(policy, "metadata", None) or {}
    frameworks = metadata.get("frameworks")
    framework = metadata.get("framework")
    if frameworks is not None and framework is not None:
        raise AmbiguousMetadataError(
            f"{getattr(policy, 'name', '(no name)')}: declares 'framework' "
            "and 'frameworks' at once"
        )
    if frameworks is not None:
        return list(frameworks)
    if framework is not None:
        return [framework]
    return []


def _fields(policies) -> dict[str, Any]:
    """{field_name: value}: what each `@@c7n:field@@` can resolve to.

    `policies` is any iterable of objects with `.name`, `.metadata` and
    `.resource` (duck typing, same as the rest of the kit: see the
    `kit/cadence.py` docstring for why this file doesn't import the
    `Policy` dataclass from `kit/policies.py`). Those three attribute
    names come from that dataclass and are a cross-module contract (see
    CONTRATOS.md), not translated here on purpose: this file has to keep
    matching the actual `Policy` objects `kit/policies.py` produces.
    """
    items = list(policies)
    names = sorted(getattr(p, "name") for p in items)
    return {
        "rules": names,
        "total_rules": len(names),
        "severities": {
            p.name: (getattr(p, "metadata", None) or {}).get("severity")
            for p in items
        },
        "categories": {
            p.name: (getattr(p, "metadata", None) or {}).get("category")
            for p in items
        },
        "frameworks": {p.name: _frameworks_of(p) for p in items},
        "resources": {p.name: getattr(p, "resource", None) for p in items},
    }


def _validate_field(field: str, values: dict[str, Any]) -> None:
    if field not in values:
        available = ", ".join(sorted(values))
        raise UnresolvedMarkerError(
            f"the template uses @@c7n:{field}@@, which isn't a known field. "
            f"Available fields: {available}."
        )


def _text_of(value: Any, field: str) -> str:
    """Text representation of `value` for a marker EMBEDDED in a longer
    string (see "TWO WAYS TO REPLACE" in the module docstring)."""
    if isinstance(value, dict):
        raise IncompatibleMarkerError(
            f"@@c7n:{field}@@ resolves to a structure ({{'name': ...}}) and "
            "is embedded inside a longer piece of text, there's no safe way "
            "to flatten a dict mid-sentence. Use it as the COMPLETE value "
            "of a JSON field (\"key\": \"@@c7n:"
            f"{field}@@\" alone, with no surrounding text), not mixed into "
            "a string."
        )
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    if value is None:
        return "(no data)"
    return str(value)


def _replace_in_string(text: str, values: dict[str, Any], counter: list[int]) -> Any:
    """Replaces the markers in a string.

    If `text` IS, start to finish, a single marker, the result preserves
    the data's real TYPE (list, dict, int, None), so a consumer expecting
    a real JSON array gets one, not its text representation. If the
    marker is embedded in something longer, it's replaced with text (see
    `_text_of`).

    `counter` gets incremented for every marker resolved, it's how
    `generate` knows, at the end, whether the template had at least one
    (see `TemplateWithoutMarkersError`).
    """
    m = _MARKER_RE.fullmatch(text)
    if m:
        field = m.group("field")
        _validate_field(field, values)
        counter[0] += 1
        return values[field]

    def _sub(match: re.Match) -> str:
        field = match.group("field")
        _validate_field(field, values)
        counter[0] += 1
        return _text_of(values[field], field)

    return _MARKER_RE.sub(_sub, text)


def _walk(node: Any, values: dict[str, Any], counter: list[int]) -> Any:
    """Applies marker substitution recursively over dicts, lists and
    strings. Any other type (int, bool, None, already that way in the
    template) passes through untouched."""
    if isinstance(node, dict):
        return {key: _walk(value, values, counter) for key, value in node.items()}
    if isinstance(node, list):
        return [_walk(item, values, counter) for item in node]
    if isinstance(node, str):
        return _replace_in_string(node, values, counter)
    return node


def generate(policies, template: dict) -> dict:
    """Replaces the `@@c7n:field@@` markers in `template` with data derived
    from `policies`, and returns the resulting dashboard.

    `template` isn't mutated: a new dict/list gets rebuilt at every level
    (see `_walk`), so the original template stays intact if the caller
    reuses it to generate several dashboards.

    Raises `UnresolvedMarkerError` if any `@@c7n:...@@` in the template
    isn't a known field, and `TemplateWithoutMarkersError` if the template
    had no marker at all, see the module docstring for the reasoning
    behind both.

    The returned dashboard always includes the reserved key
    `__c7n_manifest__` with the names of ALL the policies it received,
    whether the template uses it or not: it's the manifest `orphans`
    needs to audit this same dashboard later, once it may no longer match
    the repo.
    """
    if not isinstance(template, dict):
        raise TypeError(f"template has to be a dict (already-parsed JSON), not {type(template)!r}")

    policy_list = list(policies)
    values = _fields(policy_list)
    counter = [0]
    dashboard = _walk(template, values, counter)

    if counter[0] == 0:
        raise TemplateWithoutMarkersError(
            "the template has no @@c7n:...@@ marker at all, generating a "
            "dashboard that pulled in exactly zero data from the repo is "
            "worse than not generating it (see the module docstring)."
        )

    dashboard[_MANIFEST_KEY] = sorted({p.name for p in policy_list})
    return dashboard


def _find_manifest(node: Any) -> "set[str] | None":
    """Walks `node` (dict / list / str, recursively) looking for the
    `__c7n_manifest__` key. See "THE REAL TRAP" in the module docstring:
    nothing ever gets serialized back to JSON to search, the structure is
    walked as it already sits in memory, and when a string is reached that
    ALSO happens to be valid JSON (the case of OpenSearch/Kibana storing a
    panel as text inside a field), we keep descending inside THAT result
    too.

    Returns `None` if no manifest was found at any level (as opposed to an
    empty `set()`, which would mean "the manifest was found and it cited
    nobody").
    """
    found: list[bool] = [False]
    citations: set[str] = set()

    def _search(n: Any) -> None:
        if isinstance(n, dict):
            manifest_value = n.get(_MANIFEST_KEY)
            if isinstance(manifest_value, list):
                found[0] = True
                citations.update(str(x) for x in manifest_value)
            for v in n.values():
                _search(v)
        elif isinstance(n, list):
            for item in n:
                _search(item)
        elif isinstance(n, str):
            # Is this string, in turn, serialized JSON? (the
            # searchSourceJSON/visState pattern from OpenSearch-Kibana). If
            # it isn't, `json.loads` raises and there's nothing else to
            # look for here.
            try:
                parsed = json.loads(n)
            except (json.JSONDecodeError, ValueError):
                return
            if isinstance(parsed, (dict, list)):
                _search(parsed)

    _search(node)
    return citations if found[0] else None


def orphans(dashboard: dict, policies) -> list[str]:
    """Rule names cited in `dashboard` that no longer exist in `policies`.

    Reads the manifest `generate` left behind (`__c7n_manifest__`, see its
    docstring) by walking the dashboard's real structure, never
    serializing it to text to search, precisely because of the trap the
    module documents: a real dashboard can have JSON nested INSIDE a
    string field, and re-serializing everything escapes those quotes one
    more time, so any text search over the result finds nothing, a check
    that runs, doesn't blow up, and always says "no orphans."

    If `dashboard` doesn't have the manifest (it wasn't generated by
    `generate`, or someone deleted it by hand), there's no honest way to
    answer: `MissingManifestError` gets raised instead of returning `[]`,
    which would read the missing datum as if it were zero orphans.
    """
    citations = _find_manifest(dashboard)
    if citations is None:
        raise MissingManifestError(
            f"the dashboard doesn't have the {_MANIFEST_KEY!r} key at any "
            "level of its structure, it doesn't look like it was generated "
            "by generate() (or someone deleted its manifest). Without that "
            "there's no reliable way to know which rules it cites, so this "
            "can't be answered without guessing."
        )
    current_names = {getattr(p, "name") for p in policies}
    return sorted(n for n in citations if n not in current_names)


if __name__ == "__main__":
    # Minimal CLI: `python -m kit.dashboard <template.json> <policies-dir>`
    # Local import on purpose: the functions above (`generate`, `orphans`)
    # don't depend on `kit.policies`, only this command-line convenience
    # needs it, so as not to tie in the rest of the kit when someone
    # copies just `dashboard.py` (see CONTRATOS.md).
    import sys

    if len(sys.argv) != 3:
        print("usage: python -m kit.dashboard <template.json> <policies-dir>", file=sys.stderr)
        raise SystemExit(2)

    from kit.policies import load

    template_path, policies_dir = sys.argv[1], sys.argv[2]
    with open(template_path, encoding="utf-8") as f:
        template = json.load(f)

    policies = load(policies_dir)
    dashboard = generate(policies, template)
    print(json.dumps(dashboard, indent=2, ensure_ascii=False))
