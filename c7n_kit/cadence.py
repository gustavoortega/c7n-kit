"""c7n_kit/cadence.py -- grow without blowing up the window.

WHY CADENCE APPLIES PER TYPE AND NOT PER POLICY
`c7n-org` enumerates resources ONCE per policy file and then applies all
the filters over that same list. The cost of a run is driven by the
number of ENUMERATIONS, not the number of rules: adding a rule to a type
you already enumerate is nearly free (it's one more filter over data
already in memory); adding a new type costs a full enumeration across
every account and region.

Direct consequence: if cadence were declared and executed per policy, a
resource type with rules in both frequencies would get enumerated TWICE a
day -- once in the fast run, once in the slow one -- and separating would
end up MORE expensive than not separating at all. That's why cadence is
DECLARED per policy (in its `metadata.frequency`, which is where the
rule's author thinks about it) but EXECUTED per resource type, taking the
fastest one requested by any of its policies: that way each type gets
enumerated exactly once per run, always.

Taking the fastest one (not the slowest, not an average) is what
guarantees separating by cadence never degrades an existing detection: a
single high-frequency policy on a type whose rules are mostly slow
PROMOTES the whole type to the fast cadence. That costs more than it
would if that policy didn't exist, and that's why `promoted_to_fast`
exists: it's the concrete lever to bring the cost down (moving that one
policy alone to the slow cadence brings the whole type down with it).

WHY AN INVALID `frequency` RAISES INSTEAD OF FALLING BACK TO THE DEFAULT
A typo like `frequency: dayly` treated as if it were the default runs too
often if the default is the fast cadence (expensive, but visible: shows
up in the bill) or too rarely if the default is the slow one (cheap, but
invisible: the rule stops detecting at the frequency its author intended
and nobody notices until it was needed). Neither way of failing silently
is acceptable, so a value not in the list of valid cadences raises
`ValueError` the moment it's read, not later.

SHAPE OF `policy` OBJECTS
This file does NOT import the `Policy` dataclass from `c7n_kit/policies.py`
on purpose: every module in the kit has to be copyable on its own (see
CONTRACTS.md), and tying it to another module in the same kit breaks that
promise the moment someone copies one without the other. Instead, it
accesses the same three fields the `Policy` contract defines, via duck
typing:

  .name     str    -- to say WHICH policy promoted a type
  .resource    str    -- the resource type, canonical (prefixed with `aws.`)
  .metadata   dict    -- the `metadata:` block as-is, `frequency` comes from there

Any object with those three attributes works, whether it's the kit's
real `Policy`, a dict wrapped in `types.SimpleNamespace`, or the result
of your own YAML parser.
"""
from __future__ import annotations

# Valid cadences, ORDERED from fastest to slowest. This order is what
# defines "the fastest wins": adding a new cadence just means inserting
# it at the right position in this tuple, nothing else.
DEFAULT_CADENCES = ("4h", "daily")


def _metadata_of(policy) -> dict:
    return getattr(policy, "metadata", None) or {}


def _name_of(policy) -> str:
    return getattr(policy, "name", None) or "(unnamed)"


def _resource_of(policy) -> str:
    resource = getattr(policy, "resource", None)
    if not resource:
        raise ValueError(
            f"policy {_name_of(policy)!r}: doesn't declare `resource` (resource "
            f"type), cadence cannot be grouped without it")
    return resource


def policy_cadence(policy, cadences=DEFAULT_CADENCES) -> str:
    """The cadence declared by ONE policy, validated.

    The default (when `metadata.frequency` isn't present) is
    `cadences[0]`, i.e. the FASTEST in the list. This choice is
    deliberate: the default has to be the expensive one, so forgetting to
    declare `frequency` costs money (visible in the bill) and not
    invisibility (a rule that thinks it runs every 4h but actually runs
    once a day). If your organization prefers the opposite default, pass
    `cadences` with the order that fits: the first one always wins as
    both the default and the "fastest."
    """
    metadata = _metadata_of(policy)
    value = metadata.get("frequency", cadences[0])
    if value not in cadences:
        # Raise instead of falling back to the default: see module docstring.
        raise ValueError(
            f"policy {_name_of(policy)!r}: frequency={value!r} is not a "
            f"valid cadence. Valid ones: {list(cadences)}")
    return value


def _group_by_resource(policies):
    by_resource: dict[str, list] = {}
    for p in policies:
        by_resource.setdefault(_resource_of(p), []).append(p)
    return by_resource


def cadence_by_type(policies, cadences=DEFAULT_CADENCES) -> dict[str, str]:
    """{resource_type: cadence}, taking the FASTEST one requested by any
    of the policies of that type.

    `policies` is any iterable of objects with `.resource` and `.metadata`
    (see module docstring). Every invalid `frequency` raises as soon as
    that policy is evaluated -- there's no way for a typo to slip through
    unnoticed, not even on a type where it ends up not mattering because
    another policy already fixed the fast cadence.
    """
    by_resource = _group_by_resource(policies)
    result = {}
    for resource, items in by_resource.items():
        requested = {policy_cadence(p, cadences) for p in items}
        result[resource] = min(requested, key=cadences.index)
    return result


def promoted_to_fast(policies, cadences=DEFAULT_CADENCES
                     ) -> dict[str, list[str]]:
    """{resource_type: [policy names]} for the types that ended up on the
    FAST cadence (`cadences[0]`) because of a single policy, while the
    rest of their rules asked for something slower.

    This is the concrete lever to bring down the cost of a run: a type on
    this list gets enumerated at the full expensive frequency because of
    ONE rule. Moving it alone to a slower cadence brings the whole type
    down with it, without touching any other policy.

    A type where ALL policies already ask for the fast cadence doesn't
    show up here: there's nothing to "promote," that's simply the cadence
    the whole type is entitled to on its own.
    """
    fast = cadences[0]
    by_resource = _group_by_resource(policies)
    result = {}
    for resource, items in by_resource.items():
        requested = {policy_cadence(p, cadences) for p in items}
        if len(requested) > 1 and min(requested, key=cadences.index) == fast:
            culprits = sorted(
                _name_of(p) for p in items
                if policy_cadence(p, cadences) == fast)
            result[resource] = culprits
    return result


def _cli(argv=None):
    """What runs on each cadence, from the command line."""
    import sys
    from c7n_kit.policies import load

    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        sys.exit("usage: python -m c7n_kit.cadence <policies-directory>")

    ps = load(argv[0])
    by_type = cadence_by_type(ps)
    for resource_type, cad in sorted(by_type.items()):
        print(f"  {resource_type:<24} {cad}")

    promoted = promoted_to_fast(ps)
    print()
    if promoted:
        # The actionable data: moving that single policy brings the whole
        # type down.
        print("types on the fast cadence because of ONE policy:")
        for resource_type, policy in sorted(promoted.items()) if isinstance(promoted, dict) else promoted:
            print(f"  {resource_type:<24} promoted by: {policy}")
    else:
        print("promoted to the fast cadence: none")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
