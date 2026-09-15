"""Which branch of a policy decided the answer, for one resource.

`run_policy` answers "does this policy match this resource". That is the
question a test asks. It is not the question someone reading a policy asks,
which is "which of these conditions caught it, and which one let it
through". A policy whose `or` has two branches reports the resource if
either fires, and the whole argument of this kit is that the second branch,
the one for the key that never came back, is the one doing the work far
more often than anyone expects.

So this evaluates the tree node by node and returns all three answers per
node:

    match      the filter matched this resource
    no_match   c7n evaluated it and it did not match
    unknown    it could not be evaluated here

`unknown` is not a failure mode, it is a result. A filter that needs an AWS
call (`cross-account`, `kms-key`, `bucket-encryption`) cannot be answered
offline, and answering `no_match` for it would be the silent pass this kit
exists to prevent. It propagates up the tree the same way: an `and` with an
unknown child and no false child is unknown, not false.

Nothing here reimplements c7n. Every leaf is evaluated by building a real
policy with that single filter and running c7n's own engine over the
resource, which is what `testing._filter` already does.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from c7n_kit.testing import FilterNeedsNetwork, _filter, _find, _read_policies

MATCH = "match"
NO_MATCH = "no_match"
UNKNOWN = "unknown"

# The three filters c7n treats as boolean operators over other filters.
_OPERATORS = ("or", "and", "not")


@dataclass
class Node:
    """One node of a policy's filter tree, with its result for one resource.

    `kind` is the operator ("or", "and", "not") or the filter type as the
    policy writes it ("value", "cross-account", ...). `raw` is the filter
    exactly as it appears in the file, so a caller can render the YAML that
    produced this node without re-reading it.
    """
    kind: str
    result: str
    raw: Any
    children: list["Node"] = field(default_factory=list)

    @property
    def decided(self) -> bool:
        """True when this node is the reason the policy reported the resource.

        Only meaningful under an `or`: the branch that matched is the one
        that put the resource in the report, and the one a reader has to
        delete to make it disappear.
        """
        return self.result == MATCH


def _as_operator(node: Any) -> tuple[str, list] | None:
    """('or', [children]) when `node` is a boolean operator, else None."""
    if not isinstance(node, dict):
        return None
    for operator in _OPERATORS:
        if operator in node and isinstance(node[operator], list):
            return operator, node[operator]
    return None


def _combine(operator: str, children: list[Node]) -> str:
    """c7n's boolean semantics, with unknown as a third value.

    `and` is false as soon as one child is false, whatever the others are:
    a condition that could not be evaluated cannot rescue a resource that
    already failed another one. It is unknown only when nothing is false and
    something could not be read. `or` is the mirror. `not` swaps the two
    decided values and leaves unknown alone, because the negation of "we
    could not look" is still "we could not look".
    """
    results = [c.result for c in children]

    if operator == "and":
        if NO_MATCH in results:
            return NO_MATCH
        return UNKNOWN if UNKNOWN in results else MATCH

    if operator == "or":
        if MATCH in results:
            return MATCH
        return UNKNOWN if UNKNOWN in results else NO_MATCH

    # not: c7n applies it to the conjunction of its children
    inner = _combine("and", children)
    if inner == UNKNOWN:
        return UNKNOWN
    return NO_MATCH if inner == MATCH else MATCH


def _leaf(policy_data: dict, filter_data: Any, resource: dict,
          config: dict | None) -> str:
    """The result of ONE filter over ONE resource, through c7n's engine."""
    single = {
        "name": f"{policy_data.get('name', 'policy')}-trace",
        "resource": policy_data["resource"],
        "filters": [filter_data],
    }
    try:
        matched = _filter(single, [resource], config=config,
                          context=f"{policy_data.get('name')} (trace)")
    except FilterNeedsNetwork:
        # The honest answer. Not an error: this filter's question has no
        # answer without an account, and saying no_match here is exactly the
        # lie the kit is about.
        return UNKNOWN
    except Exception:
        # A filter that cannot even be built (an unregistered custom filter,
        # a schema the installed c7n does not know) is also unknown. The
        # alternative is to drop the node, and a node nobody evaluated must
        # not disappear from the tree.
        return UNKNOWN
    return MATCH if matched else NO_MATCH


def _node(policy_data: dict, filter_data: Any, resource: dict,
          config: dict | None) -> Node:
    operator = _as_operator(filter_data)
    if operator is None:
        kind = filter_data.get("type", "value") if isinstance(filter_data, dict) \
            else "value"
        return Node(kind=kind,
                    result=_leaf(policy_data, filter_data, resource, config),
                    raw=filter_data)

    name, children_data = operator
    children = [_node(policy_data, child, resource, config)
                for child in children_data]
    return Node(kind=name, result=_combine(name, children), raw=filter_data,
                children=children)


def trace(policy_data: dict, resource: dict,
          config: dict | None = None) -> Node:
    """The filter tree of `policy_data`, each node resolved for `resource`.

    The root is the policy's `filters:` list, which c7n treats as an `and`.
    A policy with no filters matches everything, and the root says so with
    an empty `and` that resolves to match.
    """
    filters = policy_data.get("filters") or []
    children = [_node(policy_data, f, resource, config) for f in filters]
    return Node(kind="and", result=_combine("and", children),
                raw=filters, children=children)


def trace_file(file: str, name: str, resource: dict,
               config: dict | None = None) -> Node:
    """`trace` for a policy named `name` inside the YAML file `file`."""
    return trace(_find(file, name), resource, config=config)


def flatten(node: Node) -> list[Node]:
    """`node` and every descendant, depth first, in file order."""
    out = [node]
    for child in node.children:
        out.extend(flatten(child))
    return out


def _cli(argv: list[str]) -> int:
    """`c7n-kit trace <policies.yml> <policy-name> <resource.json>`."""
    import json

    if len(argv) != 3:
        print("usage: c7n-kit trace <policies.yml> <policy-name> <resource.json>")
        return 1

    path, name, resource_path = argv
    with open(resource_path, "r", encoding="utf-8") as f:
        resource = json.load(f)

    root = trace_file(path, name, resource)

    def render(node: Node, depth: int = 0) -> None:
        label = node.kind if node.children else _describe(node.raw)
        print(f"{'  ' * depth}{node.result:<9} {label}")
        for child in node.children:
            render(child, depth + 1)

    print(f"{name}: {root.result}")
    for child in root.children:
        render(child, 1)
    return 0


def _describe(filter_data: Any) -> str:
    """A filter in one line, the way the policy wrote it."""
    if not isinstance(filter_data, dict):
        return str(filter_data)
    if "key" in filter_data:
        op = filter_data.get("op", "eq")
        return f"{filter_data['key']} {op} {filter_data.get('value')!r}"
    return filter_data.get("type", "?")


if __name__ == "__main__":
    import sys

    raise SystemExit(_cli(sys.argv[1:]))
