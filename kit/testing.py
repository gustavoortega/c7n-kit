"""kit/testing.py: test Cloud Custodian policies with no account, no network.

THE PROBLEM
There have been issues asking for a policy testing framework for c7n since
2016 (cloud-custodian/cloud-custodian#455), 2017 (#903) and 2021 (#6407).
All three are still open. The official testing docs exist, but they're
written for someone contributing to the engine (fixtures recorded with
placebo/vcr, `CustodianTestCore`, `c7n.testing`), not for someone who just
maintains their own rules and wants a quick test for "this policy does what
I say it does."

A policy tested only against the real resources in your account is NOT
tested: if your account doesn't have the rare case (the resource missing
the key, the `SecurityGroup` with no `Tags`, the bucket with no
`ServerSideEncryptionConfiguration`), the rule passes anyway and the gap
stays invisible until someone exploits it.

THE SPECIFIC C7N TRAP THAT MAKES THIS URGENT
In Python, and in the engine of `c7n.filters.core.ValueFilter`, a key
missing from the resource dict resolves to `None`. And `None == False`
evaluates to `False` in Python (they're different types). Practical
consequence: a filter

    - type: value
      key: Encryption.Enabled
      value: false

lets through as "compliant" (no match = not reported) a resource where
`Encryption` never even came back in the `describe_*` response. The policy
thinks it only excludes the ones with an explicit `Enabled: false`, but in
practice it also excludes the ones AWS never finished describing. The
correct form always adds the `absent` branch by hand (see
`examples/policies/rds-unencrypted.yaml`). This module exists, among other
things, so that pattern can be tested with a three-line test instead of
being discovered in an incident.

HOW TO RUN A C7N FILTER WITH NO CREDENTIALS AND NO NETWORK
The key is to not reimplement anything: if we reimplemented the logic of
`value`, `or`, `and`, `not`, `absent`, the test would validate OUR
reimplementation, not the policy the user actually wrote. Instead:

1. A real `c7n.policy.Policy` is built from the YAML (the same loader
   `custodian run` uses), with a `session_factory` that is neither `None`
   nor a real boto3 Session: it's a function that BLOWS UP the moment
   someone calls it (`_forbidden_session`). Building the policy (parsing
   filters, validating the schema) never touches that function at all: c7n
   resolves the session lazily, only when some filter actually needs a
   client.

2. Instead of calling `policy.resource_manager.resources()` (which
   ENUMERATES real resources by calling AWS), we call directly into
   `policy.resource_manager.filter_resources(fake_resources)`. That's the
   same method c7n uses internally after enumerating: it applies the
   policy's filter chain, in order, over whatever list you hand it. It
   skips the network step entirely.

3. If some filter in the chain DOES need to talk to AWS to decide (see
   below), at some point in its `process()` it will call
   `local_session(self.manager.session_factory)` or equivalent, which
   triggers `_forbidden_session` and raises `FilterNeedsNetwork` with an
   explicit message. It never silently returns an empty list that looks
   like a valid result: that would be exactly the kind of "absence
   reported as zero" this kit exists to prevent.

WHAT KINDS OF FILTER CANNOT RUN OFFLINE
It's been verified (see
`tests/test_kit_testing.py::test_filter_that_needs_aws...`) that these
trigger `FilterNeedsNetwork`, because they go fetch data that isn't in the
resource dict you pass them:

  - "related" filters (`c7n.filters.related.RelatedResourceFilter` and its
    subclasses): `security-group`, `subnet`, `vpc`, `flow-logs`,
    `kms-key`, `iam-role`... They need to enumerate ANOTHER resource type
    in AWS to resolve the id your resource only references (e.g.
    `security-group` on `aws.ec2` resolves
    `NetworkInterfaces[].Groups[].GroupId` against a real
    `ec2:DescribeSecurityGroups` call).
  - `metrics` (`c7n.filters.metrics.MetricsFilter`): calls
    `cloudwatch:GetMetricStatistics`/`GetMetricData`.
  - `config-compliance` (`c7n.filters.config.ConfigCompliance`): calls
    `config:DescribeComplianceByConfigRule`.
  - Any Security Hub / GuardDuty findings filter: calls the service's API
    to fetch findings for the resource.

If your policy needs to test one of these, the options are: (a) if the
filter type itself allows it, put the already-resolved data directly on
the fake resource (some related filters expose a way to do this, but it's
not the general case, read the specific filter), or (b) a real integration
test against a test account, outside this module.

WHAT THIS MODULE DOES NOT DO
It doesn't run `actions:`, doesn't evaluate `mode:` (the execution mode,
event-based or pull), and doesn't validate IAM permissions. It only runs
`filters:`, which is where the detection logic that needs to be armored
with tests lives.
"""
from __future__ import annotations

import copy
from typing import Callable

import yaml

from c7n.config import Config
from c7n.loader import PolicyLoader

# Default config for instantiating policies: dummy values, none of them get
# used to actually talk to AWS (that's blocked, see _forbidden_session).
# Exposed so they can be overridden via `config=` for policies that use
# `{account_id}`/`{region}` interpolation in a `value` filter.
_DEFAULT_CONFIG = {"region": "us-east-1", "account_id": "000000000000"}

# One PolicyLoader for the whole process: it caches the jsonschema
# generation (expensive, it involves introspecting every resource of every
# loaded provider), so sharing it between `run_policy` and
# `verify_mutation`, and across different tests in the same pytest run,
# avoids paying that cost once per test.
_LOADER = PolicyLoader(Config.empty())


class PolicyNotFound(LookupError):
    """The requested `name` isn't among the policies in the file.

    The policies that ARE in the file get listed: the most common mistake
    here is a typo in the name, and guessing it blindly from a c7n
    `KeyError` further down the stack doesn't help anyone.
    """


class FilterNeedsNetwork(RuntimeError):
    """A filter in the policy needed to open an AWS session to decide.

    See the module docstring, section "WHAT KINDS OF FILTER CANNOT RUN
    OFFLINE". This NEVER turns into an empty list of matches: whoever wrote
    the test finds out, at the moment it happens, with the policy's name
    in the message.
    """


def _forbidden_session(*args, **kwargs):
    """Replaces c7n's real `session_factory` during tests.

    It isn't `None`: if it were `None`, `Policy.__init__` builds a real
    `session_factory` against the environment's credentials (boto3's
    default chain), and a "related" filter that triggered it would end up
    calling AWS for real, or hanging, or failing with a botocore traceback
    that says nothing about WHY a unit test is trying to resolve
    credentials. This function raises the moment it's invoked, with the
    reason in the message.
    """
    raise FilterNeedsNetwork(
        "a filter needed to open an AWS session (a boto3 client) to be "
        "able to evaluate, and kit/testing.py always runs with no "
        "credentials and no network. It's a \"related\" filter "
        "(security-group, subnet, vpc, kms-key, iam-role...), a metrics "
        "filter (cloudwatch), a config-compliance filter, or a findings "
        "filter, see the kit/testing.py docstring for the detail and the "
        "alternatives."
    )


def _config(overrides: dict | None = None) -> Config:
    data = {**_DEFAULT_CONFIG, **(overrides or {})}
    return Config.empty(**data)


def _read_policies(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        content = yaml.safe_load(fh)
    if not content or "policies" not in content:
        raise ValueError(f"{path!r} has no 'policies:' block")
    return content["policies"] or []


def _find(path: str, name: str) -> dict:
    """Returns the raw dict (straight from the YAML) of the policy `name`."""
    policies = _read_policies(path)
    for raw in policies:
        if raw.get("name") == name:
            return raw
    available = ", ".join(repr(p.get("name", "???")) for p in policies)
    raise PolicyNotFound(
        f"{name!r} isn't in {path!r}. Policies in that file: "
        f"{available or '(none)'}"
    )


def _build(policy_data: dict, config: dict | None = None):
    """Builds a real `c7n.policy.Policy` from a policy dict.

    Doesn't enumerate anything: it only parses `resource`, `filters` and
    `metadata` (validating them against c7n's jsonschema) and builds the
    `resource_manager` with its filter chain already instantiated. The
    blocked `session_factory` gets injected here.
    """
    pdata = {"policies": [policy_data]}
    try:
        collection = _LOADER.load_data(
            pdata,
            file_uri="memory://kit-testing",
            session_factory=_forbidden_session,
            config=_config(config),
            validate=True,
        )
    except Exception as e:
        name = policy_data.get("name", "(no name)")
        raise ValueError(f"couldn't build policy {name!r}: {e}") from e
    return list(collection)[0]


def _filter(
    policy_data: dict,
    resources: list[dict],
    config: dict | None = None,
    context: str | None = None,
) -> list[dict]:
    """Runs `filters:` of a policy (already loaded as a dict) over `resources`.

    Copies `resources` before touching them: c7n annotates the dicts IN
    PLACE (it adds keys like `c7n:MatchedFilters`, `c7n:manual-cloudtrail`,
    etc. as filters run), and without the copy a second call with the same
    literal list would see results contaminated by the previous run.
    """
    policy = _build(policy_data, config=config)
    resources_copy = copy.deepcopy(list(resources))
    try:
        return policy.resource_manager.filter_resources(resources_copy)
    except FilterNeedsNetwork as e:
        prefix = context or policy_data.get("name", "(no name)")
        raise FilterNeedsNetwork(f"{prefix}: {e}") from e


def run_policy(
    file: str,
    name: str,
    resources: list[dict],
    config: dict | None = None,
) -> list[dict]:
    """Runs the REAL `filters:` of policy `name` (defined in `file`) against
    `resources`, and returns the subset that matches.

    `resources` is a list of dicts shaped like the response of an AWS
    `describe`/`list` call, and the fields that are present or missing are
    exactly what's being tested (see the module docstring on
    `None == False`). No credentials, no network, no traffic recording
    needed: if some filter in the chain DOES need them, you find out via
    `FilterNeedsNetwork` instead of a silently empty result.

    `config` lets you override `region`/`account_id` (a dict, merged over
    the default) for policies whose filters interpolate those values.
    """
    policy_data = _find(file, name)
    return _filter(policy_data, resources, config=config, context=f"{file}:{name}")


def verify_mutation(
    file: str,
    name: str,
    resources: list[dict],
    mutate: Callable[[dict], dict],
    assertions: Callable[[list[dict]], None],
) -> None:
    """Tests mutation by hand: does your test go red if you break the policy?

    WHY THIS EXISTS: a test that stays green after you deliberately break
    what the policy claims to protect isn't testing anything, it only
    proves `run_policy` doesn't blow up. It's the same problem mutation
    testing tools (mutmut, cosmic-ray) detect, but here no library is
    needed: the "mutation" is the policy itself (a YAML), so mutating the
    dict before building it is enough.

    HOW TO USE IT: `assertions` is a function that wraps the SAME assert
    you already wrote in your test. `mutate` receives a copy of the
    policy's raw dict and returns a version broken on purpose, typically
    you flip a `value`, delete the `absent` branch of an `or`, or change
    an `op`. Real example, on `examples/policies/rds-unencrypted.yaml`:

        def without_absent_branch(p):
            # drops the filter that covers "the key didn't even come back"
            branch = p["filters"][0]["or"]
            p["filters"][0]["or"] = [f for f in branch if f.get("value") != "absent"]
            return p

        def expected(matched):
            assert {r["DBInstanceIdentifier"] for r in matched} == {"db-2", "db-3"}

        verify_mutation(
            "examples/policies/rds-unencrypted.yaml", "rds-storage-unencrypted",
            resources, mutate=without_absent_branch, assertions=expected,
        )

    Here the mutation DOES get caught: without the `absent` branch, `db-3`
    (which has no `StorageEncrypted` key) stops matching, `expected` raises
    `AssertionError`, and `verify_mutation` finishes green, confirming that
    test really does depend on the `absent` branch.

    WHAT IT DOES: runs `assertions` against the result of the REAL policy
    first, if it already fails there, the test was wrong BEFORE mutating
    anything, and that's what gets reported (mutating something that was
    already measured wrong doesn't help). Then it runs the MUTATED policy
    over the same `resources` and runs `assertions` again. If `assertions`
    does NOT raise against the broken policy, the mutation wasn't caught:
    `AssertionError` gets raised explaining that. If `assertions` does
    raise (as it should), the function returns normally.

    No resource id or "compare results" heuristic needed: the caller's own
    assertions get reused as-is, so the mutation check proves exactly what
    the real test proves, no more, no less.
    """
    policy_data = _find(file, name)

    matched_real = _filter(
        policy_data, resources, context=f"{file}:{name} (real)"
    )
    try:
        assertions(matched_real)
    except AssertionError as e:
        raise AssertionError(
            f"{file}:{name}: assertions already fail against the "
            f"UNMUTATED policy ({e!r}). Fix the test before checking the "
            f"mutation, there's no point breaking something that was "
            f"already measured wrong."
        ) from e

    mutated = mutate(copy.deepcopy(policy_data))
    matched_mutated = _filter(
        mutated, resources, context=f"{file}:{name} (mutated)"
    )
    try:
        assertions(matched_mutated)
    except AssertionError:
        return  # the mutation was caught: the assertions went red.

    raise AssertionError(
        f"{file}:{name}: mutation NOT caught. The assertions still pass "
        f"after deliberately breaking the filter, this test doesn't "
        f"protect the rule. Add a resource to the fixture or a more "
        f"specific assertion until the mutation brings it down."
    )
