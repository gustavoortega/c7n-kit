# Module contracts

Every module in `kit/` is meant to be used on its own. Someone has to be able to
copy `kit/coverage.py` into their repo and have it work without dragging the rest
along.

## The rule that governs the kit

**An absence is not a zero.** If something could not be read, checked or
resolved, it is never reported as zero, empty or compliant. It is reported as
unknown, and it is visible.

That is the whole point. A dashboard that quietly drops what it could not
measure looks exactly like a dashboard where everything is fine.

## kit/policies.py

    load(directory) -> list[Policy]

`Policy` carries `name`, `resource` (canonical, always prefixed `aws.`), `file`,
`metadata` (the `metadata:` block verbatim) and `raw` (the whole policy).

`aws.ec2` and `ec2` are the same type to c7n, the provider prefix is optional.
Canonicalize always: without it, any grouping by resource type splits in two and
nobody notices.

A broken YAML cannot make the policies in the other files disappear silently. A
file with no `policies:` key is skipped, but if no file yielded a single policy
that is an error, not an empty list.

## kit/coverage.py

    load_catalog(path)         -> Catalog
    coverage(policies, catalog) -> Coverage

`Catalog` is a `list` subclass that also knows whether it is complete. It travels
with the data rather than as a separate argument, because as an argument the day
someone forgets to pass it the report claims a completeness nobody verified.
`Catalog.complete is None` means unknown. It never means complete.

`Coverage` carries `covered`, `missing`, `orphans`, `by_family`,
`families_evaluated` and `catalog_complete`.

`orphans` is the part nobody implements and the one that matters most: a policy
citing `FSBP RDS.99`, which does not exist, adds to your coverage forever and
nobody ever notices.

Only controls whose family is present in the catalog are evaluated. Cross a
FSBP-only catalog against policies that also map to PCI and the PCI controls are
ignored, not reported as orphans. Otherwise the function screams on every real
policy set and becomes noise.

## kit/cadence.py

    policy_cadence(policy)    -> str
    cadence_by_type(policies) -> dict[str, str]
    promoted_to_fast(policies) -> dict[str, list[str]]

A resource type runs at the fastest cadence any of its policies asks for. c7n
enumerates once per resource type, so applying cadence per policy enumerates the
type twice and costs more than not splitting at all.

A `frequency` value outside the valid list raises. It does not fall back to the
default: a typo treated as the default either runs too often (expensive but
visible) or too rarely (cheap and invisible).

`promoted_to_fast` tells you which type landed on the expensive cadence and which
policy put it there. That is the lever.

## kit/gaps.py

    classify(c7n_org_output) -> list[Gap]
    render_human(gaps)  -> str
    render_machine(gaps) -> str

`Gap` carries `account`, `region`, `policy`, `kind`, `resource` and `raw`.

Kinds, each asking for a different action from a different person:

    own-permission       our role is missing the permission
    resource-policy      the resource's own policy denies us, ask its owner
    service-absent       AWS does not offer the service in that region
    ephemeral-resource   the resource is gone, this is not a coverage gap
    throttled            retry
    unknown              could not be classified, and it is never dropped

`unknown` is mandatory and rendered first, marked. A new error shape landing in
a silent bucket is the bug this kit exists to catch.

`own-permission` and `resource-policy` are the distinction that pays for the
module. AWS separates them in the message itself, and reporting both as "no
permissions" sends the reader to check the role's permissions, which are fine.

`service-absent` is decided by consensus across accounts. boto3 returns the same
text for a network blip and for a service AWS does not offer in that region. The
endpoint is per region and shared by every account, so if it fails in several at
once it is the region.

## kit/dashboard.py

    generate(policies, template) -> dict
    orphans(dashboard, policies) -> list[str]

The dashboard is generated from the repo because a renamed rule makes its rows
disappear with no error at all, and on a security dashboard fewer findings reads
as an improvement.

A marker that does not resolve fails. A template with no markers fails too:
generating a dashboard that picked up nothing from the repo is worse than not
generating one.

`orphans` walks the structure, never `json.dumps(dashboard)`. Serialize first and
the already-escaped quotes inside fields that store JSON as a string (Kibana's
`searchSourceJSON`) get escaped twice and no regex ever matches. That was a no-op
passing green for months.

## kit/testing.py

    run_policy(file, name, resources) -> list[dict]
    verify_mutation(file, name, resources, mutate, assertions)

Runs c7n's real filter engine against resources you make up, with no credentials
and no network. Reimplementing the filter logic would mean your test validates
your reimplementation, not your policy.

A filter that needs an AWS call raises `FilterNeedsNetwork` with a clear message
rather than returning an empty result that looks valid.

`verify_mutation` breaks your filter on purpose and checks the test goes red. A
test that stays green when you break what it claims to guard is not guarding
anything.
