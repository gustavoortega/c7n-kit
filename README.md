# c7n-kit: test Cloud Custodian policies offline, count what they cover

Test Cloud Custodian policies offline, measure compliance coverage, and account for what a run could not look at. It bolts onto a clean `pip install c7n` and replaces nothing.

[![ci](https://github.com/gustavoortega/c7n-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/gustavoortega/c7n-kit/actions/workflows/ci.yml)

Cloud Custodian answers one question very well: which resources violate a rule you wrote in YAML. What it does not answer, because it is outside what the project set out to solve, is everything after that. How much of a framework you cover. Whether your rules are actually tested. What the run **could not look at**.

The four policies shipped here are illustrative. What this repository publishes is the instrument, not a catalogue: every catalogue is different and ages with each AWS API change, and this does not.

For a catalogue that uses it, see [cloud-custodian-compliance-policies](https://github.com/gustavoortega/cloud-custodian-compliance-policies), where the coverage report, the offline tests and the gap classifier all run against 325 policies in CI.

What happened when that catalogue was pointed at itself, and why an absence is not a zero: [Cloud Custodian ships an engine and no rules. Here are 325.](https://gustavoortega.hashnode.dev/cloud-custodian-ships-an-engine-and-no-rules-here-are-325)

---

## Thirty seconds

```
pip install c7n-kit
```

Or clone it and run the suite, which is what CI does:

```
git clone https://github.com/gustavoortega/c7n-kit.git && cd c7n-kit
python -m venv .venv && .venv/bin/pip install c7n pyyaml pytest
.venv/bin/python -m pytest -q
```

78 tests, **no AWS credentials and no network**. A filter that would need an AWS call raises with a clear message rather than returning an empty result that looks valid.

---

## Your rules are not tested

A policy tested only against your own account is not tested. If your account does not have the odd case, the rule passes anyway and you find out the day it shows up.

`c7n_kit/testing.py` runs c7n's **real** filter engine against resources you make up:

```python
from c7n_kit.testing import run_policy

def test_rds_storage_unencrypted():
    resources = [
        {'DBInstanceIdentifier': 'a', 'StorageEncrypted': True},
        {'DBInstanceIdentifier': 'b', 'StorageEncrypted': False},
        {'DBInstanceIdentifier': 'c'},                    # the key never came back
    ]
    r = run_policy('examples/policies/rds-unencrypted.yaml',
                   'rds-storage-unencrypted', resources)
    assert [x['DBInstanceIdentifier'] for x in r] == ['b', 'c']
```

The third one is what matters and almost nobody writes it. In c7n a missing key evaluates to `None`, and `None == False` is `False`. A `value: false` filter lets through as compliant a resource where the field simply did not come back from AWS.

There is also `verify_mutation`, which breaks your filter on purpose and checks the test goes red. A test that stays green with the bug in place is not testing anything. That one caught two of mine.

## You cannot answer how much you cover

```
$ python -m c7n_kit.coverage catalogs/fsbp.txt examples/policies
$ c7n-kit coverage catalogs/fsbp.txt examples/policies

FSBP  3/369 controls (0%)
catalog complete: yes
orphans: none
```

The mapping lives in the policy, in the `metadata:` block that c7n accepts as an arbitrary object and carries through to the output:

```yaml
    metadata:
      severity: high
      frameworks: ['FSBP RDS.3', 'PCI 3.5.1']
      frequency: daily
```

Two things here you will not find elsewhere.

**Orphans** are controls your policies cite that do not exist in the catalogue. A rule claiming to cover `FSBP RDS.99` adds to your coverage forever and nobody notices. On its first real run this function found that one of the example policies in this very repo cited `PCI 3.4`, a v3.2.1 control renumbered to 3.5.1 in v4.0.

**Catalogue completeness** is declared by the catalogue file itself and travels with the data, not as a separate argument. An incomplete catalogue produces false orphans and understates coverage. The PCI and CIS catalogues shipped here are incomplete and they say so:

```
$ python -m c7n_kit.coverage catalogs/cis-aws.txt examples/policies
$ c7n-kit coverage catalogs/cis-aws.txt examples/policies

CIS  1/36 controls (2%)
catalog complete: NO -- the percentage is a floor, not the real number

orphans (3) -- cited by a policy and absent from the catalog, they add coverage that doesn't exist:
  CIS 2.3.1
  CIS 5.2
  CIS 5.6
```

A percentage without its denominator declared cannot go into an audit.

## Every rule you add costs time, but not the way you think

`c7n-org` enumerates resources **once per policy file** and then applies every filter to that list. What drives the cost of a run is the number of enumerations, not the number of rules.

So cadence is declared per policy but executed **per resource type**, taking the fastest any of its rules asks for:

```
$ python -m c7n_kit.cadence examples/policies
$ c7n-kit cadence examples/policies

  aws.ec2                  4h
  aws.rds                  daily
  aws.s3                   daily
  aws.security-group       4h

promoted to the fast cadence: none
```

Apply cadence rule by rule instead and a type with rules in both frequencies gets enumerated twice a day, costing more than not splitting at all.

`promoted_to_fast()` tells you which type landed on the expensive cadence **and which policy put it there**. Moving that one rule brings the whole type down.

## The dashboard lies when you rename a rule

If the dashboard has rule names typed by hand, the day you rename one its rows disappear. No error, no alert, the panel just shows less. And on a security dashboard, fewer findings reads as an improvement.

```
$ python -m c7n_kit.dashboard examples/template.json examples/policies
$ c7n-kit dashboard examples/template.json examples/policies
```

The template carries `@@c7n:rules@@`, `@@c7n:severities@@`, `@@c7n:frameworks@@`, and the generator replaces them with whatever the policies declare today. The marker is deliberately ugly: Splunk uses `$field$`, Grafana `${field}` and Kibana `{{field}}` inside the same JSON, so anything prettier would have collided with the tool's own syntax.

A marker that does not resolve **fails**. A template with no markers fails too, because generating a dashboard that picked up nothing from the repo is worse than not generating one.

And `orphans()` tells you which rules the dashboard still cites that no longer exist:

```python
>>> orphans(dashboard, policies)
['rds-storage-unencrypted']
```

One detail that nearly got me: **do not search for the names over the serialized JSON.** I had this same check written in another repo and it found zero names against a real dashboard, because the quotes are escaped and the regex never matches. It was a no-op passing green. Here it walks the structure, and descends into fields that store JSON as a string, which is what Kibana does with `searchSourceJSON`.

## You do not know what the run could not look at

This is the one that took me longest to understand and the one nobody writes about.

If an account is missing permissions, or a region does not answer, or a policy dies halfway through, that account does not show up in the output. **And an account that does not show up looks exactly like a clean account.** The other problems get reported to you by someone. This one does not.

`c7n_kit/gaps.py` reads `c7n-org` output and classifies what went unchecked:

```
5 coverage gap(s).

⚠ 1 unclassified (UNKNOWN): investigate the raw message, it didn't match any known kind:
  - team-c/us-east-1 whatever: ...error:Something nobody has seen before

own-permission (1): add the permission to the role that runs c7n:
  - apps/us-east-1 s3-inventory

resource-policy (1): ask the resource owner to add the policy:
  - security/us-east-1 kms-public [arn:aws:kms:us-east-1:1:key/abc]

service-absent (2): scope the policy with region conditions, nothing to fix:
  - team-a/sa-east-1 s3-express
  - team-b/sa-east-1 s3-express
```

Three design decisions worth more than the code.

**Each kind carries its action.** A permission missing from your role, which you fix, is not the same as one denied by the resource's own policy, which you have to ask its owner for. AWS separates them in the message itself (`no identity-based policy allows` versus `no resource-based policy allows`) and reporting both as "no permissions" sends the reader to check the role's permissions, which are fine.

**`service-absent` is decided by consensus.** boto3 returns identical text for a network blip and for a service AWS does not offer in that region. What separates them is that the endpoint is per region and shared by every account: if it fails in several at once, it is the region.

**`unknown` comes first and marked.** A new error shape landing in a silent bucket is the bug this kit exists to catch.

There is a one-line-per-gap output for shipping to a SIEM.

---

## Take only what you need

Every file in `c7n_kit/` works on its own. If all you want is the coverage report, take `c7n_kit/coverage.py` and `c7n_kit/policies.py` and you are done. No framework, no configuration, nothing to adopt.

```
c7n_kit/policies.py    loads policies and canonicalizes the resource type
c7n_kit/coverage.py    cross against a framework catalogue
c7n_kit/cadence.py     groups by type and resolves the frequency
c7n_kit/gaps.py        classifies what the run could not look at
c7n_kit/testing.py     runs your filters against resources you make up
c7n_kit/dashboard.py   generates the dashboard from the repo
```

See `CONTRACTS.md` for the full API.

---

## The rule that governs all of it

**An absence is not a zero.**

If something could not be read, checked or resolved, it is never reported as zero, empty or compliant. It is reported as unknown, and it is visible.

A field that never came back read as "not encrypted". A service that does not exist read as "the network failed". An account nobody could look at that renders exactly like a clean one. It is the same mistake wearing different clothes, and it is what makes a security dashboard lie without anyone noticing.

The 78 tests here exist for that, and every one is mutation-verified: break what it claims to guard and check it goes red.

---

Apache 2.0
