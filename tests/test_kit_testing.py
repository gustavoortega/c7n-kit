# Tests for c7n_kit/testing.py itself (not an example policy). They use
# minimal policies written to a temp file so this doesn't depend on
# examples/, keeping the harness tested in isolation.
#
# The three cases that matter (and that were verified by mutation, see the
# equivalence table in the response): a missing key resolves correctly in
# both directions, a filter that needs AWS warns instead of returning an
# empty result that looks valid, and `verify_mutation` catches a test with
# no real detection power.
import pytest
import yaml

from c7n_kit.testing import FilterNeedsNetwork, run_policy, verify_mutation


def _write(tmp_path, policies):
    file = tmp_path / "policy.yaml"
    file.write_text(yaml.safe_dump({"policies": policies}))
    return str(file)


def test_absent_key_evaluates_correctly_in_both_directions(tmp_path):
    """`None == False` is the central trap this kit exists to expose: a
    `value: false` filter with NO `absent` branch should not match a
    resource where the key never came back (that's how c7n really
    behaves, if this test failed here, c7n_kit/testing.py would be correcting
    or reimplementing the real semantics instead of exposing them). The
    same resource, with the `absent` branch added, does have to match.
    """
    file = _write(tmp_path, [
        {
            "name": "without-absent",
            "resource": "aws.rds",
            "filters": [
                {"type": "value", "key": "StorageEncrypted", "value": False}
            ],
        },
        {
            "name": "with-absent",
            "resource": "aws.rds",
            "filters": [
                {"or": [
                    {"type": "value", "key": "StorageEncrypted", "value": False},
                    {"type": "value", "key": "StorageEncrypted", "value": "absent"},
                ]}
            ],
        },
    ])
    resources = [{"DBInstanceIdentifier": "db-not-described"}]  # no StorageEncrypted

    without_absent = run_policy(file, "without-absent", resources)
    with_absent = run_policy(file, "with-absent", resources)

    assert without_absent == []
    assert [r["DBInstanceIdentifier"] for r in with_absent] == ["db-not-described"]


def test_filter_that_needs_aws_raises_with_a_clear_message_not_an_empty_result(tmp_path):
    """`security-group` on aws.ec2 is a RelatedResourceFilter: to decide it
    needs to enumerate real security groups against AWS. Offline it has to
    raise `FilterNeedsNetwork`, the bad alternative would be returning
    `[]`, which an unwary test would read as "nothing matches", a result
    that LOOKS valid but is actually "couldn't be evaluated."
    """
    file = _write(tmp_path, [
        {
            "name": "ec2-with-open-sg",
            "resource": "aws.ec2",
            "filters": [
                {"type": "security-group", "key": "GroupName", "value": "default"}
            ],
        }
    ])
    resources = [
        {"InstanceId": "i-1", "NetworkInterfaces": [{"Groups": [{"GroupId": "sg-1"}]}]}
    ]

    with pytest.raises(FilterNeedsNetwork, match="AWS session"):
        run_policy(file, "ec2-with-open-sg", resources)


def test_verify_mutation_catches_a_test_that_does_nothing(tmp_path):
    """If the test's assertions don't discriminate anything (here, an
    `assert True` that always passes), breaking the filter on purpose
    doesn't make them fail, and that's exactly what `verify_mutation` has
    to report as an error, not let slide silently.
    """
    file = _write(tmp_path, [
        {
            "name": "rds-storage-unencrypted",
            "resource": "aws.rds",
            "filters": [
                {"or": [
                    {"type": "value", "key": "StorageEncrypted", "value": False},
                    {"type": "value", "key": "StorageEncrypted", "value": "absent"},
                ]}
            ],
        }
    ])
    resources = [
        {"DBInstanceIdentifier": "db-unencrypted", "StorageEncrypted": False},
        {"DBInstanceIdentifier": "db-encrypted", "StorageEncrypted": True},
    ]

    def delete_all_filters(policy_data):
        # with no filters, the policy "matches" everything, including the
        # encrypted db, which the real policy excludes. A good assertion
        # has to notice.
        policy_data["filters"] = []
        return policy_data

    def useless_assertions(matched):
        assert True  # verifies nothing about `matched`

    with pytest.raises(AssertionError, match="NOT caught"):
        verify_mutation(
            file, "rds-storage-unencrypted", resources,
            mutate=delete_all_filters,
            assertions=useless_assertions,
        )


def test_verify_mutation_does_not_complain_about_a_test_with_real_power(tmp_path):
    """Counterpart of the previous test: if the assertions do check the
    result, the same mutation (deleting the filters) has to make them
    fail, and `verify_mutation` returns normally (without raising).
    """
    file = _write(tmp_path, [
        {
            "name": "rds-storage-unencrypted",
            "resource": "aws.rds",
            "filters": [
                {"or": [
                    {"type": "value", "key": "StorageEncrypted", "value": False},
                    {"type": "value", "key": "StorageEncrypted", "value": "absent"},
                ]}
            ],
        }
    ])
    resources = [
        {"DBInstanceIdentifier": "db-unencrypted", "StorageEncrypted": False},
        {"DBInstanceIdentifier": "db-encrypted", "StorageEncrypted": True},
    ]

    def delete_all_filters(policy_data):
        policy_data["filters"] = []
        return policy_data

    def real_assertions(matched):
        assert [r["DBInstanceIdentifier"] for r in matched] == ["db-unencrypted"]

    verify_mutation(
        file, "rds-storage-unencrypted", resources,
        mutate=delete_all_filters,
        assertions=real_assertions,
    )


def test_filter_that_swallows_its_own_aws_failure_still_raises(tmp_path):
    """The harder half of the same guarantee.

    `security-group` lets `FilterNeedsNetwork` propagate, so catching it is
    enough. `bucket-encryption` does not: c7n wraps its `GetBucketEncryption`
    call in `try/except`, logs the failure and drops the bucket. The
    exception never reaches us and the filter hands back an empty list,
    which reads exactly like "no bucket matched".

    That is an absence reported as a zero, inside the module written to
    prevent it. `_forbidden_session` records the attempt so `_filter` can
    tell the two apart afterwards.
    """
    file = _write(tmp_path, [
        {
            "name": "s3-not-kms-encrypted",
            "resource": "aws.s3",
            "filters": [
                {"type": "bucket-encryption", "crypto": "aws:kms"}
            ],
        }
    ])
    resources = [{"Name": "a-bucket"}]

    with pytest.raises(FilterNeedsNetwork, match="caught the failure itself"):
        run_policy(file, "s3-not-kms-encrypted", resources)
