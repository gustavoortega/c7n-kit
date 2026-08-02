# Test of the flagship example: explicit `absent` branch against the
# `None == False` trap. See examples/policies/rds-unencrypted.yaml.
from kit.testing import run_policy, verify_mutation

FILE = "examples/policies/rds-unencrypted.yaml"
NAME = "rds-storage-unencrypted"


def _ids(resources):
    return {r["DBInstanceIdentifier"] for r in resources}


def _resources():
    return [
        {"DBInstanceIdentifier": "db-encrypted", "StorageEncrypted": True},
        {"DBInstanceIdentifier": "db-unencrypted", "StorageEncrypted": False},
        # AWS didn't return the field: this is the case the `absent`
        # branch has to cover. Without it, this resource would pass as
        # "compliant".
        {"DBInstanceIdentifier": "db-not-described"},
    ]


def test_matches_explicit_false_encryption():
    matched = run_policy(FILE, NAME, _resources())
    assert _ids(matched) == {"db-unencrypted", "db-not-described"}


def test_does_not_match_the_encrypted_ones():
    matched = run_policy(FILE, NAME, _resources())
    assert "db-encrypted" not in _ids(matched)


def test_the_test_depends_on_the_absent_branch():
    """Mutation check: if someone deletes the `absent` branch of the `or`
    (the easiest mistake to make while "simplifying" the policy), this
    test has to go red. If it stays green,
    `test_matches_explicit_false_encryption` wasn't testing what it claims
    to test.
    """

    def without_absent_branch(policy_data):
        branch = policy_data["filters"][0]["or"]
        policy_data["filters"][0]["or"] = [
            f for f in branch if f.get("value") != "absent"
        ]
        return policy_data

    def expected(matched):
        assert _ids(matched) == {"db-unencrypted", "db-not-described"}

    verify_mutation(
        FILE, NAME, _resources(),
        mutate=without_absent_branch,
        assertions=expected,
    )
