from c7n_kit.testing import run_policy

FILE = "examples/policies/s3-no-versioning.yaml"
NAME = "s3-versioning-disabled"


def _resources():
    return [
        {"Name": "bucket-versioned", "Versioning": {"Status": "Enabled"}},
        {"Name": "bucket-suspended", "Versioning": {"Status": "Suspended"}},
        # Versioning was never configured: the key doesn't even show up.
        {"Name": "bucket-never-configured"},
    ]


def test_matches_suspended_and_never_configured():
    matched = run_policy(FILE, NAME, _resources())
    assert {r["Name"] for r in matched} == {
        "bucket-suspended",
        "bucket-never-configured",
    }
