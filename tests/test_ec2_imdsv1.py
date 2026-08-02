from kit.testing import run_policy, verify_mutation

FILE = "examples/policies/ec2-imdsv1.yaml"
NAME = "ec2-imdsv2-not-enforced"


def _resources():
    return [
        {"InstanceId": "i-required", "MetadataOptions": {"HttpTokens": "required"}},
        {"InstanceId": "i-optional", "MetadataOptions": {"HttpTokens": "optional"}},
        # Instance with no MetadataOptions in the response: the `ne`
        # operator already treats it as "non-compliant" with no need for
        # an `absent` branch.
        {"InstanceId": "i-not-described"},
    ]


def test_matches_optional_and_not_described():
    matched = run_policy(FILE, NAME, _resources())
    assert {r["InstanceId"] for r in matched} == {"i-optional", "i-not-described"}


def test_the_test_detects_an_inverted_operator():
    """Typical copy-paste mutation: swapping `ne` for `eq` without
    adjusting `value`, ends up inverting the whole policy (flags as a
    problem what actually complies). The test has to notice.
    """

    def invert_operator(policy_data):
        policy_data["filters"][0]["op"] = "eq"
        return policy_data

    def expected(matched):
        assert {r["InstanceId"] for r in matched} == {"i-optional", "i-not-described"}

    verify_mutation(
        FILE, NAME, _resources(),
        mutate=invert_operator,
        assertions=expected,
    )
