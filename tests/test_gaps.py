"""Tests for c7n_kit/gaps.py. No credentials, no network.

The line texts used here are the REAL format from c7n-org (see the
docstring in c7n_kit/gaps.py for the link and source line numbers), with
`error:` filled in with real AWS messages for IAM/KMS.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from c7n_kit.gaps import (
    classify,
    render_human,
    render_machine,
    OWN_PERMISSION,
    RESOURCE_POLICY,
    SERVICE_ABSENT,
    EPHEMERAL_RESOURCE,
    THROTTLED,
    UNKNOWN,
)


def _policy_error_line(policy, account, region, error):
    return (f"2024-01-01 10:00:00,000 - c7n_org - ERROR - "
            f"Exception running policy:{policy} account:{account} "
            f"region:{region} error:{error}")


def test_resource_policy_is_not_own_permission():
    """The module's single most valuable distinction: a denial from the
    RESOURCE's policy can't land in the same bucket as a denial from our own
    role, because the reader will go check the role's permissions, find them
    fine, and conclude the message is lying.
    """
    line = _policy_error_line(
        "kms-key-rotation", "prod", "us-east-1",
        "An error occurred (AccessDeniedException) when calling the "
        "GetKeyRotationStatus operation: User: "
        "arn:aws:sts::111122223333:assumed-role/c7n/c7n is not authorized "
        "to perform: kms:GetKeyRotationStatus on resource: "
        "arn:aws:kms:us-east-1:111122223333:key/abc-123 because no "
        "resource-based policy allows the kms:GetKeyRotationStatus action")

    gaps = classify(line)

    assert len(gaps) == 1
    g = gaps[0]
    assert g.kind == RESOURCE_POLICY
    assert g.kind != OWN_PERMISSION
    assert g.resource == "arn:aws:kms:us-east-1:111122223333:key/abc-123"
    assert g.account == "prod" and g.region == "us-east-1"
    assert g.policy == "kms-key-rotation"


def test_own_permission_by_identity_based_phrase():
    line = _policy_error_line(
        "iam-no-root-keys", "prod", "us-east-1",
        "An error occurred (AccessDenied) when calling the ListUsers "
        "operation: User: arn:aws:sts::111122223333:assumed-role/c7n/c7n is "
        "not authorized to perform: iam:ListUsers because no identity-based "
        "policy allows the iam:ListUsers action")

    gaps = classify(line)

    assert gaps[0].kind == OWN_PERMISSION
    assert gaps[0].resource is None


def test_own_permission_by_generic_access_denied_without_phrase():
    """Most services do NOT add the "because no ... policy allows" phrase.
    Without it, the default has to stay own-permission (the most common
    reading), not unknown: unknown is for what truly can't be read, not for
    what "could be either of the two."
    """
    line = _policy_error_line(
        "ec2-imdsv2", "prod", "us-east-1",
        "An error occurred (UnauthorizedOperation) when calling the "
        "DescribeInstances operation: You are not authorized to perform "
        "this operation.")

    gaps = classify(line)

    assert gaps[0].kind == OWN_PERMISSION


def test_literal_access_denied_without_error_text():
    """The 'Access denied api:...' format (L1266 of c7n_org/cli.py) carries
    no error text: the literal 'AccessDenied' code already says it all."""
    line = ("2024-01-01 - WARNING - Access denied api:GetBucketPolicy "
            "policy:s3-encrypt-in-transit account:prod region:us-east-1")

    gaps = classify(line)

    assert len(gaps) == 1
    assert gaps[0].kind == OWN_PERMISSION
    assert gaps[0].policy == "s3-encrypt-in-transit"


def test_consensus_a_single_account_is_not_enough():
    """A single account with the endpoint down isn't enough to say the
    service doesn't exist in the region: it could just as likely be a
    one-off network outage. Without a second account confirming it, it's
    unknown: no certainty gets invented where there is none.
    """
    line = _policy_error_line(
        "s3express-encryption", "account-1", "sa-east-1",
        'Could not connect to the endpoint URL: '
        '"https://s3express-control.sa-east-1.amazonaws.com/"')

    gaps = classify(line, accounts_for_consensus=2)

    assert len(gaps) == 1
    assert gaps[0].kind != SERVICE_ABSENT
    assert gaps[0].kind == UNKNOWN


def test_consensus_two_accounts_confirm_service_absent():
    """Two DISTINCT accounts failing identically on the same (policy,
    region) is the signal that AWS doesn't offer the service there, not a
    network outage: a real outage landing on the exact same pair across two
    independent accounts is far less likely than "the region doesn't have
    it."
    """
    error = ('Could not connect to the endpoint URL: '
             '"https://s3express-control.sa-east-1.amazonaws.com/"')
    output = "\n".join([
        _policy_error_line("s3express-encryption", "account-1", "sa-east-1", error),
        _policy_error_line("s3express-encryption", "account-2", "sa-east-1", error),
    ])

    gaps = classify(output, accounts_for_consensus=2)

    assert len(gaps) == 2
    assert all(g.kind == SERVICE_ABSENT for g in gaps)


def test_consensus_is_by_policy_and_region_not_region_alone():
    """Two accounts failing in the SAME region but for DIFFERENT policies
    don't count as the same consensus: they could be two different services,
    each with its own problem, and grouping by region alone would invent
    consensus where there isn't any.
    """
    output = "\n".join([
        _policy_error_line(
            "policy-a", "account-1", "sa-east-1",
            'Could not connect to the endpoint URL: "https://a.amazonaws.com/"'),
        _policy_error_line(
            "policy-b", "account-2", "sa-east-1",
            'Could not connect to the endpoint URL: "https://b.amazonaws.com/"'),
    ])

    gaps = classify(output, accounts_for_consensus=2)

    assert all(g.kind == UNKNOWN for g in gaps)


def test_ephemeral_resource_is_not_a_permission_gap():
    line = _policy_error_line(
        "ec2-ami-deregistered", "bi", "us-east-1",
        "An error occurred (InvalidInstanceID.NotFound) when calling the "
        "DescribeInstances operation: The instance ID 'i-0abc123' does not "
        "exist")

    gaps = classify(line)

    assert gaps[0].kind == EPHEMERAL_RESOURCE


def test_throttled_by_generic_throttling():
    line = _policy_error_line(
        "iam-credential-report", "prod", "us-east-1",
        "An error occurred (ThrottlingException) when calling the "
        "GenerateCredentialReport operation: Rate exceeded")

    gaps = classify(line)

    assert gaps[0].kind == THROTTLED


def test_unknown_error_format_is_not_dropped():
    """A new error code that doesn't match any known kind has to SHOW UP in
    the result as `unknown`, it can't silently disappear. That's the
    module's central guarantee.
    """
    line = _policy_error_line(
        "something-new", "prod", "us-east-1",
        "An error occurred (TotallyNewNobodyHasSeenBefore) when calling "
        "the SomeNewOperation operation: who knows what this is")

    gaps = classify(line)

    assert len(gaps) == 1
    assert gaps[0].kind == UNKNOWN
    # The raw text isn't lost: whoever investigates needs to be able to read it.
    assert "TotallyNewNobodyHasSeenBefore" in gaps[0].raw


def test_policy_load_error_without_policy_name_is_still_a_gap():
    """The 'Error running policy in %s @ %s exception: %s' format carries no
    policy name (the failure belongs to the WHOLE file, before anything
    ran), but it's still a gap: it can't be lost for missing one field.
    """
    line = ("2024-01-01 - WARNING - Error running policy in prod @ "
            "us-east-1 exception: ModuleNotFoundError: custom filter not "
            "registered")

    gaps = classify(line)

    assert len(gaps) == 1
    assert gaps[0].account == "prod" and gaps[0].region == "us-east-1"
    assert gaps[0].policy  # not empty, even though it's not in the line
    assert gaps[0].kind == UNKNOWN


def test_line_without_known_format_does_not_produce_a_false_gap():
    """Normal log noise (progress, match summary) isn't a gap."""
    line = ("2024-01-01 - INFO - Ran account:prod region:us-east-1 "
            "policy:s3-encrypt-in-transit matched:3 time:1.23")

    assert classify(line) == []


def test_render_human_shows_unknown_even_when_not_requested():
    known_error = _policy_error_line(
        "iam-no-root-keys", "prod", "us-east-1",
        "An error occurred (AccessDenied) when calling ListUsers operation: "
        "because no identity-based policy allows the iam:ListUsers action")
    unknown_error = _policy_error_line(
        "something-new", "prod", "us-east-1", "CodeThatDoesNotExistYet: boom")
    gaps = classify(known_error + "\n" + unknown_error)

    text = render_human(gaps)

    assert "UNKNOWN" in text.upper()
    assert "something-new" in text


def test_render_machine_one_line_per_gap_with_parseable_fields():
    line = _policy_error_line(
        "kms-key-rotation", "prod", "us-east-1",
        "AccessDeniedException: on resource: arn:aws:kms:us-east-1:1:key/x "
        "because no resource-based policy allows the action")
    gaps = classify(line)

    output = render_machine(gaps)

    assert output.count("\n") == 0  # a single gap, a single line
    assert "kind=resource-policy" in output
    assert "account=prod" in output
    assert "region=us-east-1" in output
    assert 'resource="arn:aws:kms:us-east-1:1:key/x"' in output
