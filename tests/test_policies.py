"""Tests for c7n_kit/policies.py.

Doesn't use `c7n_kit.testing` or instantiate real c7n policies: `load()` only
reads YAML and builds dataclasses, so it's enough to write files in a
temp directory (no network, no credentials).
"""
from __future__ import annotations

import pytest

from c7n_kit.policies import Policy, NoPoliciesError, load


def _write(tmp_path, name: str, content: str):
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_ec2_and_aws_ec2_are_grouped_under_the_same_resource(tmp_path):
    # If this didn't canonicalize, "ec2" and "aws.ec2" would end up as two
    # distinct types, and any grouping by `resource` (coverage by_family,
    # cadence by type) would split the count in two with no error.
    _write(
        tmp_path,
        "a.yaml",
        """
        policies:
          - name: one
            resource: ec2
          - name: dos
            resource: aws.ec2
        """,
    )
    policies = load(str(tmp_path))
    resources = {p.resource for p in policies}
    assert resources == {"aws.ec2"}


def test_resource_from_another_provider_does_not_get_the_aws_prefix(tmp_path):
    _write(
        tmp_path,
        "a.yaml",
        """
        policies:
          - name: one
            resource: azure.vm
        """,
    )
    [policy] = load(str(tmp_path))
    assert policy.resource == "azure.vm"


def test_broken_yaml_does_not_make_other_files_policies_disappear(tmp_path):
    _write(
        tmp_path,
        "good.yaml",
        """
        policies:
          - name: policy-good
            resource: aws.s3
        """,
    )
    # invalid indentation on purpose: YAML won't parse this.
    _write(
        tmp_path,
        "broken.yaml",
        """
        policies:
          - name: policy-rota
        \tresource: aws.rds
        """,
    )
    policies = load(str(tmp_path))
    names = {p.name for p in policies}
    assert names == {"policy-good"}


def test_file_without_policies_key_is_skipped_without_error(tmp_path):
    _write(tmp_path, "config.yaml", "something: different\nanother: value\n")
    _write(
        tmp_path,
        "rules.yaml",
        """
        policies:
          - name: only-one
            resource: aws.iam-role
        """,
    )
    policies = load(str(tmp_path))
    assert [p.name for p in policies] == ["only-one"]


def test_zero_policies_in_any_file_is_an_error_not_an_empty_list(tmp_path):
    # A file without "policies:" in EVERY file of the directory -- none of
    # them contributed anything. This CANNOT return [], because downstream
    # an empty list would be confused with "coverage with no gaps."
    _write(tmp_path, "config.yaml", "something: different\n")
    _write(tmp_path, "other.yaml", "more: config\n")
    with pytest.raises(NoPoliciesError):
        load(str(tmp_path))


def test_directory_without_yaml_files_is_an_error(tmp_path):
    with pytest.raises(NoPoliciesError):
        load(str(tmp_path))


def test_all_files_broken_is_an_error_not_an_empty_list(tmp_path):
    _write(tmp_path, "roto1.yaml", "policies:\n\t- name: x\n")
    with pytest.raises(NoPoliciesError):
        load(str(tmp_path))


def test_policy_keeps_metadata_and_raw_dict(tmp_path):
    _write(
        tmp_path,
        "a.yaml",
        """
        policies:
          - name: con-metadata
            resource: aws.rds
            metadata:
              severity: high
              frameworks: ['FSBP RDS.1']
            filters:
              - type: value
                key: StorageEncrypted
                value: false
        """,
    )
    [policy] = load(str(tmp_path))
    assert isinstance(policy, Policy)
    assert policy.metadata == {"severity": "high", "frameworks": ["FSBP RDS.1"]}
    assert policy.raw["filters"][0]["key"] == "StorageEncrypted"
    assert policy.file.endswith("a.yaml")


def test_policy_without_metadata_does_not_explode(tmp_path):
    _write(
        tmp_path,
        "a.yaml",
        """
        policies:
          - name: sin-metadata
            resource: aws.s3
        """,
    )
    [policy] = load(str(tmp_path))
    assert policy.metadata == {}
