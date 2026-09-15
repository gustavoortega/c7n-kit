"""Loads Cloud Custodian policies from a directory of YAML files.

This is the base of the kit: coverage, cadence, gaps and dashboard all
receive the list of `Policy` this module returns. A bug here (a policy
that gets lost, a resource type canonicalized wrong) propagates silently
to everything else, so the two decisions in this file exist to make sure
that never goes unnoticed.

Rule of the kit: AN ABSENCE IS NOT A ZERO. A YAML that could not be parsed
does not disappear without a trace (it goes into `errors` and gets
logged), and if in the end NO policy could be read from ANY file, that is
an explicit error, not a silent empty list that something downstream
reads as "100% coverage, no missing policies."
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

# Providers that c7n recognizes. The prefix is optional when writing a
# policy (c7n resolves "ec2" and "aws.ec2" to the same type), but if we
# don't canonicalize it here, any `groupby(resource)` downstream (coverage
# by_family, cadence by type) splits the same type into two entries and
# nothing flags it: the count is just wrong.
_PROVIDER_PREFIXES = ("aws.", "azure.", "gcp.", "k8s.", "tencentcloud.")
_DEFAULT_PREFIX = "aws."


@dataclass
class Policy:
    name: str
    resource: str  # canonical, always prefixed (see _canonicalize_resource)
    file: str
    metadata: dict
    raw: dict


class NoPoliciesError(RuntimeError):
    """No file in the directory contributed a single policy.

    This is deliberately distinct from "the directory has 3 YAMLs but
    they're all broken" (that also lands here) versus "there are
    policies but none with metadata" (that is not this error). The error
    message carries the detail of what was attempted so a failed run
    doesn't have to be repeated just to see the logs.
    """


def _canonicalize_resource(resource: str) -> str:
    """Prepends the provider prefix if it wasn't already there.

    c7n accepts "ec2" and "aws.ec2" as the same resource type (it
    resolves the default prefix to "aws" when none is given). If we kept
    the string exactly as it came from the policy, two policies declaring
    the same resource with and without the prefix would end up as two
    different "types" for any code that groups by `resource`, and nobody
    would notice, because there's no exception, just a count silently
    split in two.
    """
    # The comparison is case-insensitive and the prefix is normalised to
    # lowercase: c7n itself accepts "AWS.ec2", and treating it as unprefixed
    # produced "aws.AWS.ec2", which is the same silent split this function
    # exists to prevent, just triggered by a capital letter.
    lowered = resource.lower()
    for prefix in _PROVIDER_PREFIXES:
        if lowered.startswith(prefix):
            return lowered[:len(prefix)] + resource[len(prefix):]
    return f"{_DEFAULT_PREFIX}{resource}"


def _load_file(path: Path) -> list[Policy]:
    """Parses a YAML file and returns its Policy objects. May raise yaml.YAMLError."""
    with path.open("r", encoding="utf-8") as f:
        content = yaml.safe_load(f)

    if content is None:
        # Empty file: not an error, just a file with nothing to contribute.
        return []

    if "policies" not in content:
        # Without a "policies:" key the file isn't a c7n policy file (it
        # could be an include, a fragment, shared config). Skipping it is
        # the right call -- but only for THIS file, not for all of them.
        return []

    policies = []
    for raw in content["policies"] or []:
        policies.append(
            Policy(
                name=raw["name"],
                resource=_canonicalize_resource(raw["resource"]),
                file=str(path),
                metadata=raw.get("metadata", {}) or {},
                raw=raw,
            )
        )
    return policies


def load(directory: str) -> list[Policy]:
    """Loads every policy from the .yml/.yaml files in `directory`.

    A broken YAML (bad indentation, a tab, an invalid YAML reference)
    CANNOT make the policies from sibling files disappear: each file is
    parsed in isolation, and an error is logged and skipped, not
    propagated. The reason is that this kit is used to measure security
    coverage -- if one broken file took down the whole run, the likely
    outcome isn't "someone fixes the YAML," it's "someone silences the
    exception further downstream," and then we can no longer tell "there
    are no coverage gaps" apart from "we couldn't read anything." So
    parse errors accumulate and get logged as warnings, and only if, FILE
    BY FILE, nobody contributed a single valid policy (not even
    partially), only then is it a real error: coverage computed over zero
    policies is not "full coverage," it's an unknown result that must not
    be reported as if it were zero gaps.
    """
    base = Path(directory)
    files = sorted(list(base.glob("*.yml")) + list(base.glob("*.yaml")))

    if not files:
        raise NoPoliciesError(
            f"No .yml/.yaml found in {directory!r}"
        )

    all_policies: list[Policy] = []
    errors: list[str] = []

    for path in files:
        try:
            all_policies.extend(_load_file(path))
        except yaml.YAMLError as e:
            errors.append(f"{path}: {e}")
            logger.warning("Could not parse %s, skipping it: %s", path, e)
        except (KeyError, TypeError) as e:
            # KeyError: "name" or "resource" missing from an individual policy.
            # TypeError: "policies:" isn't a list (e.g. it's a dict or a string).
            errors.append(f"{path}: malformed policy ({e})")
            logger.warning("Malformed policy in %s, skipping it: %s", path, e)
        except OSError as e:
            # Unreadable file: permissions, a broken symlink, a mount that
            # went away. Same rule as a broken YAML, and for the same reason:
            # one file nobody could read must not take the policies that were
            # already parsed from its siblings down with it.
            errors.append(f"{path}: could not be read ({e})")
            logger.warning("Could not read %s, skipping it: %s", path, e)

    if not all_policies:
        detail = "; ".join(errors) if errors else "all files were empty"
        raise NoPoliciesError(
            f"Read {len(files)} file(s) in {directory!r} but "
            f"none contributed a valid policy: {detail}"
        )

    return all_policies
