"""Fails when a number in the README stops matching the repository.

The README claimed "78 tests, every one mutation-verified" while five of
them were. Nobody was lying: the sentence was written once and the suite
kept growing. A number in prose is a claim like any other, so it gets the
same treatment as coverage in this kit: measured, not asserted.

Run from the repository root:

    python scripts/check_claims.py
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def collected_tests() -> int:
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    found = re.search(r"(\d+) tests? collected", out)
    if not found:
        raise SystemExit("could not read the collected test count from pytest")
    return int(found.group(1))


def mutation_verified_tests() -> int:
    """Test functions that call verify_mutation, not calls to it.

    A test with two mutations is one mutation-verified test, and counting
    calls would inflate the claim in exactly the direction this script
    exists to prevent.
    """
    total = 0
    for path in (ROOT / "tests").rglob("test_*.py"):
        blocks = re.split(r"^def (?=test_)", path.read_text(encoding="utf-8"),
                          flags=re.M)
        total += sum(1 for b in blocks[1:] if "verify_mutation(" in b)
    return total


def claimed(pattern: str, text: str) -> int:
    found = re.search(pattern, text)
    if not found:
        raise SystemExit(f"README no longer contains a claim matching {pattern!r}")
    return int(found.group(1))


def main() -> int:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    checks = [
        ("tests", claimed(r"(\d+) tests,", readme), collected_tests()),
        ("mutation-verified tests",
         claimed(r"(\d+) of them are mutation-verified", readme),
         mutation_verified_tests()),
    ]

    failed = False
    for label, says, measured in checks:
        status = "ok" if says == measured else "DRIFT"
        if says != measured:
            failed = True
        print(f"{status:>5}  {label}: README says {says}, repository has {measured}")

    if failed:
        print("\nUpdate the README, or the claim is the thing that is broken.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
