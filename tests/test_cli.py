"""Tests for the console script. No credentials, no network.

The entry point a `pip install c7n-kit` user actually runs had no test at
all, which is how it shipped printing a traceback for a missing file.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from c7n_kit.cli import main


def test_help_lists_every_command(capsys):
    assert main(["--help"]) == 0
    out = capsys.readouterr().out
    for command in ("coverage", "cadence", "dashboard"):
        assert command in out


def test_no_arguments_prints_help_not_a_bare_usage_line(capsys):
    assert main([]) == 0
    assert "coverage" in capsys.readouterr().out


def test_unknown_command_names_what_was_typed(capsys):
    assert main(["covrage"]) == 1
    assert "covrage" in capsys.readouterr().err


def test_missing_catalog_is_a_message_not_a_traceback(capsys, tmp_path):
    """The first thing someone who pip-installed this hits: the README's
    example paths only exist inside the git clone."""
    policies = tmp_path / "policies"
    policies.mkdir()
    (policies / "p.yml").write_text(
        "policies:\n  - name: a\n    resource: aws.ec2\n", encoding="utf-8")

    code = main(["coverage", str(tmp_path / "nope.txt"), str(policies)])

    assert code == 2
    err = capsys.readouterr().err
    assert "nope.txt" in err
    assert "Traceback" not in err
