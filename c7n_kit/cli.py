"""Unified entrypoint for the `c7n-kit` console script.

Each subcommand dispatches to the same `_cli(argv)` function that module's
own `python -m c7n_kit.<module>` invocation already calls, so both
invocation styles produce byte-identical output. Nothing here duplicates
logic that lives in `coverage.py`, `cadence.py` or `dashboard.py`.

`gaps.py` has no subcommand here: unlike the other three modules it has no
`if __name__ == "__main__":` block, because it is meant to be used as a
library fed a `c7n-org` log rather than invoked directly.
"""
import sys

COMMANDS = {
    "coverage": "controls covered per framework, with the denominator shown",
    "cadence": "what each rule costs c7n-org, resolved per resource type",
    "dashboard": "generate a dashboard from the policies in a directory",
}

USAGE = "\n".join(
    ["usage: c7n-kit <command> [args...]", ""]
    + [f"  {name:<10} {help_text}" for name, help_text in COMMANDS.items()]
    + ["",
       "The catalogues and policies are yours: every command takes paths.",
       "This package ships the instrument, not a catalogue.",
       "Example: c7n-kit coverage path/to/fsbp.txt path/to/policies"]
)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv

    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0

    if argv[0] not in COMMANDS:
        print(f"c7n-kit: unknown command {argv[0]!r}\n", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 1

    subcommand, rest = argv[0], argv[1:]

    if subcommand == "coverage":
        from c7n_kit.coverage import _cli
    elif subcommand == "cadence":
        from c7n_kit.cadence import _cli
    else:
        from c7n_kit.dashboard import _cli

    try:
        return _cli(rest)
    except FileNotFoundError as e:
        # A path that is not there is the most common first-run error, and a
        # traceback here reads as a bug in the kit rather than a typo in the
        # command. It exits 2 so a script can tell it apart from a run that
        # worked and found gaps.
        print(f"c7n-kit {subcommand}: {e.filename}: no such file or directory",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
