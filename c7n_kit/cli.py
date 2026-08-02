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

USAGE = "usage: c7n-kit <coverage|cadence|dashboard> [args...]"


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv

    if not argv or argv[0] not in ("coverage", "cadence", "dashboard"):
        print(USAGE, file=sys.stderr)
        return 1

    subcommand, rest = argv[0], argv[1:]

    if subcommand == "coverage":
        from c7n_kit.coverage import _cli
    elif subcommand == "cadence":
        from c7n_kit.cadence import _cli
    else:
        from c7n_kit.dashboard import _cli

    return _cli(rest)


if __name__ == "__main__":
    raise SystemExit(main())
