"""Lets `tests/` import `c7n_kit.*` without installing the package first.

Every module in `c7n_kit/` is meant to be usable on its own, copied into
another repository without the rest of the kit. Running the suite HERE is the
one case that needs the repository root on `sys.path`, so it is done here and
not by making the modules import each other.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
