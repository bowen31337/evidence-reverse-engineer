#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Identify a reverse-engineering target by content and suggest a route.

Usage:
  identify_target.py <path> [<path> ...]

Prints JSON: sha256 (file digest, or deterministic tree digest for directories),
size, format, arch, bitness, packer/container hints and the suggested analysis
route (domain, first operations, which reference file to read).
Identification uses magic bytes, never the file name alone.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import emit, fail, identify, route_for  # noqa: E402


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip())
        return 0
    results = []
    for a in argv:
        try:
            ident = identify(a)
        except FileNotFoundError as e:
            fail(f"target not found: {e}")
        ident["route"] = route_for(ident)
        results.append(ident)
    emit({"ok": True, "targets": results} if len(results) > 1 else {"ok": True, **results[0]})


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
