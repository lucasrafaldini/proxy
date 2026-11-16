"""
Housekeeping for files the make targets create on purpose.

    python scripts/housekeeping.py prune-benchmarks [--keep N] [--dir .benchmarks]

pytest-benchmark adds one JSON file per `make bench-save` and never removes
any: keep only the newest N per machine (their names start with an
increasing counter) so baselines cannot accumulate.
"""

import argparse
import sys
from pathlib import Path


def prune_benchmarks(root: Path, keep: int) -> list:
    removed = []
    if not root.is_dir():
        return removed
    for machine in sorted(path for path in root.iterdir() if path.is_dir()):
        saved = sorted(machine.glob("*.json"))
        for old in saved[:max(len(saved) - keep, 0)]:
            old.unlink()
            removed.append(old)
        if not any(machine.iterdir()):
            machine.rmdir()
    return removed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    prune = commands.add_parser("prune-benchmarks", help="Keep only the newest saved benchmark runs.")
    prune.add_argument("--keep", type=int, default=5)
    prune.add_argument("--dir", type=Path, default=Path(".benchmarks"))
    args = parser.parse_args(argv)
    if args.keep < 1:
        parser.error("--keep must be at least 1 (bench-compare needs a baseline)")
    removed = prune_benchmarks(args.dir, args.keep)
    if removed:
        print("Pruned {} old benchmark run(s); kept the newest {} per machine.".format(len(removed), args.keep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
