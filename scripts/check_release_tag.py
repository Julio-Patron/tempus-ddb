"""Fail unless the release tag matches Cargo.toml and pyproject.toml.

The release workflow calls this before it uploads artifacts or publishes.
A tag that does not start with ``v``, or that disagrees with either
package manifest, exits non-zero so the publish jobs stop.
"""

import argparse
import sys
from pathlib import Path

import tomllib


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("tag", help="Release tag, for example v0.5.3")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if not args.tag.startswith("v") or len(args.tag) < 2:
        sys.exit(f"release tag must look like vX.Y.Z, got {args.tag!r}")
    version = args.tag[1:]
    cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["package"]["version"]
    python = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    if cargo != version or python != version:
        sys.exit(
            "version mismatch: "
            f"tag {version}, Cargo.toml {cargo}, pyproject.toml {python}"
        )
    print(f"release tag {args.tag} matches Cargo.toml and pyproject.toml")


if __name__ == "__main__":
    main()
