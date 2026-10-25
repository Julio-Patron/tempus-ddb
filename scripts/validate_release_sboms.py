"""Fail unless the three release SBOM files are present and well formed.

SPDX must be 2.3. Each CycloneDX file must carry bomFormat, specVersion and
serialNumber, because actions/attest-sbom rejects a CycloneDX document that
has no serial number.
"""

import json
import os
import sys
from pathlib import Path


def main():
    tag = os.environ.get("RELEASE_TAG")
    if not tag:
        sys.exit("RELEASE_TAG is not set")
    root = Path(__file__).resolve().parents[1]
    files = [
        root / "sbom" / f"tempus-ddb-{tag}.spdx.json",
        root / "sbom" / f"tempus-ddb-{tag}.rust.cdx.json",
        root / "sbom" / f"tempus-ddb-{tag}.python.cdx.json",
    ]
    for path in files:
        if not path.is_file():
            sys.exit(f"missing SBOM: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        if path.name.endswith(".spdx.json"):
            if data.get("spdxVersion") != "SPDX-2.3" or not data.get("packages"):
                sys.exit(f"invalid SPDX SBOM: {path}")
        else:
            if (
                data.get("bomFormat") != "CycloneDX"
                or not data.get("serialNumber")
                or not data.get("specVersion")
            ):
                sys.exit(f"invalid CycloneDX SBOM: {path}")
            if not data.get("components"):
                sys.exit(f"CycloneDX SBOM has no components: {path}")
        print(f"ok {path.name} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
