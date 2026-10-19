"""The package's copyright file (packaging/deb/build): yk-portal's license, then the
license of each Python package bundled with it, read from their metadata.

    /opt/yk-portal/bin/python -I packaging/deb/copyright.py LICENSE
"""

import importlib.metadata
import sys
from pathlib import Path

# Licenses whose text Debian keeps in /usr/share/common-licenses.
COMMON_LICENSES = {
    "Apache-2.0": "/usr/share/common-licenses/Apache-2.0",
    "LGPL-3.0": "/usr/share/common-licenses/LGPL-3",
}


def license_of(distribution: importlib.metadata.Distribution) -> str:
    metadata = distribution.metadata
    if expression := metadata.get("License-Expression"):
        return expression
    classifiers = [
        c.removeprefix("License :: OSI Approved :: ").removeprefix("License :: ")
        for c in metadata.get_all("Classifier") or []
        if c.startswith("License :: ")
    ]
    if classifiers:
        return " or ".join(classifiers)
    text = (metadata.get("License") or "").strip()
    return text.splitlines()[0] if text else "see its license files"


def main(license_file: str) -> None:
    site = Path(str(importlib.metadata.distribution("yk-portal").locate_file("")))
    bundled = sorted(
        (d for d in importlib.metadata.distributions() if d.metadata["Name"] != "yk-portal"),
        key=lambda d: d.metadata["Name"].lower(),
    )
    print("yk-portal")
    print("https://github.com/robert-patrick-texas/yk-portal")
    print()
    print(Path(license_file).read_text().rstrip())
    print()
    print()
    print("The package includes these Python packages, each under its own license.")
    print(f"Their license files are in {site}/NAME-VERSION.dist-info/.")
    print()
    licenses = {}
    for d in bundled:
        licenses[d.metadata["Name"]] = license_of(d)
        print(f"  {d.metadata['Name']} {d.version}: {licenses[d.metadata['Name']]}")
    print()
    for spdx, common in COMMON_LICENSES.items():
        names = [name for name, text in licenses.items() if spdx in text]
        if names and Path(common).exists():
            print(f"The {spdx} license ({', '.join(names)}) is in {common}.")


if __name__ == "__main__":
    main(sys.argv[1])
