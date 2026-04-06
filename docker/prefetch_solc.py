#!/usr/bin/env python3
"""
Populate ~/.solc-select/artifacts without `solc-select install`.

`solc-select` uses urllib without a browser User-Agent; binaries.soliditylang.org
often returns 403 for list.json in Docker builds. This script fetches list.json
and binaries with an explicit UA and writes the layout solc-select expects.

linux-arm64 only ships recent 0.8.x builds; use platform: linux/amd64 in Compose
for full 0.4–0.8 coverage (see docker-compose.yml).
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.request

# Must match app.services.solidity_version._VERSION_BY_MINOR patch releases.
_VERSIONS_AMD64 = ["0.4.26", "0.5.17", "0.6.12", "0.7.6", "0.8.20"]
_VERSIONS_ARM64 = ["0.8.31"]

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (compatible; AuditQuant/1.0)"


def _fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode())


def _fetch_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=300) as r:
        return r.read()


def main() -> None:
    targetarch = os.environ.get("TARGETARCH", "amd64")
    if targetarch == "arm64":
        platform_dir = "linux-arm64"
        versions = _VERSIONS_ARM64
        default_ver = "0.8.31"
    else:
        platform_dir = "linux-amd64"
        versions = _VERSIONS_AMD64
        default_ver = "0.8.20"

    list_url = f"https://binaries.soliditylang.org/{platform_dir}/list.json"
    listing = _fetch_json(list_url)
    stable: dict[str, dict] = {}
    for b in listing.get("builds", []):
        if b.get("prerelease"):
            continue
        v = b.get("version")
        if isinstance(v, str):
            stable[v] = b

    home = os.path.expanduser("~")
    artifacts = os.path.join(home, ".solc-select", "artifacts")
    os.makedirs(artifacts, exist_ok=True)

    for ver in versions:
        b = stable.get(ver)
        if not b or "path" not in b:
            print(f"prefetch_solc: missing build for {ver} on {platform_dir}", file=sys.stderr)
            sys.exit(1)
        path = b["path"]
        bin_url = f"https://binaries.soliditylang.org/{platform_dir}/{path}"
        data = _fetch_bytes(bin_url)
        exp_sha = b.get("sha256") or ""
        if exp_sha:
            digest = "0x" + hashlib.sha256(data).hexdigest()
            if digest.lower() != exp_sha.lower():
                print(f"prefetch_solc: sha256 mismatch for {ver}", file=sys.stderr)
                sys.exit(1)
        dest_dir = os.path.join(artifacts, f"solc-{ver}")
        os.makedirs(dest_dir, exist_ok=True)
        dest_bin = os.path.join(dest_dir, f"solc-{ver}")
        with open(dest_bin, "wb") as f:
            f.write(data)
        os.chmod(dest_bin, 0o775)

    sel_dir = os.path.join(home, ".solc-select")
    os.makedirs(sel_dir, exist_ok=True)
    with open(os.path.join(sel_dir, "global-version"), "w", encoding="utf-8") as f:
        f.write(default_ver)


if __name__ == "__main__":
    main()
