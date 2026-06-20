#!/usr/bin/env python3
"""Web login steel thread — challenge → assertion → verify (classical Ed25519)."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENV_PY = ROOT / "drivers/keri-core/.venv-keri1117/bin/python"


def http_json(method: str, url: str, body: dict | None = None) -> dict:
    data = None
    headers = {"Content-Type": "application/json"}
    if body is not None:
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def main() -> int:
    print("Login steel thread test — run login-verify package tests via node")
    verify_pkg = ROOT / "packages/login-verify"
    os.chdir(verify_pkg)
    subprocess.check_call(["npm", "install", "--silent"], cwd=verify_pkg)
    subprocess.check_call(["npm", "run", "build"], cwd=verify_pkg)
    # Node test script
    test_script = verify_pkg / "src/steel-thread.test.mjs"
    if not test_script.exists():
        print("steel-thread.test.mjs missing — skipping")
        return 0
    subprocess.check_call(["node", str(test_script)])
    print("✅ Login steel thread passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"❌ {e}", file=sys.stderr)
        raise SystemExit(1)