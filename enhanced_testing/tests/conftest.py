# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Shared pytest scaffolding for the enhanced-testing probe harness.

What this gives you:
  - juice_shop_url    — http://127.0.0.1:3010, the positive-control target
  - clean_ref_url     — http://127.0.0.1:3011, the negative-control target
  - run_probe(name, url, **opts) — invoke a probe and return its parsed
                                  Verdict dict; equivalent to what
                                  toolkit.run_probe() does in production.

Each probe under enhanced_testing/probes/ should ship two tests:

    def test_<probe>_validates_juice_shop(juice_shop_url):
        v = run_probe("<probe>", juice_shop_url)
        assert v["validated"] is True

    def test_<probe>_quiet_on_clean_ref(clean_ref_url):
        v = run_probe("<probe>", clean_ref_url)
        assert v["validated"] is False

Tests skip with a helpful message if the docker-compose stack isn't up.
Bring it up with:
    docker compose -f tests/probe_stack.yml up -d
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest


JUICE_SHOP_PORT = 3010
CLEAN_REF_PORT  = 3011
PROBES_DIR = Path(__file__).resolve().parent.parent / "probes"


def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _require_stack_up(host: str, port: int, name: str) -> None:
    if not _port_open(host, port):
        pytest.skip(
            f"{name} not reachable on 127.0.0.1:{port}. Bring the test "
            f"stack up with:\n"
            f"    cd $(git rev-parse --show-toplevel)/enhanced_testing/tests\n"
            f"    docker compose -f probe_stack.yml up -d\n"
            f"and wait ~20s for Juice Shop to start before re-running."
        )


@pytest.fixture(scope="session")
def juice_shop_url() -> str:
    _require_stack_up("127.0.0.1", JUICE_SHOP_PORT, "Juice Shop")
    return f"http://127.0.0.1:{JUICE_SHOP_PORT}"


@pytest.fixture(scope="session")
def clean_ref_url() -> str:
    _require_stack_up("127.0.0.1", CLEAN_REF_PORT, "clean-ref nginx")
    return f"http://127.0.0.1:{CLEAN_REF_PORT}"


def run_probe(name: str, url: str, **extra) -> dict:
    """Invoke a probe via its standard `--stdin` JSON entry point and
    return the parsed verdict dict. Mirrors what toolkit.run_probe()
    does in production so probe behavior under tests is identical to
    behavior under the live orchestrator.

    `extra` is merged into the JSON config — useful for probe-specific
    args (cookie, custom paths, etc.).
    """
    script = PROBES_DIR / f"{name}.py"
    if not script.is_file():
        raise FileNotFoundError(f"no probe at {script}")
    config = {
        "url": url,
        "method": "GET",
        "scope": [],            # tests run against localhost; permissive
        "max_requests": 60,
        "max_rps": 20.0,
        "dry_run": False,
    }
    config.update(extra or {})
    proc = subprocess.run(
        [sys.executable, str(script), "--stdin"],
        input=json.dumps(config).encode(),
        capture_output=True, timeout=120, check=False,
    )
    out = proc.stdout.decode("utf-8", "replace")
    try:
        return json.loads(out)
    except json.JSONDecodeError as e:
        raise AssertionError(
            f"probe {name!r} did not produce JSON output.\n"
            f"  exit_code: {proc.returncode}\n"
            f"  stdout (first 1k): {out[:1000]!r}\n"
            f"  stderr (first 1k): {proc.stderr.decode('utf-8','replace')[:1000]!r}"
        ) from e
