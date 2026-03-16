"""
Integration test configuration for Phase B live interop tests.

These tests run against actual running Identity Agent instances.
They WILL reset identity state on the target instances — run against
DEDICATED TEST INSTANCES only, never against instances holding real keys.

Configuration via environment variables:

  AGENT_A_URL   URL of instance A (default: http://127.0.0.1:5000)
  AGENT_B_URL   URL of instance B (required for two-instance tests;
                tests are skipped if not set)

  SKIP_RESET    Set to "1" to skip the identity reset before tests
                (useful if you want to test against an already-initialised
                instance without destroying its state)

Run single-instance tests:
  python -m pytest tests/integration/ -m "integration and not two_instance" -v

Run all integration tests (requires two instances):
  AGENT_B_URL=http://127.0.0.1:5001 python -m pytest tests/integration/ -v
"""

import sys
import os
# Ensure tests/integration/ is on the path so `import helpers` works regardless
# of whether pytest is invoked from the repo root or from tests/integration/
sys.path.insert(0, os.path.dirname(__file__))

import pytest
import requests

from helpers import (
    AGENT_A_URL, AGENT_B_URL, SKIP_RESET, TIMEOUT,
    SEED_A, SEED_B,
    derive_key, public_key_cesr, sign_and_encode,
)

import base64

# ---------------------------------------------------------------------------
# Custom pytest marks
# ---------------------------------------------------------------------------
def pytest_configure(config):
    config.addinivalue_line("markers", "integration: live integration tests against a running Identity Agent")
    config.addinivalue_line("markers", "two_instance: requires two running Identity Agent instances (AGENT_B_URL)")


# ---------------------------------------------------------------------------
# Reachability check helper
# ---------------------------------------------------------------------------

def _check_reachable(url: str) -> tuple[bool, str]:
    """Return (reachable, reason). Tries GET /api/health."""
    try:
        r = requests.get(f"{url}/api/health", timeout=TIMEOUT)
        if r.status_code == 200:
            return True, r.json().get("status", "ok")
        return False, f"HTTP {r.status_code}"
    except requests.exceptions.ConnectionError:
        return False, "connection refused"
    except requests.exceptions.Timeout:
        return False, "timeout"
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# Session-scoped URL fixtures (skip if unreachable)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def agent_a():
    """URL + session for instance A. Skips suite if instance is not reachable."""
    reachable, reason = _check_reachable(AGENT_A_URL)
    if not reachable:
        pytest.skip(
            f"Instance A ({AGENT_A_URL}) not reachable: {reason}. "
            f"Start the Identity Agent backend and retry."
        )
    return AGENT_A_URL


@pytest.fixture(scope="session")
def agent_b():
    """URL for instance B. Skips test if AGENT_B_URL not set or unreachable."""
    if not AGENT_B_URL:
        pytest.skip(
            "AGENT_B_URL not set — skipping two-instance test. "
            "Set AGENT_B_URL=http://127.0.0.1:5001 (or wherever instance B runs)."
        )
    reachable, reason = _check_reachable(AGENT_B_URL)
    if not reachable:
        pytest.skip(
            f"Instance B ({AGENT_B_URL}) not reachable: {reason}."
        )
    return AGENT_B_URL


# ---------------------------------------------------------------------------
# Identity reset helper — resets to a clean state before tests
# ---------------------------------------------------------------------------

def reset_instance(base_url: str):
    """POST /api/reset on the given instance. Raises on failure."""
    r = requests.post(f"{base_url}/api/reset", timeout=TIMEOUT)
    assert r.status_code == 200, f"Reset failed: {r.status_code} {r.text}"


# ---------------------------------------------------------------------------
# Deterministic test seeds — one per instance to avoid key collisions
# ---------------------------------------------------------------------------

SEED_A = bytes(range(32))        # b'\x00\x01...\x1f'
SEED_B = bytes([128 + i for i in range(32)])  # b'\x80\x81...\x9f'


# ---------------------------------------------------------------------------
# Module-level identity fixture: reset + create inception, shared per module
# ---------------------------------------------------------------------------

class AgentIdentity:
    """Holds an initialised AID and keys for one agent instance."""
    def __init__(self, base_url: str, seed: bytes):
        self.url   = base_url
        self.seed  = seed
        self.pk0, self.sk0 = derive_key(seed, 0)
        self.pk1, self.sk1 = derive_key(seed, 1)
        self.cesr_pk0 = public_key_cesr(self.pk0)
        self.cesr_pk1 = public_key_cesr(self.pk1)

        # Call inception
        r = requests.post(
            f"{base_url}/api/inception",
            json={"public_key": self.cesr_pk0, "next_public_key": self.cesr_pk1},
            timeout=TIMEOUT,
        )
        assert r.status_code == 201, f"Inception failed: {r.status_code} {r.text}"
        body = r.json()

        self.aid          = body["aid"]
        self.raw_bytes_b64 = body["raw_bytes_b64"]
        self.inception_event = body["inception_event"]

        # Sign and record the CESR signature
        raw_bytes = base64.b64decode(self.raw_bytes_b64)
        self.cesr_sig = sign_and_encode(raw_bytes, self.sk0)


@pytest.fixture(scope="module")
def identity_a(agent_a):
    """Reset instance A and create a fresh test identity."""
    if not SKIP_RESET:
        reset_instance(agent_a)
    return AgentIdentity(agent_a, SEED_A)


@pytest.fixture(scope="module")
def identity_b(agent_b):
    """Reset instance B and create a fresh test identity."""
    if not SKIP_RESET:
        reset_instance(agent_b)
    return AgentIdentity(agent_b, SEED_B)
