"""
Phase B1 — Health and liveness checks.

These are the first tests to run. If they fail, skip everything else.
"""

import pytest
import requests
from helpers import TIMEOUT

pytestmark = pytest.mark.integration


def test_agent_a_is_alive(agent_a):
    r = requests.get(f"{agent_a}/api/health", timeout=TIMEOUT)
    assert r.status_code == 200


def test_agent_a_health_fields(agent_a):
    body = requests.get(f"{agent_a}/api/health", timeout=TIMEOUT).json()
    assert body.get("status") == "active"
    assert "agent" in body
    assert "version" in body
    assert "uptime" in body


def test_agent_a_info(agent_a):
    r = requests.get(f"{agent_a}/api/info", timeout=TIMEOUT)
    assert r.status_code == 200
    body = r.json()
    assert "name" in body
    assert "capabilities" in body


def test_agent_a_engine_active(agent_a):
    """The in-process keri-go engine must be active for identity operations to work."""
    body = requests.get(f"{agent_a}/api/health", timeout=TIMEOUT).json()
    mode = body.get("mode", "")
    assert "active" in mode, (
        f"Engine not active. mode='{mode}'. "
        "The keri-go engine runs in-process in the Go core; no external driver is required."
    )


@pytest.mark.two_instance
def test_agent_b_is_alive(agent_b):
    r = requests.get(f"{agent_b}/api/health", timeout=TIMEOUT)
    assert r.status_code == 200


@pytest.mark.two_instance
def test_agent_b_health_fields(agent_b):
    body = requests.get(f"{agent_b}/api/health", timeout=TIMEOUT).json()
    assert body.get("status") == "active"
