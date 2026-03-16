"""
Shared pytest fixtures and Windows compatibility for KERI interoperability tests.

This module runs before any test file is imported, which is required because:
  - libsodium.dll must be loaded before pysodium is imported on Windows
  - SysLogHandler must be patched before keripy is imported on Windows
"""

import sys
import os
import ctypes
import ctypes.util
import hashlib
import json

# ---------------------------------------------------------------------------
# Windows: load libsodium.dll before any keripy import
# ---------------------------------------------------------------------------
def _ensure_libsodium():
    if ctypes.util.find_library("sodium"):
        return
    if sys.platform != "win32":
        return
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    search_dirs = [
        os.path.join(repo_root, "identity_agent_ui", "build", "windows",
                     "x64", "runner", "Release", "backend"),
        os.path.join(repo_root, "identity_agent_ui", "build", "windows",
                     "x64", "runner", "Release", "backend", "keri-driver"),
        os.path.join(repo_root, "drivers", "keri-core"),
        script_dir,
    ]
    for d in search_dirs:
        dll_path = os.path.join(d, "libsodium.dll")
        if os.path.isfile(dll_path):
            try:
                ctypes.CDLL(dll_path)
                os.environ["PATH"] = d + ";" + os.environ.get("PATH", "")
                return
            except OSError:
                continue


_ensure_libsodium()

# ---------------------------------------------------------------------------
# Windows: patch SysLogHandler (uses AF_UNIX which doesn't exist on Windows)
# ---------------------------------------------------------------------------
if sys.platform == "win32":
    import socket as _socket
    import logging as _logging
    import logging.handlers as _lh

    if not hasattr(_socket, "AF_UNIX"):
        _socket.AF_UNIX = 1

    def _win_syslog_init(self, address=("localhost", _lh.SYSLOG_UDP_PORT),
                         facility=_lh.SysLogHandler.LOG_USER, socktype=None):
        _logging.Handler.__init__(self)
        self.address = address
        self.facility = facility
        self.socktype = socktype
        self.unixsocket = False
        self.socket = None
        self.ident = ""
        self.append_nul = True

    _lh.SysLogHandler.__init__ = _win_syslog_init
    _lh.SysLogHandler.createSocket = lambda self: None
    _lh.SysLogHandler.emit = lambda self, record: None
    _lh.SysLogHandler.close = lambda self: _logging.Handler.close(self)

# ---------------------------------------------------------------------------
# Now safe to import keripy
# ---------------------------------------------------------------------------
import pytest
import pysodium
from keri.core import coring, eventing
from keri.core.coring import MtrDex


# ---------------------------------------------------------------------------
# Deterministic test seeds — never change these; they are canonical inputs
# ---------------------------------------------------------------------------
SEED_ISSUER = bytes(range(32))   # b'\x00\x01\x02...'\x1f'
SEED_HOLDER = bytes([42] * 32)   # b'***...'
SEED_OTHER  = bytes([99] * 32)   # b'ccc...'  (attacker / third-party)


# ---------------------------------------------------------------------------
# Key derivation — mirrors the Dart KeyManager.generateFromSeed path
# ---------------------------------------------------------------------------
def derive_key(seed: bytes, index: int = 0):
    """Return (pk, sk) for an Ed25519 keypair at the given derivation index.

    Index 0  → sha256(seed[:32])
    Index N  → sha256(seed[:32] + bytes([N]))
    """
    raw = (
        hashlib.sha256(seed[:32]).digest()
        if index == 0
        else hashlib.sha256(seed[:32] + bytes([index])).digest()
    )
    return pysodium.crypto_sign_seed_keypair(raw)


def make_aid(seed: bytes):
    """Create a minimal KERI inception event and return a dict of components."""
    pk0, sk0 = derive_key(seed, 0)
    pk1, _   = derive_key(seed, 1)
    vf  = coring.Verfer(raw=pk0, code=MtrDex.Ed25519)
    d1  = coring.Diger(raw=pk1, code=MtrDex.Blake3_256)
    icp = eventing.incept(keys=[vf.qb64], ndigs=[d1.qb64], code=MtrDex.Blake3_256)
    return {"aid": icp.pre, "pk": pk0, "sk": sk0, "verfer": vf, "icp": icp}


def compute_said(obj: dict) -> str:
    """Compute Blake3_256 self-addressing ID over a JSON-serialised dict."""
    return coring.Diger(
        ser=json.dumps(obj, separators=(",", ":")).encode(),
        code=MtrDex.Blake3_256,
    ).qb64


# ---------------------------------------------------------------------------
# Session-scoped identity fixtures (created once, shared across all phases)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def issuer():
    """Issuer identity components (aid, pk, sk, verfer, icp)."""
    return make_aid(SEED_ISSUER)


@pytest.fixture(scope="session")
def holder():
    """Holder identity components (aid, pk, sk, verfer, icp)."""
    return make_aid(SEED_HOLDER)


@pytest.fixture(scope="session")
def attacker():
    """Attacker identity — used for negative (rejection) tests."""
    return make_aid(SEED_OTHER)
