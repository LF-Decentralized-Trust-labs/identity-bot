"""Shared constants and helpers for integration tests."""

import os
import sys
import ctypes
import ctypes.util
import hashlib
import base64

# ---------------------------------------------------------------------------
# Windows: libsodium + SysLogHandler (needed before keripy import)
# ---------------------------------------------------------------------------
def _ensure_libsodium():
    if ctypes.util.find_library("sodium"):
        return
    if sys.platform != "win32":
        return
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root  = os.path.dirname(os.path.dirname(script_dir))
    for d in [
        os.path.join(repo_root, "identity_agent_ui", "build", "windows",
                     "x64", "runner", "Release", "backend"),
        os.path.join(repo_root, "drivers", "keri-core"),
        script_dir,
    ]:
        dll = os.path.join(d, "libsodium.dll")
        if os.path.isfile(dll):
            try:
                ctypes.CDLL(dll)
                os.environ["PATH"] = d + ";" + os.environ.get("PATH", "")
                return
            except OSError:
                continue


_ensure_libsodium()

if sys.platform == "win32":
    import socket as _s, logging as _l, logging.handlers as _lh
    if not hasattr(_s, "AF_UNIX"):
        _s.AF_UNIX = 1
    def _wsi(self, address=("localhost", _lh.SYSLOG_UDP_PORT),
             facility=_lh.SysLogHandler.LOG_USER, socktype=None):
        _l.Handler.__init__(self)
        self.address = address; self.facility = facility; self.socktype = socktype
        self.unixsocket = False; self.socket = None; self.ident = ""; self.append_nul = True
    _lh.SysLogHandler.__init__ = _wsi
    _lh.SysLogHandler.createSocket = lambda self: None
    _lh.SysLogHandler.emit = lambda self, record: None
    _lh.SysLogHandler.close = lambda self: _l.Handler.close(self)

import pysodium
from keri.core import coring
from keri.core.coring import MtrDex

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TIMEOUT = 10  # HTTP request timeout in seconds

AGENT_A_URL = os.environ.get("AGENT_A_URL", "http://127.0.0.1:5050").rstrip("/")
AGENT_B_URL = os.environ.get("AGENT_B_URL", "").rstrip("/")
SKIP_RESET  = os.environ.get("SKIP_RESET", "0") == "1"

# Deterministic test seeds — one per instance
SEED_A = bytes(range(32))
SEED_B = bytes([128 + i for i in range(32)])


# ---------------------------------------------------------------------------
# Key derivation helpers
# ---------------------------------------------------------------------------

def derive_key(seed: bytes, index: int = 0):
    raw = (
        hashlib.sha256(seed[:32]).digest()
        if index == 0
        else hashlib.sha256(seed[:32] + bytes([index])).digest()
    )
    return pysodium.crypto_sign_seed_keypair(raw)


def public_key_cesr(pk: bytes) -> str:
    return coring.Verfer(raw=pk, code=MtrDex.Ed25519).qb64


def sign_and_encode(raw_bytes: bytes, sk: bytes) -> str:
    sig_raw = pysodium.crypto_sign_detached(raw_bytes, sk)
    return coring.Cigar(raw=sig_raw, code=MtrDex.Ed25519_Sig).qb64
