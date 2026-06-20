"""Stock keri 1.1.17 conformance checks for M63 hybrid icp events."""

from __future__ import annotations

import base64
import importlib.metadata
from typing import Any

from keri.core import serdering
from keri.kering import ICP_LABELS

REQUIRED_KERI_VERSION = "1.1.17"


def _assert_keri_version() -> None:
    installed = importlib.metadata.version("keri")
    if installed != REQUIRED_KERI_VERSION:
        raise ValueError(
            f"conformance gate requires keri=={REQUIRED_KERI_VERSION}, "
            f"got keri=={installed}"
        )


def verify_hybrid_icp_conformance(
    inception_event: dict[str, Any],
    raw_bytes_b64: str,
) -> None:
    """
    Assert icp parses and SAID/prefix verify under stock keri 1.1.17.

    Raises ValueError with a descriptive message on failure.
    """
    _assert_keri_version()

    extra = set(inception_event.keys()) - set(ICP_LABELS)
    if extra:
        raise ValueError(f"non-conformant top-level icp fields: {sorted(extra)}")

    missing = [label for label in ICP_LABELS if label not in inception_event]
    if missing:
        raise ValueError(f"missing required icp fields: {missing}")

    if list(inception_event.keys()) != ICP_LABELS:
        raise ValueError(
            f"icp field order must be {ICP_LABELS}, got {list(inception_event.keys())}"
        )

    if inception_event.get("t") != "icp":
        raise ValueError(f"expected t=icp, got {inception_event.get('t')!r}")

    raw = base64.b64decode(raw_bytes_b64, validate=True)
    try:
        serder = serdering.SerderKERI(raw=bytes(raw), verify=True)
    except Exception as exc:
        raise ValueError(
            f"SerderKERI(raw=..., verify=True) rejected event: {exc}"
        ) from exc

    if serder.said != inception_event.get("d"):
        raise ValueError("inception_event d does not match SerderKERI said")

    if serder.pre != inception_event.get("i"):
        raise ValueError("inception_event i does not match SerderKERI prefix")

    if serder.pre != serder.said:
        raise ValueError("Blake3_256 inceptive icp requires i == d")

    anchors = inception_event.get("a") or []
    if not anchors:
        raise ValueError("missing a anchor with IA-HYBRID-1 seal")
    seal = anchors[0]
    if seal.get("ia") != "IA-HYBRID-1":
        raise ValueError(f"expected ia=IA-HYBRID-1 in a[0], got {seal.get('ia')!r}")
    ka = seal.get("ka")
    if not isinstance(ka, list) or len(ka) != 2:
        raise ValueError("a[0].ka must be [X25519, ML-KEM-768]")

    k = inception_event.get("k") or []
    if len(k) != 2:
        raise ValueError("k must carry [Ed25519, ML-DSA-65] signing keys")

    n = inception_event.get("n") or []
    if len(n) != 2:
        raise ValueError("n must carry two signing-key pre-rotation digests (no na)")

    if "na" in inception_event:
        raise ValueError("na must not be present (KA keys are not pre-rotated)")