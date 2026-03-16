# KERI Implementation Phases

**Reference document** — tracks what is built, what is next, and what test proves each phase is correct.
Each phase has a corresponding interoperability test in `tests/` that proves the cryptographic math works with the real keripy library **before** production code is written.

---

## Phase 1 — CESR Signing ✓ COMPLETE

**What it proves:** Dart-signed Ed25519 signatures can be CESR-encoded using keripy and are accepted by the keripy verifier, byte-for-byte identical to keripy's native output.

**Interop test:** `tests/keri_interop_test.py` — 20/20 passing

### What was built
| Component | Change |
|---|---|
| Python driver | `POST /cesr-encode` (stateless) — wraps raw 64-byte sig in `coring.Cigar(code=MtrDex.Ed25519_Sig)` → `0B...` 88 chars |
| Python driver | `POST /inception` returns `raw_bytes_b64` — exact bytes Dart must sign |
| Python driver | `POST /verify` accepts both raw base64 and CESR `0B`-prefixed signatures |
| Go driver | `CesrEncode()` method; `DriverInceptionResponse.RawBytesB64` |
| Go server | `POST /api/cesr/encode` → `handleCesrEncode` |
| Go server | `InceptionResponse.RawBytesB64` |
| Dart | `InceptionResult.cesrSignature`, `InceptionResult.rawBytesB64` |
| Dart | `SignatureResult.cesrSignature` |
| Dart | `DesktopKeriService.inceptAid()` — signs event bytes locally, CESR-encodes |
| Dart | `DesktopKeriService.signPayload()` — CESR-encodes raw signature |
| Dart | `DesktopKeriService._cesrEncode()` helper |

### Remaining Phase 1 item
- `EventRecord` in `identity.db` does not yet store the CESR signature alongside the event body (to be done at start of Phase 2).

---

## Phase 2 — IXN Events + Key Rotation Signing

**What it proves:** Interaction events and key rotation events can be created, signed with the Dart local key, CESR-encoded, and verified by keripy.

**Interop test:** `tests/keri_phase2_interop_test.py`

### What to build
| Component | Change |
|---|---|
| Python driver | `POST /interact` — `eventing.interact()`, returns `raw_bytes_b64` |
| Python driver | `POST /rotation` updated — returns `raw_bytes_b64` |
| Go driver | `DriverInteractResponse`; `Interact()` method |
| Go driver | `DriverRotationResponse.RawBytesB64` |
| Go server | `POST /api/interact` route + `handleInteract` |
| Go server | Pass through `raw_bytes_b64` from rotation response |
| Dart | `InteractResult` class in `keri_service.dart` |
| Dart | `KeriService.interactAid()` abstract method |
| Dart | `DesktopKeriService.interactAid()` — sign locally, CESR-encode |
| Dart | `DesktopKeriService.rotateAid()` — sign rotation event locally, CESR-encode |
| Store | `EventRecord.Signature` field — persist CESR sig alongside all events |

### Key rotation note
Rotation is signed with the **pre-rotated** key (index 1 from the mnemonic). Dart derives it as `sha256(seed[:32] + [0x01])`. The Python driver must verify the new public key matches the digest committed in the inception event.

---

## Phase 3 — Real OOBI Resolution + KEL Validation

**What it proves:** An OOBI URL can be resolved (HTTP GET), the returned KEL can be parsed and cryptographically validated with keripy, and the result stored for contact verification.

**Interop test:** `tests/keri_phase3_interop_test.py`

### What to build
| Component | Change |
|---|---|
| Python driver | `POST /resolve-oobi` — HTTP GET the URL using `requests`, parse returned KEL with keripy |
| Python driver | Validate KEL hash chain and event signatures |
| SQLite | New `contact_kels` table — stores resolved KELs by AID |
| Go server | `POST /api/contacts/resolve` stores validated KEL after OOBI resolution |

---

## Phase 4 — ACDC Credential Issuance

**What it proves:** An ACDC credential can be formatted, its SAID computed, a KEL-anchored IXN seal created, and the seal signed — all producing output keripy accepts as a valid issued credential.

**Interop test:** `tests/keri_phase4_interop_test.py`

### What to build
| Component | Change |
|---|---|
| Python driver | `POST /credential/issue` — format ACDC, compute SAID, create IXN seal, return `raw_bytes_b64` for signing |
| Go server | `POST /api/credential/issue` — sign locally, CESR-encode, call interact to anchor |
| SQLite | `credential_registry` table — issued and held credentials (SAID + metadata) |
| Dart | `KeriService.issueCredential()` abstract method |

---

## Phase 5 — Credential Presentation

**What it proves:** A credential holder can package a verifiable presentation with proof of possession, signed with their current key, that a verifier can validate.

**Interop test:** `tests/keri_phase5_interop_test.py`

### What to build
| Component | Change |
|---|---|
| Python driver | `POST /credential/present` — package presentation, compute presentation SAID |
| Go server | `POST /api/credential/present` — sign locally |
| Dart | `KeriService.presentCredential()` abstract method |

---

## Phase 6 — Credential Verification (8 checks)

**What it proves:** All 8 verification checks from the SEDI grandpa scenario pass against a known-good credential + presentation.

**Interop test:** `tests/keri_phase6_interop_test.py`

### 8 Checks
1. ACDC SAID integrity — hash of content matches the embedded SAID
2. Issuer AID resolves via OOBI — issuer is reachable and authenticated
3. Issuer KEL valid and unrevoked — hash chain intact, no rotation after issuance
4. Schema SAID matches known/trusted schema
5. Credential not revoked in issuer's registry
6. Holder AID matches credential subject field
7. Presentation signature valid against holder's current public key
8. Holder KEL anchors the presentation — IXN event with seal exists in holder's KEL

### What to build
| Component | Change |
|---|---|
| Python driver | `POST /credential/verify` — implements all 8 checks |
| Go server | `POST /api/credential/verify` |
| Dart | `KeriService.verifyCredential()` abstract method |

---

## Phase 7 — KERL + Witness Receipts Storage

**What it proves:** Witness receipts can be stored and retrieved, and a threshold of witness receipts constitutes a valid KERL entry.

**Interop test:** `tests/keri_phase7_interop_test.py`

### What to build
| Component | Change |
|---|---|
| SQLite | `witness_receipts` table — stores receipts (AID, sn, event SAID, witness AID, CESR receipt sig) |
| Python driver | `POST /witness/receipt` — validate and store an incoming witness receipt |
| Go server | `POST /api/witness/receipt` |
| Go server | `GET /api/witness/receipts/{aid}` |

---

## Deferred (post-SEDI demo)

- DIDComm v2 messaging protocol
- Multi-sig / threshold signing
- Social recovery (requires contacts to exist)
- Grape ID watcher service public endpoint
- KERI delegation (parent ↔ child AID)
- Desktop UI parity with mobile dashboard

---

## SEDI Demo Priority (April 20, 2026)

| Phase | Required? |
|---|---|
| Phase 1 — CESR signing | ✓ Done |
| Phase 2 — IXN + rotation | ✓ Required |
| Phase 3 — OOBI resolution | ✓ Required |
| Phase 4 — Credential issuance | ✓ Required |
| Phase 5 — Credential presentation | ✓ Required |
| Phase 6 — Credential verification | ✓ Required |
| Phase 7 — Witness receipts | Partial (receipts storage, not full threshold) |
| Onboarding UI (paths A + B) | ✓ Required — see `docs/onboarding-wizard-design.md` |
