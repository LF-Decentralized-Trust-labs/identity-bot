# Real Android key attestation chains

Recorded from real phones and published by Google in
https://github.com/android/keyattestation (`testdata/`, Apache License 2.0,
fetched 2026-11-06). Each `.pem` is the attestation certificate chain of one
key, leaf first; the `.json` beside it is Google's own decoding of the leaf's
KeyDescription, which the tests compare this package's parser against.

| File | Phone | Android | Key held in |
|---|---|---|---|
| `blueline_sdk28_SB_RSA_NONE` | Pixel 3 | 9 (28) | StrongBox |
| `blueline_sdk28_TEE_RSA_NONE` | Pixel 3 | 9 (28) | TEE |
| `akita_sdk34_SB_RSA_NONE` | Pixel 8a | 14 (34) | StrongBox |
| `akita_sdk34_TEE_RSA_NONE` | Pixel 8a | 14 (34) | TEE |
| `akita_sdk34_TEE_RSA_NONE_USERAUTH` | Pixel 8a | 14 (34) | TEE, needs user authentication |

They are RSA signing keys requested with the challenge `challenge`, not the
seed-wrapping key, so they prove the chain and level checks and are refused by
the seed key policy (which wants a decrypt key). `google_roots_*.json` is
https://android.googleapis.com/attestation/root as read on the date shown.
