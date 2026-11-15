# login_flutter

Sign in with Identity Agent for an **installed front end** of a utility app
(ADR-072): the sign-in screen (`UtilityAppSignInScreen`: the button, the code to
compare, the waiting state), the device's hardware key (`MethodChannelHardwareKey`) and
the grant kept across restarts (`SecureGrantStore`). It is a thin layer on
`../login-dart`, whose `AppSession` does everything that is believed, signed or sealed.
A browser front end uses `login-web` instead (a Flutter web build is loaded by that page).

Run the tests with `flutter test` in this folder. They run the screen against
`login-dart`'s fake utility app, so every answer is sealed and signed as a real one is.

## What runs where, and what has been tried

Every platform has its native code; **none of it has been compiled or run on a
device**, because none was available. The Dart half is tested (`flutter test`)
against a fake channel and the shared vectors; the native code is not.

| Platform | Where | Evidence the Identity Agent accepts | State |
|---|---|---|---|
| Android | `android/` | Android Key Attestation, a key made for the ask's challenge | Written, untested. Needs `compileSdk 34`, a real device (an emulator's keys are software) |
| iOS, macOS | `darwin/` | App Attest: the attestation for `SHA-256(challenge)`, and an assertion for each statement and **each call's proof** | Written, untested. App Attest does not run in a simulator |
| Windows | `windows/` | A TPM key certify by an attestation key, a `TPM2_ActivateCredential` result of the Identity Agent's credential, and the EK certificate | Written. The TPM commands (`tpm2.cpp`) run against a software TPM and are accepted by the Identity Agent's verifier (`windows/test/run.sh`); the Windows calls (TBS, DPAPI, the EK certificate fetch) compile with mingw-w64 and **have not run on Windows**. **No manufacturer root is pinned yet**, so no TPM key is accepted (`identity-agent-core/secureenclave/tpmroots/README.md`) |

An App Attest key signs only assertions, so on Apple the proof of each call is an
assertion over the SHA-256 of the proof text (`login-go`: `IsAssertionProof`,
`VerifyAppleAssertion`), not the plain 64-byte signature of the other platforms. A
back end that checks only plain proofs (identity-agent-addons `appserve`, `checkProof`)
must also take assertions before an Apple front end can call it: not done here, in
another repository.

Until the owner pins TPM manufacturers' roots (the Identity Agent refuses every TPM
key while none is) a Windows front end signs in as `browser`, as ADR-072 Amendment 2
accepts. A TPM's evidence takes one more call to the app's back end than the other
platforms': the front end sends its endorsement key and attestation key
(`/signin/installed-key/credential`) and opens the credential that comes back in its TPM;
`tpmEnrol` and `tpmAttest` are the channel's two calls for it.

What running `windows/test/run.sh` shows: the endorsement key `tpm2.cpp` makes is the standard EK
(the one a certificate certifies); a software TPM opens the Identity Agent's credential in
`TPM2_ActivateCredential` and refuses a tampered one; the evidence is accepted by
`VerifyTPMKeyCertify`; the key's signatures verify under the point it gave. What it does not
show: TBS, a real manufacturer's chain, DPAPI, the Windows call that fetches an EK certificate a
TPM does not carry, or a real Windows machine's rules for what a program may do with its TPM.
A TPM's EK certificate may need its issuers sent too (`ek_chain`); the front end sends none yet.
