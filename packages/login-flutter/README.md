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
| Windows | `windows/` | A TPM key certify, a `TPM2_ActivateCredential` result and the EK chain | **Cannot sign in yet**: the key, its public point and its signatures are written; `attestNewKey` refuses in words, because the Identity Agent has not built its half of the credential exchange (the `TPM2_MakeCredential` blob an app must activate) and pins no TPM maker's root, so evidence made now could not be accepted (`tpm_key_certify.go`) |

An App Attest key signs only assertions, so on Apple the proof of each call is an
assertion over the SHA-256 of the proof text (`login-go`: `IsAssertionProof`,
`VerifyAppleAssertion`), not the plain 64-byte signature of the other platforms. A
back end that checks only plain proofs (identity-agent-addons `appserve`, `checkProof`)
must also take assertions before an Apple front end can call it: not done here, in
another repository.

Until Windows evidence exists a Windows front end cannot sign in as an installed app,
so this capability is not done for it. It is the one remaining gap, and it is the
Identity Agent's to close first.
