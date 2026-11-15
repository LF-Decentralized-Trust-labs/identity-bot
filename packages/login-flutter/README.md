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

Every platform has its native code. What has been **compiled**, and what has only been **written**:

| Half | Compiled? | How |
|---|---|---|
| Dart (all platforms) | Yes, and tested | `flutter test` here and in `../login-dart`, against a fake channel and the shared vectors |
| Android Kotlin (`android/src`) | Yes, on Linux; never run | `android/compilecheck/compile.sh` (Gradle `compileDebugKotlin` against the Android SDK and Flutter's embedding, no Flutter app around it). A real call that does not exist (the plugin once called `HardwareKey.sign`, which is `signCall`) fails it |
| Windows TPM commands (`windows/tpm2.cpp`) | Yes, and run against a software TPM | `windows/test/run.sh`: the endorsement key is the standard one, the software TPM opens the Identity Agent's credential and refuses a tampered one, and the Identity Agent's verifier accepts the evidence |
| Windows TBS, DPAPI and EK-certificate calls (`windows/tpm_key.cpp`, with `tpm2.cpp`) | Yes, with mingw-w64 (syntax and types); never run on Windows | `x86_64-w64-mingw32-g++ -std=c++17 -fsyntax-only` |
| Windows plugin glue (`windows/login_flutter_plugin.cpp`) | **No: written only.** It needs Flutter's Windows C++ wrapper headers, which are not here | |
| Swift (`darwin/`, iOS and macOS) | **No: written only.** Swift cannot be built on Linux | Needs a Mac and Xcode; App Attest does not run in a simulator |

Nothing has run on a device or a real TPM. Android needs a real device (an emulator's keys are software).

| Platform | Where | Evidence the Identity Agent accepts |
|---|---|---|
| Android | `android/` | Android Key Attestation, a key made for the ask's challenge |
| iOS, macOS | `darwin/` | App Attest: the attestation for `SHA-256(challenge)`, and an assertion for each statement and **each call's proof** |
| Windows | `windows/` | A TPM key certify by an attestation key, a `TPM2_ActivateCredential` result of the Identity Agent's credential, and the EK certificate. Only a **physical TPM chip** counts: a virtual or cloud TPM is refused. Microsoft's trusted TPM root list is pinned for physical chips (`identity-agent-core/secureenclave/tpmroots/README.md`) |

**A limit a person will meet:** a Windows PC whose TPM is an STMicroelectronics chip cannot sign in yet, because six of that maker's issuer certificates cannot be read and are not pinned. Such a PC can sign in from a phone.

An App Attest key signs only assertions, so on Apple the proof of each call is an
assertion over the SHA-256 of the proof text (`login-go`: `IsAssertionProof`,
`VerifyAppleAssertion`), not the plain 64-byte signature of the other platforms. A
back end that checks only plain proofs (identity-agent-addons `appserve`, `checkProof`)
must also take assertions before an Apple front end can call it: not done here, in
another repository.

A Windows front end signs in as an installed app, with its TPM key, where the owner has accepted `tpm_keys` for the app (ADR-072 Amendment 7). Its evidence takes one more call to the app's back end than the other
platforms': the front end sends its endorsement key and attestation key
(`/signin/installed-key/credential`) and opens the credential that comes back in its TPM;
`tpmEnrol` and `tpmAttest` are the channel's two calls for it.

What running `windows/test/run.sh` shows: the endorsement key `tpm2.cpp` makes is the standard EK
(the one a certificate certifies); a software TPM opens the Identity Agent's credential in
`TPM2_ActivateCredential` and refuses a tampered one; the evidence is accepted by
`VerifyTPMKeyCertify`; the key's signatures verify under the point it gave. What it does not
show: TBS, a real manufacturer's chain, DPAPI, the Windows call that fetches an EK certificate a
TPM does not carry, or a real Windows machine's rules for what a program may do with its TPM.
The Identity Agent holds the issuers of the pinned list itself, so the front end sends none (`ek_chain` is empty).
