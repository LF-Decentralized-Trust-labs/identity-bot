# login_flutter

Sign in with Identity Agent for an **installed front end** of a utility app
(ADR-072): the sign-in screen (`UtilityAppSignInScreen`: the button, the code to
compare, the waiting state), the device's hardware key (`MethodChannelHardwareKey`) and
the grant kept across restarts (`SecureGrantStore`). It is a thin layer on
`../login-dart`, whose `AppSession` does everything that is believed, signed or sealed.
A browser front end uses `login-web` instead (a Flutter web build is loaded by that page).

Run the tests with `flutter test` in this folder. They run the screen against
`login-dart`'s fake utility app, so every answer is sealed and signed as a real one is.

## Not built, and why this is not complete

The Identity Agent accepts an installed app's key only with its platform's hardware
evidence (`InstalledAppKeyProof`). Written and **not run on any device**:

- **Android**: `android/` (Keystore key with attestation for the ask's challenge).
- **Apple (iOS and macOS)**: **not written.** App Attest: `DCAppAttestService`
  `generateKey`, `attestKey` with the ask's challenge hash, and `generateAssertion`
  over the statement digest. Open point to settle on a device first: an App Attest
  key signs only assertions, not the plain ECDSA each later call's proof is checked
  as, so how the back end checks later proofs from an Apple key is not yet decided.
- **Windows**: **not written.** A TPM key certify, in the JSON document
  `secureenclave.VerifyTPMKeyCertify` reads, through NCrypt.

Until Apple and Windows exist, a front end on those platforms cannot sign in as an
installed app (`MethodChannelHardwareKey` throws on any other platform's channel),
so this must not be taken as done for them (ADR rules: a fix lands on every
platform or not at all).
