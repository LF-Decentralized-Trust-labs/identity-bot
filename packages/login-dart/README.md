# login_dart

The Dart port of what an installed front end of a utility app checks before it
believes the app's back end, for every installed platform (iOS, Android, macOS,
Windows). A browser does not use it: its page is `login-web`.

- `lib/app_checks.dart` — the sign-in link, the relay identifier's key log, the
  challenge and every answer (`login-web/src/app.ts`), held to
  `../login-web/test-vectors/app-checks.json`.
- `lib/seal.dart` — sealed front-end traffic and the sealing key's vouching
  (`login-web/src/seal.ts`, `login-go/seal.go`), held to
  `../login-web/test-vectors/seal.json`, byte for byte.

- `lib/app_session.dart` — `AppSession`, the one place an installed front end signs
  in to its app's back end and makes every later call: signed by the front end's
  key, sealed for the back end, each answer believed only as the SDK believes it
  (`appFetch` and `appSession` in `login-web/src/app.ts`). Signing in is the Ask:
  `start`, `wait`, then the grant is kept in a `GrantStore` until it is ended.
- `lib/front_end_key.dart` — `FrontEndKey`: `HardwareFrontEndKey`, an installed
  front end's key in its device's secure hardware (the platform supplies a
  `HardwareKeyPlatform`: login-flutter); `InstalledFrontEndKey`, which an installed
  front end uses: the hardware's key where the app's owner accepts it, and a key held
  in software where the owner does not require a hardware key (ADR-072 Amendment 17,
  kept in a `KeyStore`); and `SoftwareFrontEndKey` for tests.
- `lib/apple_attest.dart` — the public key of an Apple App Attest attestation object (the
  device gives that key only as an identifier).
- `lib/installed_app.dart` — the evidence an installed front end's key is proved by
  and the start body that carries it, held to
  `../login-web/test-vectors/installed-app.json`, which `login-go` runs too.

Run the vectors with `dart test` in this folder. `tool/statements_under_dart2js.sh`
runs the sealing key's statement cases again as JavaScript (dart2js, then node),
where `1.0 is int` is true; run it when `checkSealKey` changes. A rule changes in the
vectors and in the Go and TypeScript together, never here alone.
