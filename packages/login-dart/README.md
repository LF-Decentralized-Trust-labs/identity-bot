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

Run the vectors with `dart test` in this folder. A rule changes in the
vectors and in the Go and TypeScript together, never here alone.
