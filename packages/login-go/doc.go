// Package login is what a relying party's Go back end uses to sign a person in
// through its Identity Agent: StartSession asks the Identity Agent for a
// sign-in on one of its assets, ConfirmSession asks who signed in. It is the Go
// half of startLoginSession and confirmLoginSession in
// @identity-agent/login-web/server, and the two are held to the same cases:
// packages/login-web/test-vectors/start-and-confirm.json.
//
// It is standard library only. A back end that is not Go uses the TypeScript
// package; a back end that is Go uses this one, and does not write its own.
package login
