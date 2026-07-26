package server

import (
	"crypto/subtle"
	"fmt"

	"identity-agent-core/iacrypto"
)

// Consent must bind to the document that actually executes.
//
// Decode and execute each fetch the Ask over HTTP independently. Nothing
// carried the approved bytes forward, so an originator could serve one Ask at
// decode time — "Join Acme as Intern", no disclosures requested — and a
// different one at execute time — "Join Acme as Admin", credentials and score
// requested. Both are validly signed by the same minter, so the signature
// check passes on each. The user consents to one document and a different one
// runs.
//
// The fix is to digest the previewed bytes, return that digest with the
// preview, and require the client to echo it on execute. The agent then
// refuses when the bytes it is about to execute are not the bytes the user
// approved.
//
// The threat here is the ORIGINATOR serving different bytes, not the user's
// own UI lying to itself — so a client-echoed digest is sufficient and needs
// no server-side session state.

// askDigest returns the Blake3 digest of the exact Ask bytes, in CESR qb64.
func askDigest(askBytes []byte) string {
	return iacrypto.Blake3QB64Must(askBytes)
}

// bindConsent refuses execution unless the Ask about to run is byte-identical
// to the one the user approved.
func bindConsent(approvedDigest string, askBytes []byte) error {
	if approvedDigest == "" {
		return fmt.Errorf(
			"consent not bound: ask_digest is required on execute — send back the " +
				"ask_digest returned by /api/scan/decode so the agent can prove it is " +
				"acting on the request you approved")
	}
	actual := askDigest(askBytes)
	if subtle.ConstantTimeCompare([]byte(approvedDigest), []byte(actual)) != 1 {
		return fmt.Errorf(
			"consent does not match: the request served now differs from the one you "+
				"approved (approved %s, served %s). Refusing to execute — scan again and "+
				"review the new request", short(approvedDigest), short(actual))
	}
	return nil
}

func short(d string) string {
	if len(d) > 12 {
		return d[:12] + "…"
	}
	return d
}
