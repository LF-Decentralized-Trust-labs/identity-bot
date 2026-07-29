package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"identity-agent-core/login"
	"identity-agent-core/sandbox"
)

// Signed-request-envelope authentication — the strongest caller proof at the
// endpoint. A caller signs THIS request (method + params + nonce + timestamp)
// with its identity key and presents the signature in request headers. The
// endpoint verifies it against the caller's key, rejects stale or replayed
// requests, and stamps CallerContext.EnvelopeVerified.
//
// It is additive: a request with no envelope headers is untouched
// (EnvelopeVerified stays false), so plain bearer-token callers keep working.
// Only capabilities flagged RequireSignedRequest demand it.

const (
	envSigHeader    = "X-IA-Signature"  // detached Ed25519 CESR "0B" signature
	envNonceHeader  = "X-IA-Nonce"      // unique per request
	envTSHeader     = "X-IA-Timestamp"  // unix seconds
	envSignerHeader = "X-IA-Signer-AID" // optional; defaults to the resolved caller AID
	envFreshness    = 5 * time.Minute   // accept window; also the replay-cache TTL
)

// verifyRequestEnvelope checks an optional signed-request envelope. It returns an
// error only when an envelope IS present but invalid (missing fields, bad
// signature, stale, or replayed) — a missing envelope is not an error. On success
// it sets caller.EnvelopeVerified and upgrades caller.AuthLevel.
func (s *CoreServer) verifyRequestEnvelope(r *http.Request, method string, params []byte, caller *sandbox.CallerContext) error {
	sig := r.Header.Get(envSigHeader)
	if sig == "" {
		return nil // no envelope — leave EnvelopeVerified=false
	}
	nonce := r.Header.Get(envNonceHeader)
	tsStr := r.Header.Get(envTSHeader)
	if nonce == "" || tsStr == "" {
		return fmt.Errorf("signed request missing nonce or timestamp")
	}
	tsSec, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return fmt.Errorf("signed request has an invalid timestamp")
	}
	skew := time.Since(time.Unix(tsSec, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > envFreshness {
		return fmt.Errorf("signed request timestamp outside the freshness window")
	}

	signerAID := r.Header.Get(envSignerHeader)
	if signerAID == "" {
		signerAID = caller.CallerAID
	}
	if signerAID == "" {
		return fmt.Errorf("signed request has no signer AID")
	}
	// The signer must BE the authenticated caller — a token cannot present another
	// AID's signature to borrow its identity.
	if caller.CallerAID != "" && signerAID != caller.CallerAID {
		return fmt.Errorf("signed request signer does not match the authenticated caller")
	}
	pubB64 := s.publicDidWebsPubKey(signerAID)
	if pubB64 == "" {
		return fmt.Errorf("signer key unavailable for %s", signerAID)
	}
	pub, err := base64.RawURLEncoding.DecodeString(pubB64)
	if err != nil {
		return fmt.Errorf("signer key decode failed")
	}

	// Anti-replay: reject a nonce already seen within the window (scoped per signer).
	if nonceSeen(signerAID + ":" + nonce) {
		return fmt.Errorf("signed request replay detected")
	}

	payload := canonicalRequestPayload(method, params, nonce, tsStr)
	ok, verr := login.VerifyDetachedSig(payload, sig, pub)
	if verr != nil || !ok {
		return fmt.Errorf("signed request signature invalid")
	}
	// Identity-first: a valid envelope proves control of signerAID. When the caller
	// had no other identity (no bearer token), the proven signer BECOMES the caller
	// AID — authentication by signature alone, no token required.
	if caller.CallerAID == "" {
		caller.CallerAID = signerAID
	}
	caller.EnvelopeVerified = true
	caller.AuthLevel = "signed_request"
	return nil
}

// canonicalRequestPayload is the exact string the caller signs: the method, a
// hash of the raw params bytes (never re-marshalled — order- and byte-exact),
// the nonce, and the timestamp, newline-joined.
func canonicalRequestPayload(method string, params []byte, nonce, ts string) string {
	ph := sha256.Sum256(params)
	return method + "\n" + hex.EncodeToString(ph[:]) + "\n" + nonce + "\n" + ts
}

// nonceGuard is the per-process anti-replay cache: sha256(nonce key) -> expiry.
// Package-level to match the existing pairwiseKeys pattern and avoid threading
// state through CoreServer; a single server process shares one endpoint.
var nonceGuard = struct {
	sync.Mutex
	m map[string]time.Time
}{m: map[string]time.Time{}}

// nonceSeen reports whether key was already presented within the freshness window
// and records it. Expired entries are evicted opportunistically so the map only
// ever holds roughly one freshness window of nonces.
func nonceSeen(key string) bool {
	nonceGuard.Lock()
	defer nonceGuard.Unlock()
	now := time.Now()
	for k, exp := range nonceGuard.m {
		if now.After(exp) {
			delete(nonceGuard.m, k)
		}
	}
	h := sha256.Sum256([]byte(key))
	hk := hex.EncodeToString(h[:])
	if exp, ok := nonceGuard.m[hk]; ok && now.Before(exp) {
		return true
	}
	nonceGuard.m[hk] = now.Add(envFreshness)
	return false
}
