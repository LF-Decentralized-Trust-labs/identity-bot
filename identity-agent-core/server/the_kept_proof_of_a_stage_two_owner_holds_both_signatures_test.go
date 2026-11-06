//go:build kerigo_pqtest

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/keymath"
	"identity-agent-core/login"
)

// What is kept of a request an owner at stage two authorised holds both of its
// signatures, so the record verifies under both keys (ADR-061 section 6).
func TestTheKeptProofOfAStageTwoOwnerHoldsBothSignaturesAndVerifies(t *testing.T) {
	s, aid, k, pq, pqKeys := aStageOneIdentity(t)
	_, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", aStageTwoRotationRequest(t, aid, k, pqKeys))
	rot := preparedBytes(t, out)
	if code, out := commit(t, s, rot, appSign(t, k[1], rot, true), pqSign(t, pq[0], rot, 1, 1)); code != http.StatusCreated {
		t.Fatalf("commit the stage-two rotation: %d %v", code, out)
	}

	body := []byte(`{"label":"x"}`)
	stamp := time.Now().UTC().Format(time.RFC3339)
	path := "/api/controllers"
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
	sig, err := SignOwnerRequest(aid, http.MethodPost, path, stamp, body, k[1])
	if err != nil {
		t.Fatal(err)
	}
	message := canonicalOwnerRequest(aid, http.MethodPost, path, stamp, body)
	raw, err := keymath.SignMLDSA65(pq[0], []byte(message))
	if err != nil {
		t.Fatal(err)
	}
	pqSig, err := keymath.EncodeMLDSA65CurrentOnlySignature(raw, 1)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(headerOwnerSig, sig)
	req.Header.Set(headerOwnerSigPostQuantum, pqSig)
	req.Header.Set(headerOwnerTimestamp, stamp)
	req.Header.Set(headerOwnerFor, aid)
	req.Header.Set(headerBodyDigest, iacrypto.Blake3QB64Must(body))

	by, release, err := s.authorityOf(req)
	release()
	if err != nil {
		t.Fatal(err)
	}
	kept := by.Request
	if kept == nil || kept.Signature != sig || kept.SignaturePostQuantum != pqSig {
		t.Fatalf("the kept request does not hold both signatures: %+v", kept)
	}
	pub, _ := login.DecodeVerkey(verkeyOf(k[1]))
	if ok, err := login.VerifyString(kept.Signed, kept.Signature, pub); err != nil || !ok {
		t.Fatalf("the kept classical signature does not verify: %v", err)
	}
	if err := thePostQuantumSignatureOver(kept.SignaturePostQuantum, pqKeys[0].Verkey, 1, kept.Signed); err != nil {
		t.Fatalf("the kept post-quantum signature does not verify: %v", err)
	}

	// Checked as the issuer checks a request it kept: one without the second
	// signature is not the stage-two owner's.
	bare := coretypes.Authority{Request: &coretypes.SignedRequest{Kind: "owner", Signature: kept.Signature, Signed: kept.Signed, Body: string(body)}}
	if err := s.checkAuthorisationOf(nil, aid, "", "", bare); err == nil || !strings.Contains(err.Error(), "stage two") {
		t.Fatalf("a kept request with the classical signature alone: %v", err)
	}
	if err := s.checkAuthorisationOf(nil, aid, "", "", by); err != nil && strings.Contains(err.Error(), "stage two") {
		t.Fatalf("a kept request with both signatures was refused for want of the second: %v", err)
	}
}
