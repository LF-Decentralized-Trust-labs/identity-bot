package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/store"
)

// An identity founded elsewhere — on a phone, by the local KERI engine — has to
// end up in the same position as one founded here: committing to messaging keys
// that come back from the recovery phrase. It got neither.
func TestAnIdentityFoundedElsewhereStillGetsItsMessagingKeys(t *testing.T) {
	// About what a machine founds, not about where founding is allowed.
	// These run on the machines the platform check refuses, so this
	// stands in for one that may found.
	aMachineThatMayFound(t)
	s := witnessWithSeed(t, 1)
	const aid = "EFoundedOnAPhone"

	body, _ := json.Marshal(store.IdentityState{AID: aid, PublicKey: "Dpub"})
	w := httptest.NewRecorder()
	s.handleStoreIdentity(w, httptest.NewRequest(http.MethodPost, "/api/store/identity",
		bytes.NewReader(body)))
	if w.Code != http.StatusCreated {
		t.Fatalf("storing the identity failed: %d %s", w.Code, w.Body.String())
	}
	if !s.hasKeySet(aid) {
		t.Fatal("an identity founded elsewhere has no messaging keys, so nothing can be " +
			"encrypted to it and a restore could never reproduce them")
	}
}

// The seal a caller is asked to put in the event it is about to build. Prepared
// before the identity exists, because the identifier is derived from an event
// that has to contain it.
func TestTheCommitmentIsPreparedBeforeTheIdentityExists(t *testing.T) {
	s := witnessWithSeed(t, 1)
	w := httptest.NewRecorder()
	s.handlePrepareMessagingKeys(w, ownerRequest(http.MethodPost, "/api/messaging-keys/prepare", nil, s))
	if w.Code != http.StatusOK {
		t.Fatalf("preparing the commitment failed: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Anchor map[string]interface{} `json:"anchor"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	// It must be readable by the same code that reads it out of a real event.
	event := map[string]interface{}{"a": []interface{}{out.Anchor}}
	if _, _, err := iacrypto.AnchoredAgreementKeys(event); err != nil {
		t.Fatalf("the prepared seal cannot be read back as a commitment: %v", err)
	}
	if _, _, err := iacrypto.AnchoredSigningKeys(event); err != nil {
		t.Fatalf("the prepared seal does not carry the signing keys: %v", err)
	}
}

// Asking twice must not strand the first set: a caller that retries would
// otherwise found an identity committing to keys the agent has replaced.
func TestPreparingTwiceYieldsTheSameCommitment(t *testing.T) {
	s := witnessWithSeed(t, 1)
	get := func() string {
		w := httptest.NewRecorder()
		s.handlePrepareMessagingKeys(w, ownerRequest(http.MethodPost, "/x", nil, s))
		if w.Code != http.StatusOK {
			t.Fatalf("prepare failed: %d %s", w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	if first, second := get(), get(); first != second {
		t.Fatal("asking twice produced different keys, so a retry would strand the first set")
	}
}

// The keys sealed into the event must be the keys the agent then holds, or the
// identity commits to something it cannot use.
func TestTheSealedKeysAreTheKeysTheAgentKeeps(t *testing.T) {
	// About what a machine founds, not about where founding is allowed.
	// These run on the machines the platform check refuses, so this
	// stands in for one that may found.
	aMachineThatMayFound(t)
	s := witnessWithSeed(t, 1)
	const aid = "EFoundedOnAPhone2"

	w := httptest.NewRecorder()
	s.handlePrepareMessagingKeys(w, ownerRequest(http.MethodPost, "/x", nil, s))
	var out struct {
		Anchor map[string]interface{} `json:"anchor"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	event := map[string]interface{}{"a": []interface{}{out.Anchor}}
	x, kem, err := iacrypto.AnchoredAgreementKeys(event)
	if err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(store.IdentityState{AID: aid, PublicKey: "Dpub"})
	rec := httptest.NewRecorder()
	s.handleStoreIdentity(rec, httptest.NewRequest(http.MethodPost, "/api/store/identity",
		bytes.NewReader(body)))

	ks, err := s.keySetFor(aid)
	if err != nil {
		t.Fatal(err)
	}
	did, err := ks.DID()
	if err != nil {
		t.Fatal(err)
	}
	if err := did.MatchesAnchoredKeys(x, kem); err != nil {
		t.Fatalf("the agent kept different keys from the ones it sealed: %v", err)
	}
}
