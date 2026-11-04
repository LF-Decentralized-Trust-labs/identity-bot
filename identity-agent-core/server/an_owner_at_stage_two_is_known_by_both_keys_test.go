//go:build kerigo_pqtest

package server

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/keymath"
)

// An owner at stage two signs a request with both keys: the classical signature
// alone is refused, and so is a post-quantum one that is another key's or is not
// at place 1. With both, the request is the owner's.
func TestAnOwnerAtStageTwoSignsARequestWithBothKeys(t *testing.T) {
	s, aid, k, pq, pqKeys := aStageOneIdentity(t)
	_, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", aStageTwoRotationRequest(t, aid, k, pqKeys))
	rot := preparedBytes(t, out)
	if code, out := commit(t, s, rot, appSign(t, k[1], rot, true), pqSign(t, pq[0], rot, 1, 1)); code != http.StatusCreated {
		t.Fatalf("commit the stage-two rotation: %d %v", code, out)
	}

	request := func(pqSig func(message string) string) error {
		stamp := time.Now().UTC().Format(time.RFC3339)
		path := "/api/identity/" + strconv.FormatInt(time.Now().UnixNano(), 10)
		req := httptest.NewRequest(http.MethodGet, path, strings.NewReader(""))
		sig, err := SignOwnerRequest(aid, http.MethodGet, path, stamp, nil, k[1])
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(headerOwnerSig, sig)
		req.Header.Set(headerOwnerTimestamp, stamp)
		req.Header.Set(headerOwnerFor, aid)
		req.Header.Set(headerBodyDigest, iacrypto.Blake3QB64Must(nil))
		if pqSig != nil {
			req.Header.Set(headerOwnerSigPostQuantum, pqSig(canonicalOwnerRequest(aid, http.MethodGet, path, stamp, nil)))
		}
		return s.verifyOwnerSignature(req)
	}
	pqAt := func(seed []byte, index int) func(string) string {
		return func(message string) string {
			sig, err := keymath.SignMLDSA65(seed, []byte(message))
			if err != nil {
				t.Fatal(err)
			}
			q, err := keymath.EncodeMLDSA65CurrentOnlySignature(sig, index)
			if err != nil {
				t.Fatal(err)
			}
			return q
		}
	}

	if err := request(nil); err == nil || !strings.Contains(err.Error(), "stage two") {
		t.Fatalf("the classical signature alone: %v", err)
	}
	if err := request(pqAt(pq[1], 1)); err == nil {
		t.Fatal("another post-quantum key's signature was taken")
	}
	if err := request(pqAt(pq[0], 0)); err == nil {
		t.Fatal("a post-quantum signature at place 0 was taken")
	}
	if err := request(pqAt(pq[0], 1)); err != nil {
		t.Fatalf("both keys' signatures were refused: %v", err)
	}
}

// An owner at stage one is unchanged: the classical signature is enough.
func TestAnOwnerAtStageOneNeedsOnlyTheClassicalSignature(t *testing.T) {
	s, aid, k, _, _ := aStageOneIdentity(t)
	stamp := time.Now().UTC().Format(time.RFC3339)
	path := "/api/identity/" + strconv.FormatInt(time.Now().UnixNano(), 10)
	req := httptest.NewRequest(http.MethodGet, path, strings.NewReader(""))
	sig, _ := SignOwnerRequest(aid, http.MethodGet, path, stamp, nil, k[0])
	req.Header.Set(headerOwnerSig, sig)
	req.Header.Set(headerOwnerTimestamp, stamp)
	req.Header.Set(headerOwnerFor, aid)
	req.Header.Set(headerBodyDigest, iacrypto.Blake3QB64Must(nil))
	if err := s.verifyOwnerSignature(req); err != nil {
		t.Fatalf("a stage-one owner's request: %v", err)
	}
}
