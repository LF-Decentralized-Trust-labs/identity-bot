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
)

// This machine's own log is what says whether its own owner is at stage two.
// An identity row with no events, or with only some, says nothing of the
// rotation to stage two, and must not be read as an identity still at stage
// one: a classical-only request by the stage-two key is refused.

func aClassicalOnlyRequestTo(t *testing.T, s *CoreServer, aid string, seed []byte) error {
	t.Helper()
	stamp := time.Now().UTC().Format(time.RFC3339)
	path := "/api/identity/x" + strconv.FormatInt(time.Now().UnixNano(), 10)
	req := httptest.NewRequest(http.MethodGet, path, strings.NewReader(""))
	sig, err := SignOwnerRequest(aid, http.MethodGet, path, stamp, nil, seed)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(headerOwnerSig, sig)
	req.Header.Set(headerOwnerTimestamp, stamp)
	req.Header.Set(headerOwnerFor, aid)
	req.Header.Set(headerBodyDigest, iacrypto.Blake3QB64Must(nil))
	return s.verifyOwnerSignature(req)
}

func TestAnIdentityWhoseLogStopsBeforeStageTwoIsNotTakenOnTheClassicalKeyAlone(t *testing.T) {
	s, aid, k, pq, pqKeys := aStageOneIdentity(t)
	_, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", aStageTwoRotationRequest(t, aid, k, pqKeys))
	rot := preparedBytes(t, out)
	if code, out := commit(t, s, rot, appSign(t, k[1], rot, true), pqSign(t, pq[0], rot, 1, 1)); code != http.StatusCreated {
		t.Fatalf("commit: %d %v", code, out)
	}
	if err := aClassicalOnlyRequestTo(t, s, aid, k[1]); err == nil {
		t.Fatal("precondition: classical alone should be refused on the whole log")
	}
	own, _ := s.DataStore.GetIdentity()
	events, _ := s.DataStore.GetEvents(aid)
	for _, keep := range []int{0, 1} {
		b := appHeldCore(t)
		if err := b.DataStore.SaveIdentity(*own); err != nil {
			t.Fatal(err)
		}
		for _, ev := range events[:keep] {
			if err := b.DataStore.SaveEvent(ev); err != nil {
				t.Fatal(err)
			}
		}
		if err := aClassicalOnlyRequestTo(t, b, aid, k[1]); err == nil {
			t.Errorf("an identity saved with %d of %d events took a classical-only request by its stage-two key", keep, len(events))
		}
	}
}
