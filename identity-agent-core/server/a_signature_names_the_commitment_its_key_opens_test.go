//go:build kerigo_pqtest

package server

import (
	"crypto/ed25519"
	"net/http"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// A signature on a rotation counts only where its prior-next place names the
// commitment its key opens: the Ed25519 key opens place 0 of the commitment
// and the post-quantum key place 1. Either key naming the other's place is
// refused, and nothing is written, though both signatures verify.
func TestASignatureMustNameTheCommitmentItsKeyOpens(t *testing.T) {
	s, aid, k, pq, pqKeys := aStageOneIdentity(t)
	_, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", aStageTwoRotationRequest(t, aid, k, pqKeys))
	rot := preparedBytes(t, out)

	edAt := func(index, ondex int) string {
		q, err := keri.EncodeIndexedSignature(ed25519.Sign(ed25519.NewKeyFromSeed(k[1]), rot),
			keri.SignaturePlace{Index: index, Ondex: ondex})
		if err != nil {
			t.Fatal(err)
		}
		return q
	}
	refused := func(what string, sigs ...string) {
		t.Helper()
		if code, out := commit(t, s, rot, sigs...); code == http.StatusCreated || code == http.StatusAccepted {
			t.Fatalf("%s was taken: %d %v", what, code, out)
		}
		if own, _ := s.DataStore.GetIdentity(); own.EventCount != 1 {
			t.Fatalf("%s changed the log: %d events", what, own.EventCount)
		}
	}
	refused("an ML-DSA signature at index 1 naming prior-next 0", edAt(0, 0), pqSign(t, pq[0], rot, 1, 0))
	refused("an Ed25519 signature at index 0 naming prior-next 1", edAt(0, 1), pqSign(t, pq[0], rot, 1, 1))

	if code, out := commit(t, s, rot, edAt(0, 0), pqSign(t, pq[0], rot, 1, 1)); code != http.StatusCreated {
		t.Fatalf("the rotation with every place right: %d %v", code, out)
	}
}
