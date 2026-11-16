package witness

import (
	"context"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// An event that states no digest has no identifier a receipt or a count can be
// kept under, so a witness takes none and an agent broadcasts none, and neither
// says anything about it but why.
func TestAnEventThatStatesNoDigestIsNeitherTakenNorBroadcast(t *testing.T) {
	s := witnessFor(t)
	id, icp, icpSig := newIdentity(t)
	witnessesFor(t, s, id.prefix)
	// The same inception with its digest field renamed, and signed over those
	// bytes by the identity's own key, so the only thing wrong with it is that.
	noD := strings.Replace(string(icp), `"d":"`, `"x":"`, 1)
	if noD == string(icp) {
		t.Fatal("the inception does not state its digest where this test removes it")
	}
	icpSig = signAt(t, id.keys[0], []byte(noD), keri.SamePlace(0))

	if _, err := s.ReceiveSignedEvent(id.prefix, []byte(noD), []string{icpSig}); err == nil {
		t.Fatal("an event that states no digest was taken")
	} else {
		t.Logf("receive: %v", err)
	}
	if kel, _ := s.Store.GetKelEvents(id.prefix); len(kel) != 0 {
		t.Fatalf("an event that states no digest was kept: %d held", len(kel))
	}
	err := s.BroadcastEvent(context.Background(), id.prefix, []byte(noD), icpSig)
	if err == nil || !strings.Contains(err.Error(), "no digest") {
		t.Fatalf("an event that states no digest was broadcast, or refused for another reason: %v", err)
	}
	err = s.BroadcastToDesignated(context.Background(), id.prefix, []byte(noD), []string{icpSig}, nil, 1)
	if err == nil || !strings.Contains(err.Error(), "no digest") {
		t.Fatalf("an event that states no digest was broadcast to designated witnesses, or refused for another reason: %v", err)
	}
}
