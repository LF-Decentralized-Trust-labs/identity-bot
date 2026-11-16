package witness

import (
	"encoding/json"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// After a recovery rotation replaces an interaction, a different interaction at
// that place signed by the key the owner rotated away from is not evidence of
// duplicity: it is not kept as a conflict, so it cannot make the witness refuse
// the owner's later claims.
func TestAnInteractionSignedByARotatedAwayKeyIsNotAConflict(t *testing.T) {
	s := witnessFor(t)
	id, icp, icpSig := newIdentity(t)
	witnessesFor(t, s, id.prefix)
	mustReceive(t, s, id.prefix, icp, icpSig)
	id.kept(icp)
	for sn := 1; sn <= 2; sn++ {
		raw, sig := id.interaction(sn, `{"i":"EA","s":"0","d":"EA"}`)
		mustReceive(t, s, id.prefix, raw, sig)
		id.kept(raw)
	}
	rot, rotSig := id.rotation(2, 1)
	mustReceive(t, s, id.prefix, rot, rotSig)
	id.kept(rot)

	late, err := keri.BuildInteraction(keri.InteractionInput{Prefix: id.prefix,
		PriorSAID: id.saids[1], SN: 2,
		Data: []json.RawMessage{json.RawMessage(`{"i":"EB","s":"0","d":"EB"}`)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReceiveSignedEvent(id.prefix, late,
		[]string{signAt(t, id.keys[0], late, keri.SamePlace(0))}); err == nil {
		t.Fatal("an interaction replaced by a rotation was taken")
	}
	if conflicts, _ := s.Store.GetKelConflicts(id.prefix); len(conflicts) != 0 {
		t.Fatalf("an interaction the rotation replaced was kept as evidence: %+v", conflicts)
	}
}
