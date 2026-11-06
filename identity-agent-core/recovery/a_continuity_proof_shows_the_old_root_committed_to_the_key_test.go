package recovery

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"identity-agent-core/drivers"

	keri "github.com/grapeid/keri-go"
)

// forgedProof is a proof naming the old root that someone with no key of the
// old root builds: a rotation of it to a key the old root never committed to,
// sealing a new root's inception, and that new root's back-reference. Every
// event is well formed and every signature is true of its own event.
func (b *breakGlass) forgedProof(log []drivers.SignedEventBytes, priorSAID string) ContinuityProof {
	a := b.app
	t := b.t
	sn := len(log)
	if sn == 0 {
		sn = 1 // a proof carrying no log still names a rotation
	}
	icpRaw, err := keri.BuildInception(keri.InceptionInput{Keys: []string{a.pub(9)}, NextDigests: a.commits(10, 11),
		Isith: one, Nsith: one, Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	icp, _ := keri.ParseEvent(icpRaw)
	seal, _ := json.Marshal(BuildDelegationAnchorSeal(icp.SAID)[0])
	rotRaw, err := keri.BuildRotation(keri.RotationInput{Prefix: b.oldAID, Keys: []string{a.pub(11)}, PriorSAID: priorSAID,
		SN: sn, NextDigests: a.commits(10, 9), Isith: one, Nsith: one, Data: []json.RawMessage{seal}})
	if err != nil {
		t.Fatal(err)
	}
	rot, _ := keri.ParseEvent(rotRaw)
	back, _ := json.Marshal(BuildContinuityBackReferenceSeal(rot.SAID)[0])
	ixnRaw, err := keri.BuildInteraction(keri.InteractionInput{Prefix: icp.Identifier, PriorSAID: icp.SAID, SN: 1,
		Data: []json.RawMessage{back}})
	if err != nil {
		t.Fatal(err)
	}
	ixn, _ := keri.ParseEvent(ixnRaw)
	enc := base64.StdEncoding.EncodeToString
	return BuildContinuityProof(ContinuityProofInput{OldRootAID: b.oldAID, NewRootAID: icp.Identifier, NewInceptionSAID: icp.SAID,
		NewInceptionRawB64: enc(icpRaw), NewInceptionSignatures: []string{a.sign(9, icpRaw, true)},
		AuthorizationEventRawB64: enc(rotRaw), AuthorizationSignatures: []string{a.sign(11, rotRaw, true)}, AuthorizationEventSAID: rot.SAID,
		BackAnchorEventRawB64: enc(ixnRaw), BackAnchorSignatures: []string{a.sign(9, ixnRaw, false)}, BackAnchorEventSAID: ixn.SAID,
		OldRootLog: log, PriorKelTailSAID: priorSAID, RotatedAt: "2026-11-03T00:00:00Z"})
}

// A proof is only as good as the old root's log it carries: a rotation of the
// old root to a key the old root never committed to is refused, whether the
// proof carries no log, the old root's true log, or a log it made up.
func TestAForgedContinuityProofIsRefused(t *testing.T) {
	withRootAIDRotationEnabled(t, func() {
		b := aBreakGlassSetup(t)
		genuine := b.logOfSigned(b.oldAID)
		tail := b.tailSAID(b.oldAID)

		cases := map[string]ContinuityProof{
			"no log of the old root":                              b.forgedProof(nil, b.oldAID),
			"the old root's true log, a key it did not commit to": b.forgedProof(genuine, tail),
		}
		for name, p := range cases {
			if err := VerifyContinuityProof(p); err == nil {
				t.Errorf("%s: the forged proof for %s was verified", name, b.oldAID)
			}
		}

		// The same proof of a rotation the old root really made verifies, and
		// is refused once its tail is not the one the rotation follows, or once
		// the rotation's threshold is not met.
		res, err := RotateRootAID(b.signed(b.prepare()), b.commit, b.st, t.TempDir(), nil)
		if err != nil {
			t.Fatal(err)
		}
		good := res.ContinuityProof
		if err := VerifyContinuityProof(good); err != nil {
			t.Fatalf("the true proof: %v", err)
		}
		wrongTail := good
		wrongTail.PriorKelTailSAID = good.NewInceptionSAID
		if err := VerifyContinuityProof(wrongTail); err == nil {
			t.Error("a proof naming a tail the rotation does not follow was verified")
		}
		short := good
		short.OldRootLog = nil
		if err := VerifyContinuityProof(short); err == nil {
			t.Error("a proof that carries none of the old root's log was verified")
		}
		unsigned := good
		unsigned.AuthorizationSignatures = []string{b.app.sign(1, []byte("another event"), true)}
		if err := VerifyContinuityProof(unsigned); err == nil {
			t.Error("a rotation whose threshold is not met by true signatures was verified")
		}
	})
}

// logOfSigned is the log of aid as the proof carries it: each event's bytes
// with its signatures.
func (b *breakGlass) logOfSigned(aid string) []drivers.SignedEventBytes {
	var out []drivers.SignedEventBytes
	for _, rec := range b.st.events {
		if rec.AID == aid {
			out = append(out, drivers.SignedEventBytes{RawB64: rec.RawBytesB64, Sigs: rec.ControllerSignatures()})
		}
	}
	return out
}

// tailSAID is the digest of the last event of aid's log.
func (b *breakGlass) tailSAID(aid string) string {
	events := b.logOfSigned(aid)
	raw, _ := base64.StdEncoding.DecodeString(events[len(events)-1].RawB64)
	said, err := keri.ComputeSAID(raw)
	if err != nil {
		b.t.Fatal(err)
	}
	return said
}
