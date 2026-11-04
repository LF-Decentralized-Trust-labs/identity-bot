package recovery

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/keriengine"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// A break-glass rotation stopped part way is finished by sending the same
// request again; it supersedes what the holder of the stolen key signed; and
// the proof it leaves can be checked from what it carries.

// stopsAt is a store that fails one write once, as a disk or a database does.
type stopsAt struct {
	*memNotifyStore
	identityOf string // the SaveIdentity of this AID fails once
	task       bool   // the first SaveTask fails once
}

func (s *stopsAt) SaveIdentity(id store.IdentityState) error {
	if s.identityOf != "" && id.AID == s.identityOf {
		s.identityOf = ""
		return fmt.Errorf("disk full")
	}
	return s.memNotifyStore.SaveIdentity(id)
}

// SaveTask replaces a task of the same id, as the real store does.
func (s *stopsAt) SaveTask(t store.TaskRecord) error {
	if s.task {
		s.task = false
		return fmt.Errorf("database busy")
	}
	for i := range s.tasks {
		if s.tasks[i].ID == t.ID {
			s.tasks[i] = t
			return nil
		}
	}
	s.tasks = append(s.tasks, t)
	return nil
}

func (b *breakGlass) withAWitnessToTell() {
	b.st.contacts = append(b.st.contacts, store.ContactRecord{AID: "EW1", Alias: "Witness", IsWitness: true,
		Status: "accepted", OobiURL: "http://w1/oobi"})
}

// finished is what a rotation that ran without stopping leaves, whichever way
// this one got there.
func (b *breakGlass) finished(p *PreparedRootAIDRotation, dir string, res *RootAIDRotationResult) {
	b.t.Helper()
	newAID := p.NewRootFounding.Hint.I
	for label, aid := range map[string]string{"old": b.oldAID, "new": newAID} {
		if _, err := keri.ValidateSignedKEL(b.logOf(aid)); err != nil {
			b.t.Fatalf("the %s root's log does not verify: %v", label, err)
		}
		if n := len(b.logOf(aid)); n != 2 {
			b.t.Fatalf("the %s root's log is %d events, want 2", label, n)
		}
	}
	if b.st.identity.AID != newAID || b.st.identity.EventCount != 1 {
		b.t.Fatalf("identity record %+v", b.st.identity)
	}
	if len(b.st.tasks) != 1 {
		b.t.Fatalf("%d notification tasks, want 1", len(b.st.tasks))
	}
	got, err := ContinuityProofOfTask(b.st.tasks[0])
	if err != nil || got.AuthorizationEventSAID != p.OldRootRotation.Hint.D {
		b.t.Fatalf("the task does not carry the proof: %v", err)
	}
	if err := VerifyContinuityProof(got); err != nil {
		b.t.Fatalf("the proof in the task does not verify: %v", err)
	}
	m, err := LoadRootAIDMap(dir)
	if err != nil || len(m.Entries) != 1 || m.Entries[0].NewRootAID != newAID {
		b.t.Fatalf("root map %+v %v", m, err)
	}
	if res == nil || res.NewRootAID != newAID || res.NotificationsSent != 1 {
		b.t.Fatalf("answer %+v", res)
	}
}

// (a) Stopped after the old root's rotation was added and before the identity
// record moved.
func TestBreakGlassStoppedBeforeTheIdentityMovesIsFinishedByAResend(t *testing.T) {
	withRootAIDRotationEnabled(t, func() {
		b := aBreakGlassSetup(t)
		b.withAWitnessToTell()
		p := b.prepare()
		req, dir := b.signed(p), t.TempDir()
		st := &stopsAt{memNotifyStore: b.st, identityOf: p.NewRootFounding.Hint.I}

		if _, err := RotateRootAID(req, b.commit, st, dir, nil); err == nil {
			t.Fatal("the stop was not reported")
		}
		if n := len(b.logOf(b.oldAID)); n != 2 || b.st.identity.AID != b.oldAID {
			t.Fatalf("expected to stop with the rotation added and the identity not moved: %d events, %s", n, b.st.identity.AID)
		}
		res, err := RotateRootAID(req, b.commit, st, dir, nil)
		if err != nil {
			t.Fatalf("the resend: %v", err)
		}
		b.finished(p, dir, res)
	})
}

// (b) Stopped on the interaction, after the identity record moved.
func TestBreakGlassStoppedOnTheInteractionIsFinishedByAResend(t *testing.T) {
	withRootAIDRotationEnabled(t, func() {
		b := aBreakGlassSetup(t)
		b.withAWitnessToTell()
		p := b.prepare()
		req, dir := b.signed(p), t.TempDir()
		stop := true
		commit := func(raw []byte, sigs []string) error {
			if ev, _ := keri.ParseEvent(raw); stop && ev.Ilk == "ixn" {
				stop = false
				return fmt.Errorf("connection lost")
			}
			return b.commit(raw, sigs)
		}
		if _, err := RotateRootAID(req, commit, b.st, dir, nil); err == nil {
			t.Fatal("the stop was not reported")
		}
		if b.st.identity.AID != p.NewRootFounding.Hint.I || len(b.logOf(p.NewRootFounding.Hint.I)) != 1 {
			t.Fatal("expected to stop with the identity moved and the interaction not added")
		}
		res, err := RotateRootAID(req, commit, b.st, dir, nil)
		if err != nil {
			t.Fatalf("the resend: %v", err)
		}
		b.finished(p, dir, res)
	})
}

// (c) Stopped after all three events were added, queuing the notifications or
// writing the root map entry: the caller was told it failed.
func TestBreakGlassStoppedAfterTheThreeEventsIsFinishedByAResend(t *testing.T) {
	for _, which := range []string{"queuing the notification tasks", "writing the root map entry"} {
		t.Run(which, func(t *testing.T) {
			withRootAIDRotationEnabled(t, func() {
				b := aBreakGlassSetup(t)
				b.withAWitnessToTell()
				p := b.prepare()
				req, dir := b.signed(p), t.TempDir()
				st := &stopsAt{memNotifyStore: b.st}
				if which == "queuing the notification tasks" {
					st.task = true
				} else {
					// A directory where the file goes: reading and writing it fail.
					if err := os.Mkdir(filepath.Join(dir, rootAIDMapFileName), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := RotateRootAID(req, b.commit, st, dir, nil); err == nil {
					t.Fatal("the stop was not reported")
				}
				if len(b.logOf(p.NewRootFounding.Hint.I)) != 2 {
					t.Fatal("expected to stop with all three events added")
				}
				if which != "queuing the notification tasks" {
					if err := os.Remove(filepath.Join(dir, rootAIDMapFileName)); err != nil {
						t.Fatal(err)
					}
				}
				res, err := RotateRootAID(req, b.commit, st, dir, nil)
				if err != nil {
					t.Fatalf("the resend: %v", err)
				}
				b.finished(p, dir, res)

				// And once more, with nothing left to do, nothing is added.
				again, err := RotateRootAID(req, b.commit, st, dir, nil)
				if err != nil {
					t.Fatalf("a repeat of a finished rotation: %v", err)
				}
				b.finished(p, dir, again)
				if again.ContinuityProof.RotatedAt != res.ContinuityProof.RotatedAt {
					t.Fatal("a repeat records another time for the rotation")
				}
			})
		})
	}
}

// A request that is not the one that moved the identity does not finish by it.
func TestBreakGlassAnotherFoundingIsNotTakenForTheOneThatWasMoved(t *testing.T) {
	withRootAIDRotationEnabled(t, func() {
		b := aBreakGlassSetup(t)
		p := b.prepare()
		req, dir := b.signed(p), t.TempDir()
		if _, err := RotateRootAID(req, b.commit, b.st, dir, nil); err != nil {
			t.Fatal(err)
		}
		// The old root's rotation swapped for one that is not in its log.
		req2 := b.signed(p)
		req2.OldRootRotation = drivers.SignedEventBytes{RawB64: base64.StdEncoding.EncodeToString(raw(t, p.NewRootInteraction)),
			Sigs: req.OldRootRotation.Sigs}
		if _, err := RotateRootAID(req2, b.commit, b.st, dir, nil); err == nil {
			t.Fatal("a request whose rotation is not the one in the log was taken")
		}
	})
}

// a thief is a holder of the stolen current key: it signs interactions.
func (b *breakGlass) thiefAnchors(label string) string {
	b.t.Helper()
	kel, err := b.e.GetKel(b.oldAID)
	if err != nil {
		b.t.Fatal(err)
	}
	rawTip, _ := base64.StdEncoding.DecodeString(kel.RawEventsB64[len(kel.RawEventsB64)-1])
	tipEv, _ := keri.ParseEvent(rawTip)
	p, err := b.e.Prepare(keriengine.PrepareRequest{Name: b.oldAID, Ilk: "ixn",
		Anchors: []json.RawMessage{json.RawMessage(`{"d":"` + label + `"}`)},
		After:   &keriengine.Place{SN: int(tipEv.SN), SAID: tipEv.SAID}})
	if err != nil {
		b.t.Fatal(err)
	}
	if err := b.commit(p.Raw, []string{b.app.sign(0, p.Raw, false)}); err != nil {
		b.t.Fatal(err)
	}
	return p.Hint.D
}

func (b *breakGlass) prepareAfter(s, d string) *PreparedRootAIDRotation {
	var req PrepareRootAIDRotationRequest
	req.NewRoot.K, req.NewRoot.N = []string{b.app.pub(4)}, b.app.commits(5, 9)
	req.OldRoot.K, req.OldRoot.N = []string{b.app.pub(1)}, b.app.commits(2, 10)
	req.OldRoot.After.S, req.OldRoot.After.D = s, d
	p, err := PrepareRootAIDRotation(req, b.founding(), b.e, b.st)
	if err != nil {
		b.t.Fatal(err)
	}
	return p
}

func (b *breakGlass) oldLogSAIDs() []string {
	var out []string
	for _, ev := range b.st.events {
		if ev.AID == b.oldAID {
			var ked struct {
				D string `json:"d"`
			}
			_ = json.Unmarshal([]byte(ev.EventJSON), &ked)
			out = append(out, ked.D)
		}
	}
	return out
}

// An interaction the stolen key signed after the last establishment event is
// superseded by the rotation, and the break-glass completes. The sealed tail
// is the rotation's.
func TestBreakGlassSupersedesWhatTheThiefSigned(t *testing.T) {
	withRootAIDRotationEnabled(t, func() {
		b := aBreakGlassSetup(t)
		thief := b.thiefAnchors("EThiefAnchorOne000000000000000000000000000")
		if n := len(b.logOf(b.oldAID)); n != 2 {
			t.Fatalf("the thief's interaction was not added: %d", n)
		}
		p := b.prepareAfter("0", b.oldAID)
		res, err := RotateRootAID(b.signed(p), b.commit, b.st, t.TempDir(), nil)
		if err != nil {
			t.Fatalf("the thief's interaction blocked the break-glass: %v", err)
		}
		saids := b.oldLogSAIDs()
		if len(saids) != 2 || saids[1] != p.OldRootRotation.Hint.D || saids[1] == thief {
			t.Fatalf("the old root's log is %v: the thief's %s was not superseded", saids, thief)
		}
		if _, err := keri.ValidateSignedKEL(b.logOf(b.oldAID)); err != nil {
			t.Fatal(err)
		}
		if res.ContinuityProof.PriorKelTailSAID != b.oldAID || res.ContinuityProof.BackAnchorEventSAID != p.NewRootInteraction.Hint.D {
			t.Fatalf("proof %+v", res.ContinuityProof)
		}
		// The new root's interaction seals the rotation, not what it superseded.
		var ixn struct {
			A []struct {
				D string `json:"d"`
			} `json:"a"`
		}
		_ = json.Unmarshal(raw(t, p.NewRootInteraction), &ixn)
		if len(ixn.A) != 1 || ixn.A[0].D != p.OldRootRotation.Hint.D {
			t.Fatalf("the interaction seals %+v, want the rotation %s", ixn.A, p.OldRootRotation.Hint.D)
		}
	})
}

// A thief who keeps adding interactions, before and after the rotation was
// prepared, cannot block it; one the owner kept stays.
func TestBreakGlassKeepsWhatTheOwnerKeptAndCannotBeBlockedByAThief(t *testing.T) {
	withRootAIDRotationEnabled(t, func() {
		b := aBreakGlassSetup(t)
		kept := b.thiefAnchors("EOwnersOwnAnchor00000000000000000000000000")
		b.thiefAnchors("EThiefAnchorTwo000000000000000000000000000")
		p := b.prepareAfter("1", kept)
		// And again after the app prepared and signed, before it is sent.
		b.thiefAnchors("EThiefAnchorThree0000000000000000000000000")
		req := b.signed(p)
		if _, err := RotateRootAID(req, b.commit, b.st, t.TempDir(), nil); err != nil {
			t.Fatalf("a thief blocked the break-glass: %v", err)
		}
		saids := b.oldLogSAIDs()
		if len(saids) != 3 || saids[1] != kept || saids[2] != p.OldRootRotation.Hint.D {
			t.Fatalf("the old root's log is %v", saids)
		}
		if _, err := keri.ValidateSignedKEL(b.logOf(b.oldAID)); err != nil {
			t.Fatal(err)
		}
	})
}

// A rotation can follow the last establishment event or an interaction after
// it, and nothing else: not an event that is not in the log.
func TestBreakGlassFollowsOnlyAPlaceItMayTake(t *testing.T) {
	withRootAIDRotationEnabled(t, func() {
		b := aBreakGlassSetup(t)
		var req PrepareRootAIDRotationRequest
		req.NewRoot.K, req.NewRoot.N = []string{b.app.pub(4)}, b.app.commits(5, 9)
		req.OldRoot.K, req.OldRoot.N = []string{b.app.pub(1)}, b.app.commits(2, 10)
		req.OldRoot.After.S, req.OldRoot.After.D = "0", "EnotAnEventOfThisLog00000000000000000000000"
		if _, err := PrepareRootAIDRotation(req, b.founding(), b.e, b.st); err == nil {
			t.Fatal("a rotation following an event that is not in the log was prepared")
		}
	})
}

// The proof is checked from what it carries alone: it is read back from its
// JSON, each digest is recomputed from the bytes, and both signatures verify.
func TestAContinuityProofIsVerifiedFromWhatItCarries(t *testing.T) {
	withRootAIDRotationEnabled(t, func() {
		b := aBreakGlassSetup(t)
		p := b.prepare()
		res, err := RotateRootAID(b.signed(p), b.commit, b.st, t.TempDir(), nil)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := json.Marshal(res.ContinuityProof)
		if err != nil {
			t.Fatal(err)
		}
		var proof ContinuityProof
		if err := json.Unmarshal(wire, &proof); err != nil {
			t.Fatal(err)
		}
		if err := VerifyContinuityProof(proof); err != nil {
			t.Fatalf("a proof read back from the wire does not verify: %v", err)
		}
		// The bytes carried are the bytes that were signed, so the digests are theirs.
		for label, c := range map[string]struct{ raw, said string }{
			"authorization": {proof.AuthorizationEventRawB64, proof.AuthorizationEventSAID},
			"back-anchor":   {proof.BackAnchorEventRawB64, proof.BackAnchorEventSAID},
			"inception":     {proof.NewInceptionRawB64, proof.NewInceptionSAID},
		} {
			rawBytes, _ := base64.StdEncoding.DecodeString(c.raw)
			if got, err := keri.ComputeSAID(rawBytes); err != nil || got != c.said {
				t.Fatalf("the %s event's bytes digest to %s (%v), the proof says %s", label, got, err, c.said)
			}
		}
		if len(proof.AuthorizationSignatures) == 0 || len(proof.BackAnchorSignatures) == 0 {
			t.Fatal("a signature list is empty")
		}
		if _, err := keri.ParseIndexedSignature(proof.AuthorizationSignatures[0]); err != nil {
			t.Fatalf("the authorization signature is not an indexed signature: %v", err)
		}

		tamper := map[string]func(p *ContinuityProof){
			"an authorization event with a byte changed": func(p *ContinuityProof) {
				r, _ := base64.StdEncoding.DecodeString(p.AuthorizationEventRawB64)
				r[len(r)/2] ^= 1
				p.AuthorizationEventRawB64 = base64.StdEncoding.EncodeToString(r)
			},
			"an authorization signature of another event": func(p *ContinuityProof) {
				p.AuthorizationSignatures = []string{b.app.sign(1, []byte("another event"), true)}
			},
			"a back-anchor signature of another key": func(p *ContinuityProof) {
				ixn, _ := base64.StdEncoding.DecodeString(p.BackAnchorEventRawB64)
				p.BackAnchorSignatures = []string{b.app.sign(7, ixn, false)}
			},
			"no authorization signature": func(p *ContinuityProof) { p.AuthorizationSignatures = nil },
		}
		for name, f := range tamper {
			bad := proof
			bad.AuthorizationSignatures = append([]string(nil), proof.AuthorizationSignatures...)
			bad.BackAnchorSignatures = append([]string(nil), proof.BackAnchorSignatures...)
			f(&bad)
			if err := VerifyContinuityProof(bad); err == nil {
				t.Fatalf("%s was verified", name)
			}
		}
		if !strings.HasPrefix(proof.V, "3") {
			t.Fatalf("proof version %s", proof.V)
		}
	})
}

// The schema the proof is published under names the fields it has: every
// required field is present, and no field is one the schema does not name.
func TestAContinuityProofIsWhatItsSchemaDescribes(t *testing.T) {
	withRootAIDRotationEnabled(t, func() {
		b := aBreakGlassSetup(t)
		res, err := RotateRootAID(b.signed(b.prepare()), b.commit, b.st, t.TempDir(), nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(filepath.Join("..", "contracts", "root-aid-continuity", "continuity-proof.schema.json"))
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			ID         string                     `json:"$id"`
			Required   []string                   `json:"required"`
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal(body, &schema); err != nil {
			t.Fatal(err)
		}
		wire, _ := json.Marshal(res.ContinuityProof)
		var doc map[string]json.RawMessage
		_ = json.Unmarshal(wire, &doc)
		for _, name := range schema.Required {
			if _, ok := doc[name]; !ok {
				t.Errorf("the schema requires %s and the proof has none", name)
			}
		}
		for name := range doc {
			if _, ok := schema.Properties[name]; !ok {
				t.Errorf("the proof has %s, which the schema does not name", name)
			}
		}
		if !strings.HasSuffix(schema.ID, "/v"+continuityProofVersion) {
			t.Errorf("the schema is %s, the proof is version %s", schema.ID, continuityProofVersion)
		}
	})
}
