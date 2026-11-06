package recovery

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/keriengine"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// The break-glass root rotation writes three events, and each is signed by the
// key it needs before anything is added. These tests drive the real engine,
// with keys only the test holds, standing in for the person's app.

type appKeys struct {
	t    *testing.T
	keys []*keri.SoftwareSigner
}

func newAppKeys(t *testing.T, n int) *appKeys {
	a := &appKeys{t: t}
	for i := 0; i < n; i++ {
		s, err := keri.GenerateSigner(true)
		if err != nil {
			t.Fatal(err)
		}
		a.keys = append(a.keys, s)
	}
	return a
}

func (a *appKeys) pub(i int) string {
	p, err := a.keys[i].PublicKey()
	if err != nil {
		a.t.Fatal(err)
	}
	return p
}

func (a *appKeys) digest(i int) string {
	d, err := keri.NextDigest(a.pub(i))
	if err != nil {
		a.t.Fatal(err)
	}
	return d
}

// commits is what an establishment event commits to: the digest of the next
// classical key and of a post-quantum reserve (here a key standing in for it).
func (a *appKeys) commits(next, reserve int) []string {
	return []string{a.digest(next), a.digest(reserve)}
}

// sign is key i's indexed signature over raw, opening the prior commitment at
// index 0 when it reveals it (a founding or rotation), the current list only otherwise.
func (a *appKeys) sign(i int, raw []byte, opens bool) string {
	sig, err := a.keys[i].Sign(raw)
	if err != nil {
		a.t.Fatal(err)
	}
	at := keri.SignaturePlace{Index: 0, Ondex: 0, CurrentOnly: !opens}
	q, err := keri.EncodeIndexedSignature(sig, at)
	if err != nil {
		a.t.Fatal(err)
	}
	return q
}

// breakGlass is an identity kept in an engine and a store, as the core keeps
// one, with the app's keys: old root keys 0..3 (0 is in force and "stolen", 1 is
// committed, 2 and 3 its next and reserve), new root keys 4..7.
type breakGlass struct {
	t       *testing.T
	app     *appKeys
	e       *keriengine.Engine
	st      *memNotifyStore
	oldAID  string
	commits []string // the ilk of each event committed, in order
}

func aBreakGlassSetup(t *testing.T) *breakGlass {
	app := newAppKeys(t, 12)
	e := keriengine.New()
	p, err := e.Prepare(keriengine.PrepareRequest{Ilk: "icp", Keys: []string{app.pub(0)}, Kt: one,
		Next: app.commits(1, 8), Nt: one})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Commit("", p.Raw, []string{app.sign(0, p.Raw, true)}, nil); err != nil {
		t.Fatal(err)
	}
	b := &breakGlass{t: t, app: app, e: e, oldAID: p.Hint.I,
		st: &memNotifyStore{
			identity: &store.IdentityState{AID: p.Hint.I},
			contacts: []store.ContactRecord{{AID: "EP1", Status: "accepted"}, {AID: "EP2", Status: "accepted"}},
		}}
	b.syncStore(p.Hint.I)
	return b
}

// syncStore keeps the store's events as the core's store keeps them: raw bytes and signatures.
func (b *breakGlass) syncStore(aid string) {
	kel, err := b.e.GetKel(aid)
	if err != nil {
		b.t.Fatal(err)
	}
	var kept []store.EventRecord
	for _, ev := range b.st.events {
		if ev.AID != aid {
			kept = append(kept, ev)
		}
	}
	for i, raw64 := range kel.RawEventsB64 {
		raw, _ := base64.StdEncoding.DecodeString(raw64)
		parsed, err := keri.ParseEvent(raw)
		if err != nil {
			b.t.Fatal(err)
		}
		kept = append(kept, store.EventRecord{AID: aid, SequenceNumber: i, EventType: parsed.Ilk,
			EventJSON: string(raw), RawBytesB64: raw64, Signatures: kel.Signatures[i]})
	}
	b.st.events = kept
}

// commit is the commit path the core gives the rotation: the engine adds the
// event only with its signatures.
func (b *breakGlass) commit(raw []byte, sigs []string) error {
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return err
	}
	name := ev.Identifier
	if ev.Ilk == "icp" {
		name = ""
	}
	res, err := b.e.Commit(name, raw, sigs, nil)
	if err != nil {
		return err
	}
	if res.Status != "recorded" && res.Status != "already_recorded" {
		return &commitNotRecorded{res.Status}
	}
	b.commits = append(b.commits, ev.Ilk)
	b.syncStore(ev.Identifier)
	return nil
}

type commitNotRecorded struct{ status string }

func (c *commitNotRecorded) Error() string { return c.status }

func (b *breakGlass) prepare() *PreparedRootAIDRotation {
	tip := b.st.events[len(b.st.events)-1]
	var ked struct {
		D string `json:"d"`
	}
	_ = json.Unmarshal([]byte(tip.EventJSON), &ked)
	var req PrepareRootAIDRotationRequest
	req.NewRoot.K = []string{b.app.pub(4)}
	req.NewRoot.N = b.app.commits(5, 9)
	req.OldRoot.K = []string{b.app.pub(1)}
	req.OldRoot.N = b.app.commits(2, 10)
	req.OldRoot.After.S = "0"
	req.OldRoot.After.D = ked.D
	prepared, err := PrepareRootAIDRotation(req, b.founding(), b.e, b.st)
	if err != nil {
		b.t.Fatal(err)
	}
	return prepared
}

// founding is the new root's inception as a founding is asked for: key 4,
// committing to keys 5 and 9. (The server builds this from an app's request,
// with the owner seal, anchors and witnesses; here it is bare.)
func (b *breakGlass) founding() keriengine.PrepareRequest {
	return keriengine.PrepareRequest{Ilk: "icp", Keys: []string{b.app.pub(4)}, Kt: one,
		Next: b.app.commits(5, 9), Nt: one}
}

func raw(t *testing.T, e PreparedRootAIDEvent) []byte {
	t.Helper()
	r, err := base64.StdEncoding.DecodeString(e.RawB64)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// signed is the request the app makes: icp by new key 4, the rotation by old key 1
// (the one it reveals), the interaction by new key 4.
func (b *breakGlass) signed(p *PreparedRootAIDRotation) RootAIDRotationRequest {
	icp, rot, ixn := raw(b.t, p.NewRootFounding), raw(b.t, p.OldRootRotation), raw(b.t, p.NewRootInteraction)
	return RootAIDRotationRequest{
		RecoverySessionID:  "sess-1",
		NewRootFounding:    drivers.SignedEventBytes{RawB64: p.NewRootFounding.RawB64, Sigs: []string{b.app.sign(4, icp, true)}},
		OldRootRotation:    drivers.SignedEventBytes{RawB64: p.OldRootRotation.RawB64, Sigs: []string{b.app.sign(1, rot, true)}},
		NewRootInteraction: drivers.SignedEventBytes{RawB64: p.NewRootInteraction.RawB64, Sigs: []string{b.app.sign(4, ixn, false)}},
		CarryForwardAIDs:   []string{"EP2"},
	}
}

func (b *breakGlass) logOf(aid string) [][]byte {
	kel, err := b.e.GetKel(aid)
	if err != nil {
		b.t.Fatal(err)
	}
	var out [][]byte
	for i, r64 := range kel.RawEventsB64 {
		r, _ := base64.StdEncoding.DecodeString(r64)
		m, err := drivers.SignedMessage(r, kel.Signatures[i])
		if err != nil {
			b.t.Fatalf("event %d of %s is held without signatures", i, aid)
		}
		out = append(out, m)
	}
	return out
}

// Every event the rotation writes is signed by the key it needs and the logs
// they make verify: the old root's with the rotation that authorises the new
// root, and the new root's with its interaction.
func TestEveryEventBreakGlassWritesIsSignedAndVerifies(t *testing.T) {
	withRootAIDRotationEnabled(t, func() {
		b := aBreakGlassSetup(t)
		prepared := b.prepare()
		if b.commits != nil {
			t.Fatal("preparing the rotation wrote an event")
		}
		res, err := RotateRootAID(b.signed(prepared), b.commit, b.st, t.TempDir(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(b.commits, ","); got != "icp,rot,ixn" {
			t.Fatalf("events were written in the order %s", got)
		}
		newAID := prepared.NewRootFounding.Hint.I
		if res.OldRootAID != b.oldAID || res.NewRootAID != newAID {
			t.Fatalf("%s -> %s", res.OldRootAID, res.NewRootAID)
		}

		oldLog, err := keri.ValidateSignedKEL(b.logOf(b.oldAID))
		if err != nil {
			t.Fatalf("the old root's log does not verify: %v", err)
		}
		newLog, err := keri.ValidateSignedKEL(b.logOf(newAID))
		if err != nil {
			t.Fatalf("the new root's log does not verify: %v", err)
		}
		if oldLog.Identifier != b.oldAID || newLog.Identifier != newAID {
			t.Fatal("a log is of another identifier")
		}
		if len(b.logOf(b.oldAID)) != 2 || len(b.logOf(newAID)) != 2 {
			t.Fatal("each log is its founding and one event")
		}

		// The proof ties the two: the rotation seals the new inception, the
		// interaction seals the old log's tip after it, the rotation.
		if err := VerifyContinuityProof(res.ContinuityProof); err != nil {
			t.Fatal(err)
		}
		if res.ContinuityProof.PriorKelTailSAID != b.oldAID {
			t.Fatalf("the rotation follows %s, not the old root's founding", res.ContinuityProof.PriorKelTailSAID)
		}
		if res.ContinuityProof.BackAnchorEventSAID != prepared.NewRootInteraction.Hint.D ||
			res.ContinuityProof.AuthorizationEventSAID != prepared.OldRootRotation.Hint.D {
			t.Fatal("the proof does not name the events written")
		}
		if b.st.identity.AID != newAID || b.st.identity.EventCount != 1 {
			t.Fatalf("identity record %+v", b.st.identity)
		}
		if res.NotificationsSent != 0 || len(res.CarriedForwardAIDs) != 1 {
			t.Fatalf("carry-forward %+v notified %d", res.CarriedForwardAIDs, res.NotificationsSent)
		}
	})
}

// A break-glass where any event lacks a signature is refused whole, before
// anything is written: not even the harmless founding is added.
func TestBreakGlassWithAnUnsignedEventIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	for _, which := range []string{"new_root_founding", "old_root_rotation", "new_root_interaction"} {
		t.Run(which, func(t *testing.T) {
			withRootAIDRotationEnabled(t, func() {
				b := aBreakGlassSetup(t)
				req := b.signed(b.prepare())
				switch which {
				case "new_root_founding":
					req.NewRootFounding.Sigs = nil
				case "old_root_rotation":
					req.OldRootRotation.Sigs = nil
				default:
					req.NewRootInteraction.Sigs = nil
				}
				_, err := RotateRootAID(req, b.commit, b.st, t.TempDir(), nil)
				if err == nil || !strings.Contains(err.Error(), which+" is not signed") {
					t.Fatalf("not refused for the missing signature: %v", err)
				}
				b.nothingWritten()
			})
		})
	}
}

// The signature has to be by the key the event needs: the rotation signed by
// the old root's current key, the stolen one, opens no commitment.
func TestBreakGlassSignedByTheWrongKeyIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	withRootAIDRotationEnabled(t, func() {
		for name, tamper := range map[string]func(*breakGlass, *RootAIDRotationRequest, *PreparedRootAIDRotation){
			"the rotation signed by the stolen current key": func(b *breakGlass, r *RootAIDRotationRequest, p *PreparedRootAIDRotation) {
				r.OldRootRotation.Sigs = []string{b.app.sign(0, raw(b.t, p.OldRootRotation), true)}
			},
			"the founding signed by another key": func(b *breakGlass, r *RootAIDRotationRequest, p *PreparedRootAIDRotation) {
				r.NewRootFounding.Sigs = []string{b.app.sign(7, raw(b.t, p.NewRootFounding), true)}
			},
			"the interaction signed by another key": func(b *breakGlass, r *RootAIDRotationRequest, p *PreparedRootAIDRotation) {
				r.NewRootInteraction.Sigs = []string{b.app.sign(7, raw(b.t, p.NewRootInteraction), false)}
			},
		} {
			t.Run(name, func(t *testing.T) {
				b := aBreakGlassSetup(t)
				p := b.prepare()
				req := b.signed(p)
				tamper(b, &req, p)
				if _, err := RotateRootAID(req, b.commit, b.st, t.TempDir(), nil); err == nil {
					t.Fatal("a rotation signed by the wrong key was taken")
				}
				b.nothingWritten()
			})
		}
	})
}

// Each rotation carries the post-quantum commitment: an establishment event
// that commits to one digest is not prepared, and not taken if one is made another way.
func TestBreakGlassCarriesThePostQuantumCommitment(t *testing.T) {
	withRootAIDRotationEnabled(t, func() {
		b := aBreakGlassSetup(t)
		var req PrepareRootAIDRotationRequest
		req.NewRoot.K = []string{b.app.pub(4)}
		req.NewRoot.N = b.app.commits(5, 9)
		req.OldRoot.K = []string{b.app.pub(1)}
		req.OldRoot.N = []string{b.app.digest(2)}
		req.OldRoot.After.S, req.OldRoot.After.D = "0", b.oldAID
		if _, err := PrepareRootAIDRotation(req, b.founding(), b.e, b.st); err == nil || !strings.Contains(err.Error(), "two next-key digests") {
			t.Fatalf("a rotation committing to one digest was prepared: %v", err)
		}

		// Built another way, bypassing the prepare, and signed.
		p := b.prepare()
		oneDigest, err := b.e.Prepare(keriengine.PrepareRequest{Name: b.oldAID, Ilk: "rot", Keys: []string{b.app.pub(1)}, Kt: one,
			Next: []string{b.app.digest(2)}, Nt: one,
			Anchors: []json.RawMessage{json.RawMessage(`{"d":"` + p.NewRootFounding.Hint.D + `"}`)},
			After:   &keriengine.Place{SN: 0, SAID: b.oldAID}})
		if err != nil {
			t.Fatal(err)
		}
		signed := b.signed(p)
		signed.OldRootRotation = drivers.SignedEventBytes{RawB64: base64.StdEncoding.EncodeToString(oneDigest.Raw),
			Sigs: []string{b.app.sign(1, oneDigest.Raw, true)}}
		// The interaction seals the rotation actually sent.
		sealed, err := keri.ParseEvent(oneDigest.Raw)
		if err != nil {
			t.Fatal(err)
		}
		ixnRaw, err := keri.BuildInteraction(keri.InteractionInput{Prefix: p.NewRootFounding.Hint.I,
			PriorSAID: p.NewRootFounding.Hint.D, SN: 1, Data: []json.RawMessage{json.RawMessage(`{"d":"` + sealed.SAID + `"}`)}})
		if err != nil {
			t.Fatal(err)
		}
		signed.NewRootInteraction = drivers.SignedEventBytes{RawB64: base64.StdEncoding.EncodeToString(ixnRaw),
			Sigs: []string{b.app.sign(4, ixnRaw, false)}}
		if _, err := RotateRootAID(signed, b.commit, b.st, t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "two next-key digests") {
			t.Fatalf("a rotation committing to one digest was taken: %v", err)
		}
		b.nothingWritten()
	})
}

// Switched off, nothing is prepared and nothing is committed.
func TestBreakGlassSwitchedOffPreparesAndCommitsNothing(t *testing.T) {
	b := aBreakGlassSetup(t)
	if _, err := PrepareRootAIDRotation(PrepareRootAIDRotationRequest{}, keriengine.PrepareRequest{}, b.e, b.st); err == nil {
		t.Fatal("prepared while switched off")
	}
	if _, err := RotateRootAID(RootAIDRotationRequest{RecoverySessionID: "s"}, b.commit, b.st, t.TempDir(), nil); err == nil {
		t.Fatal("rotated while switched off")
	}
	b.nothingWritten()
}

func (b *breakGlass) nothingWritten() {
	b.t.Helper()
	if len(b.commits) != 0 {
		b.t.Fatalf("%v were committed", b.commits)
	}
	if b.st.identity.AID != b.oldAID {
		b.t.Fatal("the identity record moved")
	}
	if kel, _ := b.e.GetKel(b.oldAID); kel == nil || kel.EventCount != 1 {
		b.t.Fatal("the old root's log changed")
	}
}
