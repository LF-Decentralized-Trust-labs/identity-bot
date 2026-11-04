package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"identity-agent-core/didcomm"
	"identity-agent-core/iacrypto"
	"identity-agent-core/recovery"
	"identity-agent-core/store"
	"identity-agent-core/witness"
)

// A break-glass root rotation stopped part way is finished by sending the same
// request again; it supersedes what the thief signed; the new root is founded
// as any other is; the old root's witnesses are told of the rotation however
// late; and the request is bound to a real recovery session and a size.

// stopsAtStore is a store that fails one write once.
type stopsAtStore struct {
	store.Store
	mu       sync.Mutex
	identity func(store.IdentityState) bool
	event    func(store.EventRecord) bool
	task     bool
	stopped  int
}

func (s *stopsAtStore) fail(hit bool) error {
	if !hit {
		return nil
	}
	s.stopped++
	return fmt.Errorf("the disk is full")
}

func (s *stopsAtStore) SaveIdentity(id store.IdentityState) error {
	s.mu.Lock()
	hit := s.identity != nil && s.identity(id)
	if hit {
		s.identity = nil
	}
	s.mu.Unlock()
	if err := s.fail(hit); err != nil {
		return err
	}
	return s.Store.SaveIdentity(id)
}

func (s *stopsAtStore) SaveEvent(rec store.EventRecord) error {
	s.mu.Lock()
	hit := s.event != nil && s.event(rec)
	if hit {
		s.event = nil
	}
	s.mu.Unlock()
	if err := s.fail(hit); err != nil {
		return err
	}
	return s.Store.SaveEvent(rec)
}

func (s *stopsAtStore) SaveTask(t store.TaskRecord) error {
	s.mu.Lock()
	hit := s.task
	s.task = false
	s.mu.Unlock()
	if err := s.fail(hit); err != nil {
		return err
	}
	return s.Store.SaveTask(t)
}

// aWitnessToTell is a core with a contact the rotation notifies, so a task is queued.
func aWitnessToTell(s *CoreServer) {
	s.DataStore.SaveContact(store.ContactRecord{AID: "EContactToTell", Status: "accepted", IsWitness: true,
		OobiURL: "http://w1.test/oobi"})
}

// whatARotationLeaves is the state of a core after a break-glass, without the
// times it was done at.
func whatARotationLeaves(t *testing.T, b *brokenGlass) map[string]any {
	t.Helper()
	newAID := b.prepared["new_root_founding"]["hint"].(map[string]any)["i"].(string)
	out := map[string]any{}
	for label, aid := range map[string]string{"old": b.oldAID, "new": newAID} {
		evs, _ := b.s.DataStore.GetEvents(aid)
		var kept []string
		for _, ev := range evs {
			kept = append(kept, fmt.Sprint(ev.SequenceNumber, ev.EventType, ev.RawBytesB64, ev.ControllerSignatures()))
		}
		out[label+" log"] = kept
		sup, _ := b.s.DataStore.SupersededEvents(aid)
		var superseded []string
		for _, ev := range sup {
			superseded = append(superseded, ev.RawBytesB64)
		}
		out[label+" superseded"] = superseded
	}
	own, _ := b.s.DataStore.GetIdentity()
	out["identity"] = fmt.Sprint(own.AID, own.EventCount, own.PublicKey, own.NextKeyDigest, own.KeyGeneration)
	tasks, _ := b.s.DataStore.GetTasks()
	var ts []string
	for _, task := range tasks {
		ts = append(ts, fmt.Sprint(task.ID, task.Type, task.Status, task.ContactAID))
	}
	out["tasks"] = ts
	m, _ := recovery.LoadRootAIDMap(b.s.DataDir)
	var entries []string
	for _, e := range m.Entries {
		e.RotatedAt, e.RecoverySessionID = "", ""
		e.WitnessedAt, e.WitnessingGaveUpAt = "", "" // how the witnessing went is not the rotation's
		entries = append(entries, fmt.Sprint(e))
	}
	out["root map"] = entries
	return out
}

func TestBreakGlassStoppedPartWayIsFinishedByAResendAndLeavesWhatACleanRunLeaves(t *testing.T) {
	t.Run("on a log nobody added to", func(t *testing.T) { stoppedPartWay(t, false) })
	// With an interaction the stolen key signed, which the rotation supersedes:
	// finishing it must not supersede the rotation itself.
	t.Run("over an interaction the stolen key signed", func(t *testing.T) { stoppedPartWay(t, true) })
}

func stoppedPartWay(t *testing.T, thief bool) {
	setup := breakGlassSetup{core: aWitnessToTell}
	if thief {
		setup.between = func(b *brokenGlass) { thiefAnchors(t, b, "EThiefAnchorBeforeThePreparation00000000000") }
		setup.after = func(b *brokenGlass) map[string]string { return map[string]string{"s": "0", "d": b.oldAID} }
	}
	clean := aRootToBreakGlassWith(t, setup)
	if code, out := clean.rotate(t); code != http.StatusOK {
		t.Fatalf("a clean run: %d %v", code, out)
	}
	want := whatARotationLeaves(t, clean)
	if n := len(want["tasks"].([]string)); n != 1 {
		t.Fatalf("a clean run queued %d notification tasks, want 1", n)
	}

	newOf := func(b *brokenGlass) string {
		return b.prepared["new_root_founding"]["hint"].(map[string]any)["i"].(string)
	}
	for _, c := range []struct {
		name string
		stop func(b *brokenGlass, st *stopsAtStore)
		// before the resend
		repair func(b *brokenGlass)
	}{
		{"(a) after the old root's rotation was added, before the identity moved", func(b *brokenGlass, st *stopsAtStore) {
			st.identity = func(id store.IdentityState) bool { return id.AID == newOf(b) && id.EventCount == 1 }
		}, nil},
		{"(a) while the rotation's own record of the identity was being moved on", func(b *brokenGlass, st *stopsAtStore) {
			st.identity = func(id store.IdentityState) bool { return id.AID == b.oldAID }
		}, nil},
		{"(b) on the interaction, before it was stored", func(b *brokenGlass, st *stopsAtStore) {
			st.event = func(r store.EventRecord) bool { return r.AID == newOf(b) && r.SequenceNumber == 1 }
		}, nil},
		{"(b) on the interaction, after it was stored", func(b *brokenGlass, st *stopsAtStore) {
			st.identity = func(id store.IdentityState) bool { return id.AID == newOf(b) && id.EventCount == 2 }
		}, nil},
		{"(c) queuing the notification tasks", func(b *brokenGlass, st *stopsAtStore) { st.task = true }, nil},
		{"(c) writing the root map entry", func(b *brokenGlass, st *stopsAtStore) {
			if err := os.Mkdir(filepath.Join(b.s.DataDir, "root_aid_map.json"), 0o700); err != nil {
				t.Fatal(err)
			}
		}, func(b *brokenGlass) {
			if err := os.Remove(filepath.Join(b.s.DataDir, "root_aid_map.json")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := aRootToBreakGlassWith(t, setup)
			st := &stopsAtStore{Store: b.s.DataStore}
			b.s.DataStore = st
			c.stop(b, st)
			code, out := b.rotate(t)
			if code != http.StatusUnprocessableEntity {
				t.Fatalf("the stop was not reported: %d %v", code, out)
			}
			if c.repair != nil {
				c.repair(b)
			}
			code, out = b.rotate(t)
			if code != http.StatusOK {
				t.Fatalf("the resend did not finish it: %d %v", code, out)
			}
			if got := whatARotationLeaves(t, b); !reflect.DeepEqual(got, want) {
				for k := range want {
					if !reflect.DeepEqual(got[k], want[k]) {
						t.Errorf("%s: a resend left\n%v\nand a clean run\n%v", k, got[k], want[k])
					}
				}
				t.FailNow()
			}
			// And the identity kept here carries on from the new root.
			if own, _ := b.s.DataStore.GetIdentity(); own.AID != newOf(b) || own.EventCount != 2 {
				t.Fatalf("identity %+v", own)
			}
			// Sending it once more adds nothing.
			if code, out = b.rotate(t); code != http.StatusOK {
				t.Fatalf("a repeat of a finished rotation: %d %v", code, out)
			}
			if got := whatARotationLeaves(t, b); !reflect.DeepEqual(got, want) {
				t.Fatalf("a repeat changed what was left:\n%v", got)
			}
		})
	}
}

// thiefAnchors is the holder of the stolen current key adding an interaction to the old root.
func thiefAnchors(t *testing.T, b *brokenGlass, label string) {
	t.Helper()
	evs, _ := b.s.DataStore.GetEvents(b.oldAID)
	last := evs[len(evs)-1]
	var ked struct{ D string }
	_ = json.Unmarshal([]byte(last.EventJSON), &ked)
	prepareAndCommit(t, b.s, map[string]any{"t": "ixn", "aid": b.oldAID, "a": []any{map[string]string{"d": label}},
		"after": map[string]string{"s": fmt.Sprintf("%x", last.SequenceNumber), "d": ked.D}}, b.k[0], false)
}

// An interaction signed by the stolen key after the last establishment event
// is superseded, kept as superseded, and the break-glass completes; a thief
// who keeps adding interactions, even after the rotation was prepared and
// signed, cannot block it. The new root's interaction seals the rotation.
func TestBreakGlassSupersedesWhatTheStolenKeySigned(t *testing.T) {
	b := aRootToBreakGlassWith(t, breakGlassSetup{
		between: func(b *brokenGlass) { thiefAnchors(t, b, "EThiefAnchorBeforeThePreparation00000000000") },
		after: func(b *brokenGlass) map[string]string {
			return map[string]string{"s": "0", "d": b.oldAID}
		},
	})
	thiefAnchors(t, b, "EThiefAnchorAfterThePreparation000000000000")
	if evs, _ := b.s.DataStore.GetEvents(b.oldAID); len(evs) != 3 {
		t.Fatalf("the thief's interactions are not in the log: %d events", len(evs))
	}
	code, out := b.rotate(t)
	if code != http.StatusOK {
		t.Fatalf("a thief blocked the break-glass: %d %v", code, out)
	}
	m, _ := storedLog(t, b.s, b.oldAID)
	if len(m) != 2 {
		t.Fatalf("the old root's log is %d events, want its founding and the rotation", len(m))
	}
	superseded, _ := b.s.DataStore.SupersededEvents(b.oldAID)
	if len(superseded) != 2 {
		t.Fatalf("%d interactions kept as superseded, want the thief's two", len(superseded))
	}
	for _, ev := range superseded {
		if ev.EventType != "ixn" {
			t.Fatalf("a %s was superseded", ev.EventType)
		}
	}
	rotD := b.prepared["old_root_rotation"]["hint"].(map[string]any)["d"].(string)
	var ixn struct {
		A []struct{ D string } `json:"a"`
	}
	_ = json.Unmarshal(preparedBytes(t, b.prepared["new_root_interaction"]), &ixn)
	if len(ixn.A) != 1 || ixn.A[0].D != rotD {
		t.Fatalf("the new root's interaction seals %+v, want the rotation %s", ixn.A, rotD)
	}
}

// ---- the new root is founded as any other is ----

const anOwner = "EOwnerOfTheNewRoot00000000000000000000000000"

func messagingSeedHex(n byte) string { return hex.EncodeToString(bytes.Repeat([]byte{n}, 32)) }

// aWitness is a witness that holds what it is sent, in order, only if signed;
// it can be down.
type aWitness struct {
	mu   sync.Mutex
	down bool
	held map[string][]store.EventRecord
	name string
	priv ed25519.PrivateKey
}

func newWitness() *aWitness {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &aWitness{name: iacrypto.NonTransferableAIDQB64(pub), priv: priv, held: map[string][]store.EventRecord{}}
}

func (w *aWitness) installOn(t *testing.T, s *CoreServer) {
	t.Helper()
	sq := s.DataStore.(*store.SQLiteStore)
	s.WitnessService = witness.NewService(witness.NewSQLiteStore(sq.DB()), sq, s.KeriDriver, witness.BackendDesktop)
	s.DataStore.SaveContact(store.ContactRecord{AID: "EWitness0", OobiURL: "http://w0.test", Status: "active", IsWitness: true})
	s.WitnessService.Store.SaveContactMeta(witness.ContactMeta{ContactAID: "EWitness0", WitnessKey: w.name, IsCommercial: true})
	s.WitnessService.FetchTip = func(_ context.Context, url string) (witness.TipAnswer, error) {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.down {
			return witness.TipAnswer{}, fmt.Errorf("unreachable")
		}
		path, _, _ := strings.Cut(url, "?")
		aid := strings.TrimSuffix(path[strings.Index(path, "/witness/kel/")+len("/witness/kel/"):], "/tip")
		return witnessTip(url, w.held[aid], w.priv, w.name), nil
	}
	s.WitnessService.PostEvent = func(_ context.Context, _ string, body []byte) (map[string]interface{}, error) {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.down {
			return nil, fmt.Errorf("unreachable")
		}
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		raw, _ := base64.StdEncoding.DecodeString(req["event_b64"].(string))
		var ev map[string]any
		_ = json.Unmarshal(raw, &ev)
		aid := ev["i"].(string)
		if sig, _ := req["cesr_signature"].(string); sig == "" || ev["s"] != fmt.Sprintf("%x", len(w.held[aid])) {
			return nil, fmt.Errorf("refused")
		}
		w.held[aid] = append(w.held[aid], store.EventRecord{RawBytesB64: req["event_b64"].(string), SequenceNumber: len(w.held[aid])})
		return nil, nil
	}
}

func (w *aWitness) holds(aid string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.held[aid])
}

func (w *aWitness) setDown(down bool) {
	w.mu.Lock()
	w.down = down
	w.mu.Unlock()
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if f() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("never: %s", what)
}

func newRootOf(b *brokenGlass) string {
	return b.prepared["new_root_founding"]["hint"].(map[string]any)["i"].(string)
}

// foundedWitnessed is a break-glass on an old root that names a witness, the
// owner and a messaging keyset the app handed over, and a new root asked for
// as newRoot says.
func foundedWitnessed(t *testing.T, w *aWitness, newRoot map[string]any) (*brokenGlass, any) {
	t.Helper()
	var anchor any
	b := aRootToBreakGlassWith(t, breakGlassSetup{
		core: func(s *CoreServer) {
			s.requireOwnerAtInception = true
			w.installOn(t, s)
		},
		oldFounding: map[string]any{"owner_aid": anOwner, "b": []string{w.name}, "bt": "1"},
		newRoot:     newRoot,
		between: func(b *brokenGlass) {
			code, out := call(t, b.s, b.s.handleMessagingSeed, "/api/keystore/messaging-seed", map[string]any{"seed_hex": messagingSeedHex(7)})
			if code != http.StatusOK {
				t.Fatalf("messaging seed: %d %v", code, out)
			}
			anchor = out["anchor"]
			newRoot["a"] = []any{anchor}
		},
	})
	return b, anchor
}

// The new root is what an ordinary app founding is: it keeps the old root's
// witnesses unless the app names others, anchors the owner and the messaging
// keyset the app handed over, and is committed and witnessed.
func TestBreakGlassFoundsTheNewRootAsAnyOtherIsFounded(t *testing.T) {
	other := newWitness()
	for _, c := range []struct {
		name      string
		asks      map[string]any
		witnesses func(w *aWitness) []any
		toad      string
	}{
		{"it keeps the old root's witnesses when the app names none", nil,
			func(w *aWitness) []any { return []any{w.name} }, "1"},
		{"it takes the witnesses the app names", map[string]any{"b": []string{other.name}, "bt": "1"},
			func(*aWitness) []any { return []any{other.name} }, "1"},
		{"it has none when the app names an empty list", map[string]any{"b": []string{}},
			func(*aWitness) []any { return nil }, "0"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newWitness()
			newRoot := map[string]any{"owner_aid": anOwner}
			for k, v := range c.asks {
				newRoot[k] = v
			}
			b, anchor := foundedWitnessed(t, w, newRoot)
			newAID := newRootOf(b)

			icp := eventsOfRaw(t, preparedBytes(t, b.prepared["new_root_founding"]))
			if got, _ := icp["b"].([]any); !reflect.DeepEqual(got, c.witnesses(w)) && !(len(got) == 0 && len(c.witnesses(w)) == 0) {
				t.Fatalf("the new root names witnesses %v, want %v", got, c.witnesses(w))
			}
			if icp["bt"] != c.toad {
				t.Fatalf("the new root's witness threshold is %v, want %v", icp["bt"], c.toad)
			}
			seals, _ := icp["a"].([]any)
			if len(seals) != 2 || !reflect.DeepEqual(seals[0], map[string]any{"i": anOwner, "s": "0", "d": anOwner}) ||
				!reflect.DeepEqual(seals[1], anchor) {
				t.Fatalf("the new root anchors %v, want the owner's seal and the messaging keyset", seals)
			}

			// The old root is witnessed from its founding; then the rotation is committed.
			eventually(t, "the old root's founding reaches its witness", func() bool { return w.holds(b.oldAID) == 1 })
			if code, out := b.rotate(t); code != http.StatusOK {
				t.Fatalf("break-glass: %d %v", code, out)
			}
			// The messaging keys the app handed over are now the new root's.
			if has, _ := b.s.hasKeySet(newAID); !has {
				t.Fatal("the new root's messaging keyset was not filed under it")
			}
			if held, _ := b.s.keySetAnchorHeld(newAID, anchor.(map[string]any)); !held {
				t.Fatal("the new root holds another messaging keyset than the one it anchors")
			}
			if len(c.witnesses(w)) == 0 {
				return
			}
			named := c.witnesses(w)[0].(string)
			if named != w.name {
				return // a witness this core has no address for is not sent to
			}
			eventually(t, "the old root's rotation and the new root's events reach the witness", func() bool {
				return w.holds(b.oldAID) == 2 && w.holds(newAID) == 2
			})
		})
	}
}

func eventsOfRaw(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var ev map[string]any
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

// A core that requires an owner prepares no new root without one, and the
// gate is the founding's: a machine that may not found refuses.
func TestBreakGlassNewRootIsHeldToTheFoundingGate(t *testing.T) {
	w := newWitness()
	b, _ := foundedWitnessed(t, w, map[string]any{"owner_aid": anOwner})
	k := b.k
	code, out := call(t, b.s, b.s.handleRecoveryRootAIDPrepare, "/api/recovery/root-aid-rotation/prepare", map[string]any{
		"new_root": map[string]any{"k": []string{verkeyOf(k[5])}, "n": commits(t, k[6], reserveFor(k[6]))},
		"old_root": map[string]any{"k": []string{verkeyOf(k[1])}, "n": commits(t, k[2], reserveFor(k[2])),
			"after": map[string]string{"s": "0", "d": b.oldAID}},
	})
	if code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(out), "owner") {
		t.Fatalf("a new root naming no owner was prepared by a core that requires one: %d %v", code, out)
	}
}

// A new root anchoring messaging keys this Identity Agent does not hold is
// refused, as an ordinary founding is, before anything is written.
func TestBreakGlassRefusesANewRootAnchoringKeysNobodyHolds(t *testing.T) {
	ks, err := didcomm.DeriveKeySet("", bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := ks.Anchor()
	if err != nil {
		t.Fatal(err)
	}
	b := aRootToBreakGlassWith(t, breakGlassSetup{newRoot: map[string]any{"a": []any{anchor}}})
	code, out := b.rotate(t)
	if code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(out), "messaging_keyset_not_held") {
		t.Fatalf("answered %d %v", code, out)
	}
	b.nothingWritten(t)
}

func (b *brokenGlass) nothingWritten(t *testing.T) {
	t.Helper()
	if evs, _ := b.s.DataStore.GetEvents(newRootOf(b)); len(evs) != 0 {
		t.Fatalf("%d event(s) of the new root were written", len(evs))
	}
	if evs, _ := b.s.DataStore.GetEvents(b.oldAID); len(evs) != b.preparedWhenLogWas {
		t.Fatalf("the old root's log is %d events, was %d", len(evs), b.preparedWhenLogWas)
	}
	if own, _ := b.s.DataStore.GetIdentity(); own == nil || own.AID != b.oldAID {
		t.Fatalf("the identity kept here moved: %+v", own)
	}
}

// The old root's witnesses may be down when the rotation is committed. The
// identity kept here is the new root by then, so the retry that brings the
// identity's witnesses up to date has to reach the old root as well, however
// late the witness is back, and after a restart.
func TestTheOldRootsWitnessesHearOfTheRotationWhenTheyAreBackUp(t *testing.T) {
	w := newWitness()
	b, _ := foundedWitnessed(t, w, map[string]any{"owner_aid": anOwner})
	newAID := newRootOf(b)
	eventually(t, "the old root's founding reaches its witness", func() bool { return w.holds(b.oldAID) == 1 })

	w.setDown(true)
	if code, out := b.rotate(t); code != http.StatusOK {
		t.Fatalf("break-glass: %d %v", code, out)
	}
	// Whatever the commit sent in the background has failed; and the agent
	// restarts, so nothing remembers there was something to send.
	time.Sleep(300 * time.Millisecond)
	restart(b)
	if w.holds(b.oldAID) != 1 || w.holds(newAID) != 0 {
		t.Fatalf("the witness holds %d of the old root and %d of the new while down", w.holds(b.oldAID), w.holds(newAID))
	}

	w.setDown(false)
	b.s.tick()
	eventually(t, "the rotation reaches the old root's witness", func() bool { return w.holds(b.oldAID) == 2 })
	eventually(t, "the new root reaches its witness", func() bool { return w.holds(newAID) == 2 })
}

// The request is bound to a real recovery session, and to a size.
func TestBreakGlassIsBoundToARealSessionAndASize(t *testing.T) {
	t.Run("an unknown session", func(t *testing.T) {
		b := aRootToBreakGlassOn(t)
		b.req["recovery_session_id"] = "00000000-0000-0000-0000-000000000000"
		code, out := b.rotate(t)
		if code != http.StatusNotFound {
			t.Fatalf("answered %d %v", code, out)
		}
		b.nothingWritten(t)
	})
	t.Run("no session", func(t *testing.T) {
		b := aRootToBreakGlassOn(t)
		b.req["recovery_session_id"] = ""
		if code, out := b.rotate(t); code != http.StatusBadRequest {
			t.Fatalf("answered %d %v", code, out)
		}
		b.nothingWritten(t)
	})
	t.Run("a body past the bound", func(t *testing.T) {
		b := aRootToBreakGlassOn(t)
		b.req["padding"] = strings.Repeat("A", maxRootRotationBody)
		code, out := b.rotate(t)
		if code != http.StatusBadRequest {
			t.Fatalf("answered %d %v", code, out)
		}
		b.nothingWritten(t)
		delete(b.req, "padding")
		if code, out := b.rotate(t); code != http.StatusOK {
			t.Fatalf("the same request within the bound: %d %v", code, out)
		}
	})
}
