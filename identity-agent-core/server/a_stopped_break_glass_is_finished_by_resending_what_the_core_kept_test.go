package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/store"
)

func (b *brokenGlass) status(t *testing.T, owner bool) map[string]any {
	t.Helper()
	var r *http.Request
	if owner {
		r = ownerRequest(http.MethodGet, "/api/recovery/root-aid-rotation/status", nil, b.s)
	} else {
		r = httptest.NewRequest(http.MethodGet, "/api/recovery/root-aid-rotation/status", nil)
	}
	rec := httptest.NewRecorder()
	b.s.handleRecoveryRootAIDStatus(rec, r)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	return out
}

func (b *brokenGlass) prepareAnotherAfter(t *testing.T, after map[string]any) (int, map[string]any) {
	k := b.k
	return call(t, b.s, b.s.handleRecoveryRootAIDPrepare, "/api/recovery/root-aid-rotation/prepare", map[string]any{
		"new_root": map[string]any{"k": []string{verkeyOf(k[7])}, "n": commits(t, k[8], reserveFor(k[8]))},
		"old_root": map[string]any{"k": []string{verkeyOf(k[2])}, "n": commits(t, k[3], reserveFor(k[3])), "after": after},
	})
}

// A run stopped after the old root's rotation was added: the core keeps the
// signed request and offers it back to the owner, and prepares no second run
// on top of the first (which would leave two roots the old log authorises).
// The kept request, sent again, finishes the run, and nothing is kept after.
func TestAStoppedBreakGlassIsFinishedByTheRequestTheCoreKept(t *testing.T) {
	b := aRootToBreakGlassWith(t, breakGlassSetup{})
	st := &stopsAtStore{Store: b.s.DataStore}
	b.s.DataStore = st
	newAID := newRootOf(b)
	st.identity = func(id store.IdentityState) bool { return id.AID == newAID && id.EventCount == 1 }
	if code, out := b.rotate(t); code != http.StatusUnprocessableEntity {
		t.Fatalf("the stop was not reported: %d %v", code, out)
	}
	// The app loses its copy of the request it sent.

	// Offered back to the owner, and to nobody else.
	unfinished, _ := b.status(t, true)["unfinished"].([]any)
	if len(unfinished) != 1 {
		t.Fatalf("the owner is offered %d unfinished runs, want 1", len(unfinished))
	}
	run := unfinished[0].(map[string]any)
	if run["old_root_aid"] != b.oldAID || run["new_root_aid"] != newAID {
		t.Fatalf("the unfinished run is %v", run)
	}
	if _, offered := b.status(t, false)["unfinished"]; offered {
		t.Fatal("the signed request was offered to a caller that is not the owner")
	}

	// A second run on the half-finished one is refused, saying to resend.
	rotA := b.prepared["old_root_rotation"]["hint"].(map[string]any)
	code, out := b.prepareAnotherAfter(t, map[string]any{"s": rotA["s"], "d": rotA["d"]})
	if code != http.StatusConflict || !strings.Contains(out["details"].(string), "Send the same signed request again") {
		t.Fatalf("a second prepare on an unfinished run was answered %d %v", code, out)
	}

	// The request the core kept finishes it.
	b.req = run["request"].(map[string]any)
	if code, out := b.rotate(t); code != http.StatusOK {
		t.Fatalf("the kept request did not finish the run: %d %v", code, out)
	}
	if left, _ := b.status(t, true)["unfinished"].([]any); len(left) != 0 {
		t.Fatalf("a finished run is still kept: %v", left)
	}
	if own, _ := b.s.DataStore.GetIdentity(); own.AID != newAID {
		t.Fatalf("the identity kept is %s, not the new root", own.AID)
	}
}

// A run stopped before the old root's rotation landed has authorised nothing,
// so it does not block the identity: a new prepare drops it and goes ahead.
// Only a run whose rotation is in the old root's log must be finished.
func TestABreakGlassWhoseRotationNeverLandedDoesNotBlockAnother(t *testing.T) {
	b := aRootToBreakGlassWith(t, breakGlassSetup{})
	st := &stopsAtStore{Store: b.s.DataStore}
	b.s.DataStore = st
	st.event = func(rec store.EventRecord) bool { return rec.AID == b.oldAID && rec.EventType == "rot" }
	if code, out := b.rotate(t); code == http.StatusOK {
		t.Fatalf("the stop was not reported: %d %v", code, out)
	}
	if evs, _ := b.s.DataStore.GetEvents(b.oldAID); len(evs) != 1 {
		t.Fatalf("the old root's log is %d events; the rotation should not have landed", len(evs))
	}
	if left, _ := b.status(t, true)["unfinished"].([]any); len(left) != 1 {
		t.Fatalf("the stopped run is not kept: %v", left)
	}

	// A fresh prepare after the old root's founding, revealing the key the
	// founding committed to (k[1]) and a new root of its own, is answered.
	k := b.k
	code, out := call(t, b.s, b.s.handleRecoveryRootAIDPrepare, "/api/recovery/root-aid-rotation/prepare", map[string]any{
		"new_root": map[string]any{"k": []string{verkeyOf(k[7])}, "n": commits(t, k[8], reserveFor(k[8]))},
		"old_root": map[string]any{"k": []string{verkeyOf(k[1])}, "n": commits(t, k[2], reserveFor(k[2])),
			"after": map[string]any{"s": "0", "d": b.oldAID}},
	})
	if code != http.StatusOK {
		t.Fatalf("a run whose rotation never landed blocked another: %d %v", code, out)
	}
	if left, _ := b.status(t, true)["unfinished"].([]any); len(left) != 0 {
		t.Fatalf("the run that authorised nothing is still kept: %v", left)
	}
}

// A run whose rotation landed is still judged landed when the request spelled
// the same bytes in another base64 form (a line break the decoder ignores):
// "landed" is decided by the event's digest, not its text, so a second run
// that would leave two roots is refused.
func TestALandedBreakGlassIsRecognisedWhateverItsBase64Spelling(t *testing.T) {
	b := aRootToBreakGlassOn(t)
	rot := b.req["old_root_rotation"].(map[string]any)
	r := rot["raw_b64"].(string)
	rot["raw_b64"] = r[:76] + "\n" + r[76:]
	st := &stopsAtStore{Store: b.s.DataStore}
	b.s.DataStore = st
	newAID := newRootOf(b)
	st.identity = func(id store.IdentityState) bool { return id.AID == newAID && id.EventCount == 1 }
	if code, out := b.rotate(t); code == http.StatusOK {
		t.Fatalf("the stop was not reported: %d %v", code, out)
	}
	if evs, _ := b.s.DataStore.GetEvents(b.oldAID); len(evs) != 2 {
		t.Fatalf("the old root's log is %d events; the rotation should have landed", len(evs))
	}
	rotA := b.prepared["old_root_rotation"]["hint"].(map[string]any)
	if code, out := b.prepareAnotherAfter(t, map[string]any{"s": rotA["s"], "d": rotA["d"]}); code != http.StatusConflict {
		t.Fatalf("a second run on a landed one was answered %d %v", code, out)
	}
	if left, _ := b.status(t, true)["unfinished"].([]any); len(left) != 1 {
		t.Fatalf("the landed run was dropped: %v", left)
	}
}
