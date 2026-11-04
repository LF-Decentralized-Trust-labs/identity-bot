package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// breakGlassWithMessagingKeys is a break-glass whose app handed over a
// messaging seed while the old root was kept here, so the keyset waits as the
// old root's replacement, and whose new root anchors it.
func breakGlassWithMessagingKeys(t *testing.T, opt breakGlassSetup) (*brokenGlass, map[string]any) {
	t.Helper()
	var anchor map[string]any
	newRoot := map[string]any{}
	for k, v := range opt.newRoot {
		newRoot[k] = v
	}
	opt.newRoot = newRoot
	between := opt.between
	opt.between = func(b *brokenGlass) {
		if between != nil {
			between(b)
		}
		code, out := call(t, b.s, b.s.handleMessagingSeed, "/api/keystore/messaging-seed", map[string]any{"seed_hex": messagingSeedHex(7)})
		if code != http.StatusOK {
			t.Fatalf("messaging seed: %d %v", code, out)
		}
		anchor = out["anchor"].(map[string]any)
		newRoot["a"] = []any{anchor}
	}
	b := aRootToBreakGlassWith(t, opt)
	return b, anchor
}

func (b *brokenGlass) keysFiledUnder(label string) bool {
	has, _ := b.s.hasKeySet(label)
	return has
}

// A request the checks refuse writes nothing, the messaging keys it would have
// handed to the new root included; and one that finishes leaves the keys with
// the new root alone, with no copy waiting and no replacement held for the old
// root, however often it is sent again.
func TestARefusedBreakGlassWritesNoCopyOfTheMessagingKeys(t *testing.T) {
	b, anchor := breakGlassWithMessagingKeys(t, breakGlassSetup{})
	newAID := newRootOf(b)
	pending, replacement := pendingKeySetLabel(anchor), pendingReplacementLabel(b.oldAID)
	if !b.keysFiledUnder(replacement) {
		t.Fatal("the keys handed over are not held as the old root's replacement")
	}

	good := b.req["new_root_interaction"]
	b.req["new_root_interaction"] = map[string]any{"raw_b64": good.(map[string]any)["raw_b64"], "sigs": []string{}}
	if code, out := b.rotate(t); code != http.StatusUnprocessableEntity {
		t.Fatalf("an unsigned interaction was answered %d %v", code, out)
	}
	if b.keysFiledUnder(pending) {
		t.Fatal("a refused request left a copy of the messaging keys waiting for the new root")
	}
	if !b.keysFiledUnder(replacement) {
		t.Fatal("a refused request took away the old root's replacement")
	}
	b.nothingWritten(t)

	b.req["new_root_interaction"] = good
	for i := 0; i < 2; i++ { // and sent again once it is finished
		if code, out := b.rotate(t); code != http.StatusOK {
			t.Fatalf("break-glass %d: %d %v", i, code, out)
		}
		if held, _ := b.s.keySetAnchorHeld(newAID, anchor); !held {
			t.Fatal("the new root does not hold the messaging keys it anchors")
		}
		if b.keysFiledUnder(pending) {
			t.Fatalf("send %d left the copy waiting for a founding that is done", i)
		}
		if b.keysFiledUnder(replacement) {
			t.Fatalf("send %d left the old root's replacement held after the new root's keys were filed", i)
		}
	}
}

// The new root's founding gate at commit is the founding gate itself: a core
// that requires an owner refuses a new root that names none, even if it was
// prepared before the requirement, and nothing is written.
func TestBreakGlassCommitAppliesTheFoundingGate(t *testing.T) {
	b := aRootToBreakGlassOn(t)
	b.s.requireOwnerAtInception = true
	code, out := b.rotate(t)
	if code != http.StatusBadRequest {
		t.Fatalf("a new root naming no owner was committed by a core that requires one: %d %v", code, out)
	}
	b.nothingWritten(t)
}

// A founding is made one at a time: the rotation waits for any other that
// holds the founding lock, as /api/events/commit does for an inception.
func TestBreakGlassFoundsTheNewRootUnderTheFoundingLock(t *testing.T) {
	b := aRootToBreakGlassOn(t)
	b.s.founding.Lock()
	done := make(chan int, 1)
	go func() {
		code, _ := b.rotate(t)
		done <- code
	}()
	select {
	case code := <-done:
		b.s.founding.Unlock()
		t.Fatalf("the rotation went on while another founding held the lock (answered %d)", code)
	case <-time.After(300 * time.Millisecond):
	}
	b.s.founding.Unlock()
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("answered %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the rotation never went on")
	}
}

// The new root inherits the old root's owner as it inherits its witnesses: an
// owned identity is not quietly un-owned by a break-glass whose app names no
// owner, on a core that does not require one. An owner the app names is kept.
func TestBreakGlassKeepsTheOwnerOfAnOwnedIdentity(t *testing.T) {
	const another = "EAnotherOwnerOfTheRoot0000000000000000000000"
	for _, c := range []struct {
		name  string
		asks  map[string]any
		owner string
	}{
		{"the app names none", nil, anOwner},
		{"the app names another", map[string]any{"owner_aid": another}, another},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := aRootToBreakGlassWith(t, breakGlassSetup{
				oldFounding: map[string]any{"owner_aid": anOwner}, newRoot: c.asks})
			raw := preparedBytes(t, b.prepared["new_root_founding"])
			if got := ownerNamedIn(raw); got != c.owner {
				var ev map[string]any
				_ = json.Unmarshal(raw, &ev)
				t.Fatalf("the new root names owner %q, want %q (anchors %v)", got, c.owner, ev["a"])
			}
			if code, out := b.rotate(t); code != http.StatusOK {
				t.Fatalf("break-glass: %d %v", code, out)
			}
		})
	}
}
