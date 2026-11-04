package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"identity-agent-core/recovery"

	keri "github.com/grapeid/keri-go"
)

// The break-glass root rotation through the core's routes: the app has the
// three events prepared, signs each with the key it needs, and commits them
// in one request. With the switch off the routes answer as they did. The two
// logs it makes are also judged by keripy, as cases of TestKeripyJudges.

func breakGlassOn(t *testing.T) {
	t.Helper()
	prior := recovery.RootAIDRotationEnabled
	recovery.RootAIDRotationEnabled = true
	t.Cleanup(func() { recovery.RootAIDRotationEnabled = prior })
}

type brokenGlass struct {
	s        *CoreServer
	k        [][]byte
	oldAID   string
	prepared map[string]map[string]any
	req      map[string]any
	// preparedWhenLogWas is how long the old root's log was when the
	// rotation was prepared: preparing added nothing to it.
	preparedWhenLogWas int
}

// breakGlassSetup says how the root to break glass on is founded, and what the
// app asks of the new root.
type breakGlassSetup struct {
	oldFounding map[string]any // added to the old root's founding request
	newRoot     map[string]any // added to the prepare request's new_root
	core        func(*CoreServer)
	// between runs after the old root is founded, before the rotation is prepared.
	between func(b *brokenGlass)
	// after, if set, names the event the rotation follows.
	after func(b *brokenGlass) map[string]string
}

// aSession writes a recovery session the way a running agent keeps one, and
// returns its id.
func aSession(t *testing.T, s *CoreServer) string {
	t.Helper()
	id := uuid.New().String()
	dir := filepath.Join(s.DataDir, "recovery_sessions")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"session": map[string]any{"id": id, "state": "pending"},
		"written_at": time.Now().UTC().Format(time.RFC3339)})
	if err := os.WriteFile(filepath.Join(dir, id+".json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return id
}

// aRootToBreakGlassOn founds the old root, app-held, and has the rotation prepared and signed.
// Old keys k[0] (current, "stolen") and k[1] (committed); new root keys k[5], k[6].
func aRootToBreakGlassOn(t *testing.T) *brokenGlass {
	return aRootToBreakGlassWith(t, breakGlassSetup{})
}

func aRootToBreakGlassWith(t *testing.T, opt breakGlassSetup) *brokenGlass {
	t.Helper()
	breakGlassOn(t)
	s := appHeldCore(t)
	if opt.core != nil {
		opt.core(s)
	}
	k := appSeeds(10)
	aid, tip := founding(t, s, k[0], k[1], opt.oldFounding)
	b := &brokenGlass{s: s, k: k, oldAID: aid}
	if opt.between != nil {
		opt.between(b)
	}
	if opt.after != nil {
		tip = opt.after(b)
	}

	newRoot := map[string]any{"k": []string{verkeyOf(k[5])}, "n": commits(t, k[6], reserveFor(k[6]))}
	for name, v := range opt.newRoot {
		newRoot[name] = v
	}
	before, _ := s.DataStore.GetEvents(aid)
	code, out := call(t, s, s.handleRecoveryRootAIDPrepare, "/api/recovery/root-aid-rotation/prepare", map[string]any{
		"new_root": newRoot,
		"old_root": map[string]any{"k": []string{verkeyOf(k[1])}, "n": commits(t, k[2], reserveFor(k[2])),
			"after": tip},
	})
	if code != http.StatusOK {
		t.Fatalf("prepare: %d %v", code, out)
	}
	if after, _ := s.DataStore.GetEvents(aid); len(after) != len(before) {
		t.Fatalf("preparing added an event: the old root's log is %d long, was %d", len(after), len(before))
	}
	prepared := map[string]map[string]any{}
	for _, name := range []string{"new_root_founding", "old_root_rotation", "new_root_interaction"} {
		prepared[name] = out[name].(map[string]any)
	}
	rawOf := func(name string) []byte { return preparedBytes(t, prepared[name]) }
	sig := func(name string, seed []byte, opens bool) map[string]any {
		return map[string]any{"raw_b64": prepared[name]["raw_b64"], "sigs": []string{appSign(t, seed, rawOf(name), opens)}}
	}
	b.prepared = prepared
	b.preparedWhenLogWas = len(before)
	b.req = map[string]any{
		"recovery_session_id":  aSession(t, s),
		"new_root_founding":    sig("new_root_founding", k[5], true),
		"old_root_rotation":    sig("old_root_rotation", k[1], true),
		"new_root_interaction": sig("new_root_interaction", k[5], false),
	}
	return b
}

func (b *brokenGlass) rotate(t *testing.T) (int, map[string]any) {
	return call(t, b.s, b.s.handleRecoveryRootAIDRotation, "/api/recovery/root-aid-rotation", b.req)
}

func TestBreakGlassRotationLogsAreWritten(t *testing.T) {
	b := aRootToBreakGlassOn(t)
	newAID := b.prepared["new_root_founding"]["hint"].(map[string]any)["i"].(string)

	code, out := b.rotate(t)
	if code != http.StatusOK {
		t.Fatalf("break-glass rotation: %d %v", code, out)
	}
	// Every event it wrote verifies, signed, as a log of its own identifier.
	for label, aid := range map[string]string{"old root": b.oldAID, "new root": newAID} {
		m, _ := storedLog(t, b.s, aid)
		if len(m) != 2 {
			t.Fatalf("the %s's log is %d events, want its founding and one more", label, len(m))
		}
		if _, err := keri.ValidateSignedKEL(m); err != nil {
			t.Fatalf("the %s's log does not verify: %v", label, err)
		}
	}
	own, err := b.s.DataStore.GetIdentity()
	if err != nil || own == nil || own.AID != newAID || own.EventCount != 2 {
		t.Fatalf("the identity kept here is %+v, want the new root at 2 events", own)
	}
	if out["new_root_aid"] != newAID || out["old_root_aid"] != b.oldAID {
		t.Fatalf("answer %v", out)
	}
	// The rotation took the old root's pre-committed key: it carries both next-key digests.
	var rot struct {
		N  []string `json:"n"`
		Nt string   `json:"nt"`
		A  []struct {
			D string `json:"d"`
		} `json:"a"`
	}
	_ = json.Unmarshal(preparedBytes(t, b.prepared["old_root_rotation"]), &rot)
	if len(rot.N) != 2 || rot.Nt != "1" || len(rot.A) != 1 || rot.A[0].D != b.prepared["new_root_founding"]["hint"].(map[string]any)["d"] {
		t.Fatalf("the rotation is %+v", rot)
	}
}

// With any of the three events unsigned the whole is refused, and nothing is
// written: not the founding, not the rotation, and the identity stays the old root.
func TestBreakGlassRotationWithAnUnsignedEventWritesNothing(t *testing.T) {
	for _, name := range []string{"new_root_founding", "old_root_rotation", "new_root_interaction"} {
		t.Run(name, func(t *testing.T) {
			b := aRootToBreakGlassOn(t)
			ev := b.req[name].(map[string]any)
			ev["sigs"] = []string{}
			code, out := b.rotate(t)
			if code != http.StatusUnprocessableEntity || !strings.Contains(out["details"].(string), name+" is not signed") {
				t.Fatalf("answered %d %v", code, out)
			}
			newAID := b.prepared["new_root_founding"]["hint"].(map[string]any)["i"].(string)
			if evs, _ := b.s.DataStore.GetEvents(newAID); len(evs) != 0 {
				t.Fatalf("%d event(s) of the new root were written", len(evs))
			}
			if evs, _ := b.s.DataStore.GetEvents(b.oldAID); len(evs) != 1 {
				t.Fatalf("the old root's log is %d events, was 1", len(evs))
			}
			if own, _ := b.s.DataStore.GetIdentity(); own == nil || own.AID != b.oldAID {
				t.Fatalf("the identity kept here moved: %+v", own)
			}
		})
	}
}

// A default build is unchanged: with the switch off, neither route prepares or
// commits anything, and answers as it did before.
func TestBreakGlassRoutesAreClosedWithTheSwitchOff(t *testing.T) {
	s := appHeldCore(t)
	k := appSeeds(2)
	aid, _ := founding(t, s, k[0], k[1], nil)
	if recovery.RootAIDRotationEnabled {
		t.Fatal("the switch is on by default")
	}
	for path, h := range map[string]http.HandlerFunc{
		"/api/recovery/root-aid-rotation":         s.handleRecoveryRootAIDRotation,
		"/api/recovery/root-aid-rotation/prepare": s.handleRecoveryRootAIDPrepare,
	} {
		rec := httptest.NewRecorder()
		h(rec, ownerRequest(http.MethodPost, path, strings.NewReader(`{}`), s))
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "gated pending security review") {
			t.Fatalf("%s answered %d %s", path, rec.Code, rec.Body.String())
		}
	}
	if evs, _ := s.DataStore.GetEvents(aid); len(evs) != 1 {
		t.Fatal("a closed route wrote an event")
	}
}
