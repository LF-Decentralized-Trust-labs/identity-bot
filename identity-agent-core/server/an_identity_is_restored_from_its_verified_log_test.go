package server

import (
	"encoding/base64"
	"net/http"
	"testing"
)

// A key log is installed on a new core only once the whole chain verifies; one
// bad signature anywhere and nothing is installed. Installed, it is extended by
// the app that holds the key, with no seed given to the core.
func TestAnIdentityIsRestoredOnlyFromALogThatVerifies(t *testing.T) {
	first := appHeldCore(t)
	k := appSeeds(3)
	_, out := call(t, first, first.handlePrepareEvent, "/api/events/prepare", map[string]any{
		"t": "icp", "k": []string{verkeyOf(k[0])}, "kt": "1", "n": []string{digestOfSeed(t, k[1])}, "nt": "1"})
	icp := preparedBytes(t, out)
	icpSig := appSign(t, k[0], icp, true)
	call(t, first, first.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(icp), "sigs": []string{icpSig}})
	own, _ := first.DataStore.GetIdentity()
	_, out = call(t, first, first.handlePrepareEvent, "/api/events/prepare", map[string]any{"aid": own.AID, "t": "rot",
		"k": []string{verkeyOf(k[1])}, "kt": "1", "n": []string{digestOfSeed(t, k[2])}, "nt": "1",
		"after": map[string]string{"s": "0", "d": own.AID}})
	rot := preparedBytes(t, out)
	rotSig := appSign(t, k[1], rot, true)
	_, res := call(t, first, first.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(rot), "sigs": []string{rotSig}})

	logWith := func(rs string) map[string]any {
		return map[string]any{"aid": own.AID, "events": []map[string]any{
			{"raw_b64": base64.StdEncoding.EncodeToString(icp), "sigs": []string{icpSig}},
			{"raw_b64": base64.StdEncoding.EncodeToString(rot), "sigs": []string{rs}},
		}}
	}
	fresh := appHeldCore(t)
	if code, _ := call(t, fresh, fresh.handleRestoreIdentity, "/api/identity/restore",
		logWith(appSign(t, k[0], rot, true))); code != http.StatusUnprocessableEntity {
		t.Fatalf("a log with a bad signature was answered %d", code)
	}
	if id, _ := fresh.DataStore.GetIdentity(); id != nil {
		t.Fatal("a log that does not verify was installed")
	}
	// A copy carrying a signature that verifies nothing beside the good one
	// is installed with the good one alone.
	junky := logWith(rotSig)
	junky["events"].([]map[string]any)[1]["sigs"] = []string{rotSig, appSign(t, k[2], rot, true)}
	if code, out := call(t, fresh, fresh.handleRestoreIdentity, "/api/identity/restore", junky); code != http.StatusCreated {
		t.Fatalf("a sound log was answered %d %v", code, out)
	}
	if evs, _ := fresh.DataStore.GetEvents(own.AID); len(evs) != 2 || len(evs[1].ControllerSignatures()) != 1 {
		t.Fatalf("the restored rotation holds %v", evs[1].ControllerSignatures())
	}

	_, out = call(t, fresh, fresh.handlePrepareEvent, "/api/events/prepare", map[string]any{"aid": own.AID,
		"t": "ixn", "a": []any{map[string]string{"d": "EAfterRestore"}},
		"after": map[string]string{"s": "1", "d": res["d"].(string)}})
	ixn := preparedBytes(t, out)
	if code, out := call(t, fresh, fresh.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(ixn), "sigs": []string{appSign(t, k[1], ixn, false)}}); code != http.StatusCreated {
		t.Fatalf("the restored identity could not be extended: %d %v", code, out)
	}
}
