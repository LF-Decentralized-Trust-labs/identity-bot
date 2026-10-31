package activitylog_test

import (
	"strings"
	"testing"

	"identity-agent-core/activitylog"
	"identity-agent-core/activitylog/activitylogtest"
)

// A record's signature is read in its one canonical string. 64 bytes in
// unpadded base64url leave 4 spare bits in the last character; read
// leniently, each signature had 16 strings that all verified.
func TestARecordWhoseSignatureIsRespelledFails(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	store := activitylog.NewTestLog(t)
	ts := activitylogtest.NewSigner(t)
	prev, _ := store.LastEventHash()
	ev := ts.Sign(activitylog.InvocationEvent{TS: "2026-07-31T00:00:00Z", CapabilityID: "f.one", ResultStatus: "ok", PrevHash: prev})
	last := len(ev.Signature) - 1
	v := strings.IndexByte(alphabet, ev.Signature[last])
	ev.Signature = ev.Signature[:last] + string(alphabet[v|1])
	if _, err := store.InsertInvocationEvent(ev); err != nil {
		t.Fatal(err)
	}
	if broken, _, err := verifyFirst(store, ts.Keys, nil); err != nil || broken == 0 {
		t.Fatalf("a record whose signature was respelled verified (err %v)", err)
	}
}
