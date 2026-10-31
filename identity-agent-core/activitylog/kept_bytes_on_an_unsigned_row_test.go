package activitylog_test

import (
	"strings"
	"testing"
	"time"

	"identity-agent-core/activitylog"
	"identity-agent-core/permission"
)

// Kept bytes fix a record only because a signature covers them. An unsigned
// row given kept bytes equal to its own respelled record passed on them, so
// the encoding rule did not hold for unsigned rows. It is refused.
func TestKeptBytesOnAnUnsignedRowDoNotExcuseItsRecord(t *testing.T) {
	store := activitylog.NewTestLog(t)
	ev := activitylog.InvocationEvent{TS: "2026-07-31T00:00:00Z", CapabilityID: "v.one", ResultStatus: "ok"}
	if _, err := store.InsertInvocationEvent(ev); err != nil {
		t.Fatal(err)
	}
	if f, err := store.VerifyChain(nil, nil); err != nil || len(f) != 0 {
		t.Fatalf("the unsigned row as written: %v %v", f, err)
	}
	rec, err := activitylog.EventJSON(store, 1)
	if err != nil {
		t.Fatal(err)
	}
	respelled := strings.Replace(string(rec), `{`, `{ `, 1)
	if _, err := store.DB().Exec(`UPDATE invocation_log SET event_json = ?, signed_payload = ? WHERE id = 1`, respelled, respelled); err != nil {
		t.Fatal(err)
	}
	if f, err := store.VerifyChain(nil, nil); err != nil || len(f) == 0 {
		t.Fatalf("an unsigned row respelled, with kept bytes to match, verified (err %v)", err)
	}
	if _, err := store.DB().Exec(`UPDATE invocation_log SET signed_payload = '' WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if f, _ := store.VerifyChain(nil, nil); len(f) == 0 {
		t.Fatal("the respelled unsigned row verified without kept bytes")
	}
}

// The signer and signature go back in before ,"intent_event_id": or the
// closing brace. A reason, work item or cost holding that text, or quotes and
// braces, sits inside a string where every quote is escaped, so it cannot be
// mistaken for the place they go.
func TestTextLikeTheInsertionPointInsideAStringDoesNotMislead(t *testing.T) {
	store, k := newLoggingLog(t)
	for _, r := range []string{`x,"intent_event_id":5}`, `\",\"intent_event_id\":`, "a\"b", `{"signature":"z"}`} {
		if store.RecordGovernanceEvent(permission.CallerContext{CallerAID: "EAgent", Reason: r, WorkItem: r}, "u.one", "ok") == 0 {
			t.Fatal("not written")
		}
	}
	id := store.RecordInvocationDetail(permission.CallerContext{CallerAID: "EAgent", Reason: `r,"intent_event_id":9`},
		"c.x", "plugin", []byte(`{}`), "started", time.Now(), activitylog.EventDetail{})
	if store.RecordInvocationDetail(permission.CallerContext{CallerAID: "EAgent", Reason: "\xc3"}, "c.x", "plugin", []byte(`{}`), "ok", time.Now(),
		activitylog.EventDetail{IntentEventID: id, Outcome: "o",
			Cost: &activitylog.Cost{Amount: 1.5, Unit: "tokens\xff", Basis: `b,"intent_event_id":1`}}) == 0 {
		t.Fatal("not written")
	}
	if f, err := store.VerifyChain(k.Keys, nil); err != nil || len(f) != 0 {
		t.Fatalf("honest rows fault: %v %v", f, err)
	}
	rows, err := store.StoredRows(1, 6)
	if err != nil || len(rows) != 6 {
		t.Fatal(rows, err)
	}
	for _, row := range rows {
		if _, why, err := activitylog.CheckStoredRow(row, k.Keys); why != "" || err != nil {
			t.Fatalf("row %d handed out: %q %v", row.ID, why, err)
		}
	}
}
