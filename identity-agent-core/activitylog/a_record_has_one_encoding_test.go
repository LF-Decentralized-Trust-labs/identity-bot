package activitylog_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"identity-agent-core/activitylog"
	"identity-agent-core/activitylog/activitylogtest"
)

// A record is read only in the encoding this log writes it in. The link to a
// record is the hash of its text, and a row written before the signed bytes
// were kept is checked by encoding its event again, so a record respaced or
// re-escaped kept its signature while its hash changed: one event, many
// records, and the last row of a log could be swapped for another of them
// without a fault.
func TestARecordInAnotherEncodingFails(t *testing.T) {
	for name, respell := range map[string]func(string) string{
		"spaced":     func(s string) string { return strings.Replace(s, `":`, `": `, 1) },
		"re-escaped": func(s string) string { return strings.Replace(s, `"g.one"`, "\"g\\u002eone\"", 1) },
	} {
		t.Run(name, func(t *testing.T) {
			store := activitylog.NewTestLog(t)
			ts := activitylogtest.NewSigner(t)
			appendChained(t, store, ts, "g.one")
			if broken, why, err := verifyFirst(store, ts.Keys, nil); err != nil || broken != 0 {
				t.Fatalf("the row as written should verify, got %d (%s) err=%v", broken, why, err)
			}
			stored, err := activitylog.EventJSON(store, 1)
			if err != nil {
				t.Fatal(err)
			}
			other := respell(string(stored))
			if other == string(stored) {
				t.Fatal("the respelling changed nothing")
			}
			var a, b activitylog.InvocationEvent
			if json.Unmarshal(stored, &a) != nil || json.Unmarshal([]byte(other), &b) != nil || !reflect.DeepEqual(a, b) {
				t.Fatal("the respelled record should read as the same event")
			}
			if _, err := store.DB().Exec(`UPDATE invocation_log SET event_json = ? WHERE id = 1`, other); err != nil {
				t.Fatal(err)
			}
			if broken, _, err := verifyFirst(store, ts.Keys, nil); err != nil || broken == 0 {
				t.Fatalf("a record in another encoding verified (err %v)", err)
			}
		})
	}
}

// A row handed out with its signed bytes is held to the same rule: the bytes
// still say what the record says, and the record is still another string.
func TestAHandedOutRowInAnotherEncodingFails(t *testing.T) {
	store, k := newLoggingLog(t)
	activitylogtest.WriteEvents(t, store, "h.one")
	rows, err := store.StoredRows(1, 1)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows: %v %v", rows, err)
	}
	if _, why, err := activitylog.CheckStoredRow(rows[0], k.Keys); err != nil || why != "" {
		t.Fatalf("the row as kept should hold, got %q err=%v", why, err)
	}
	rows[0].Record = strings.Replace(rows[0].Record, `":`, `": `, 1)
	if _, why, err := activitylog.CheckStoredRow(rows[0], k.Keys); err != nil || why == "" {
		t.Fatalf("a handed-out record in another encoding held (err %v)", err)
	}
}
