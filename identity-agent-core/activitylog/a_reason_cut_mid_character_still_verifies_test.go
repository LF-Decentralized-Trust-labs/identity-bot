package activitylog_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"identity-agent-core/activitylog"
	"identity-agent-core/activitylog/activitylogtest"
	"identity-agent-core/permission"
)

// escapedBadByte is how the JSON encoder writes a byte that is not UTF-8.
const escapedBadByte = `\ufffd`

// An honest caller's reason, cut at 512 bytes in the middle of a multi-byte
// character, is written through the real path and then verified. The encoder
// writes the stray byte as the escape \ufffd, which reads back as the
// replacement character and encodes again raw, so a record held to "the
// encoding of the event it reads as" faulted an honest row.
func TestAReasonCutMidCharacterVerifies(t *testing.T) {
	store, k := newLoggingLog(t)
	reason := (strings.Repeat("a", 511) + "é")[:512] // byte 512 is the first half of é
	if store.RecordGovernanceEvent(permission.CallerContext{CallerAID: "EAgent", Reason: reason}, "u.one", "ok") == 0 {
		t.Fatal("not written")
	}
	if store.RecordGovernanceEvent(permission.CallerContext{CallerAID: "EAgent", Reason: "fine"}, "u.two", "ok") == 0 {
		t.Fatal("not written")
	}
	faults, err := store.VerifyChain(k.Keys, nil)
	if err != nil || len(faults) != 0 {
		t.Fatalf("an honest row faults: %v %v", faults, err)
	}
	stored, err := activitylog.EventJSON(store, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.Valid(stored) || strings.Contains(string(stored), escapedBadByte) {
		t.Fatalf("a new row was written with invalid UTF-8 escaped: %s", stored)
	}
}

// A row written before invalid UTF-8 was replaced on the way in carries the
// escape \ufffd in both its record and its kept signed bytes. It still
// verifies, because the record is checked against the kept bytes, which the
// signature fixes; and since the kept bytes are fixed, so is the record. The
// same row with the escape respelled as the character itself fails.
func TestARowWrittenWithAnEscapedBadByteVerifiesInItsOneSpelling(t *testing.T) {
	store := activitylog.NewTestLog(t)
	ts := activitylogtest.NewSigner(t)
	prev, _ := store.LastEventHash()
	unsigned := activitylog.InvocationEvent{TS: "2026-07-31T00:00:00Z", CapabilityID: "v.one", ResultStatus: "ok",
		Reason: "cut mid character \xc3", PrevHash: prev}
	payload, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), escapedBadByte) {
		t.Fatalf("the encoder no longer escapes a bad byte, so this test tests nothing: %s", payload)
	}
	ev := ts.Sign(unsigned)
	ev.SignedPayload = string(payload)
	if _, err := store.InsertInvocationEvent(ev); err != nil {
		t.Fatal(err)
	}
	if faults, err := store.VerifyChain(ts.Keys, nil); err != nil || len(faults) != 0 {
		t.Fatalf("a row written with an escaped bad byte faults: %v %v", faults, err)
	}
	rows, err := store.StoredRows(1, 1)
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	if _, why, err := activitylog.CheckStoredRow(rows[0], ts.Keys); err != nil || why != "" {
		t.Fatalf("handed out, the row fails: %q %v", why, err)
	}

	raw := strings.Replace(rows[0].Record, escapedBadByte, string(utf8.RuneError), 1)
	if _, err := store.DB().Exec(`UPDATE invocation_log SET event_json = ? WHERE id = 1`, raw); err != nil {
		t.Fatal(err)
	}
	if faults, err := store.VerifyChain(ts.Keys, nil); err != nil || len(faults) == 0 {
		t.Fatalf("the record respelled with the character itself verified (err %v)", err)
	}
	rows[0].Record = raw
	if _, why, _ := activitylog.CheckStoredRow(rows[0], ts.Keys); why == "" {
		t.Fatal("handed out, the respelled record held")
	}
}

// Every string an event carries is made valid UTF-8 before it is written,
// including any string field added later to the event or to its cost: this
// sets each one to a bad byte by reflection and fails on any that comes back
// with one.
func TestEveryStringOfAnEventIsMadeValidUTF8(t *testing.T) {
	var ev activitylog.InvocationEvent
	spoil(t, reflect.ValueOf(&ev).Elem())
	out, err := json.Marshal(activitylog.WithValidUTF8(ev))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), escapedBadByte) {
		t.Fatalf("a string was left with invalid UTF-8: %s", out)
	}
	if ev.Cost == nil || ev.Cost.Unit != "\xff" {
		t.Fatal("the event given was changed, not copied")
	}
}

// spoil sets every string reachable from v to a byte that is not UTF-8,
// following slices and pointers to structs, and fails on a kind it cannot
// fill, so a new kind of field is noticed here.
func spoil(t *testing.T, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.String:
		v.SetString("\xff")
	case reflect.Int64, reflect.Float64, reflect.Bool:
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			spoil(t, v.Field(i))
		}
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		spoil(t, v.Index(0))
	case reflect.Ptr:
		v.Set(reflect.New(v.Type().Elem()))
		spoil(t, v.Elem())
	default:
		t.Fatalf("a field of kind %s is not covered by this test", v.Kind())
	}
}
