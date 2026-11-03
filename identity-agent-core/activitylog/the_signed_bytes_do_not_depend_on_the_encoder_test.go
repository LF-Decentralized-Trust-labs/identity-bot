package activitylog_test

import (
	"encoding/json"
	"strings"
	"testing"

	"identity-agent-core/activitylog"
)

// The bytes a signature covers are what json.Marshal writes for the event, so
// they are fixed here, spelled out, for the characters an encoder is free to
// treat differently: the HTML characters, the line and paragraph separators,
// the replacement character itself, a character outside the Basic
// Multilingual Plane, a control character, a quote, and the cost's number in
// its large and small forms.
//
// A Go release that spells any of these differently changes what every new row
// is signed over while the rows already written keep the old spelling (their
// kept signed bytes are what they verify against). This test fails on that
// release, so the change is seen and answered, here, before a signature is
// made over bytes nobody expected. Invalid UTF-8 is not listed because no
// event carries it: every string is made valid before it is signed
// (TestEveryStringOfAnEventIsMadeValidUTF8).
func TestTheBytesAnEventIsSignedOverAreTheSameOnEveryGoRelease(t *testing.T) {
	ev := activitylog.InvocationEvent{
		TS:           "2026-07-31T00:00:00Z",
		CapabilityID: "v.one",
		ResultStatus: "ok",
		Reason:       "<a href=\"x\">&</a> " + string(rune(0x2028)) + " " + string(rune(0x2029)) + " " + string(rune(0xfffd)) + " " + string(rune(0x1f600)) + " \x01 \\ / é",
		Cost:         &activitylog.Cost{Amount: 1e21, Unit: "u", Basis: "b"},
	}
	got, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.ReplaceAll(`{"ts":"2026-07-31T00:00:00Z","capability_id":"v.one","result_status":"ok","duration_ms":0,"reason":"~u003ca href=\"x\"~u003e~u0026~u003c/a~u003e ~u2028 ~u2029 `+string(rune(0xfffd))+` `+string(rune(0x1f600))+` ~u0001 \\ / é","cost":{"amount":1e+21,"unit":"u","basis":"b"}}`, "~u", `\u`)
	if string(got) != want {
		t.Fatalf("the encoder writes an event differently:\n got  %s\n want %s", got, want)
	}
	ev.Cost.Amount = 1e-7
	got, _ = json.Marshal(ev)
	if want := `"cost":{"amount":1e-7,"unit":"u","basis":"b"}`; !strings.Contains(string(got), want) {
		t.Fatalf("the encoder writes a small number differently: %s", got)
	}
}
