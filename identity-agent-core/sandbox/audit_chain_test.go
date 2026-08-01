package sandbox

import (
	"encoding/json"
	"strings"
	"testing"
)

func newTestSandboxStore(t *testing.T) *SandboxStore {
	t.Helper()
	store, err := NewSandboxStore(t.TempDir())
	if err != nil {
		t.Fatalf("open sandbox store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// ── argument preview ────────────────────────────────────────────────────────
//
// The preview exists so a person reading the log can see what a capability was
// asked to do. That is only safe if it cannot become a place secrets come to rest,
// which is what these tests pin.

func TestPreviewArgsRedactsSecretsByKey(t *testing.T) {
	cases := []struct {
		name string
		args string
		want string // substring that must appear
		deny string // substring that must NOT appear
	}{
		{"api_key", `{"api_key":"ghp_realtokenvalue"}`, "api_key=[redacted]", "ghp_realtokenvalue"},
		{"password", `{"password":"hunter2"}`, "password=[redacted]", "hunter2"},
		{"authorization", `{"authorization":"Bearer abc"}`, "authorization=[redacted]", "Bearer abc"},
		{"mixed case", `{"API_Key":"zzz"}`, "API_Key=[redacted]", "zzz"},
		{"embedded", `{"github_token":"zzz"}`, "github_token=[redacted]", "zzz"},
		{"passphrase", `{"passphrase":"correct horse"}`, "passphrase=[redacted]", "correct horse"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := previewArgs([]byte(tc.args))
			if !strings.Contains(got, tc.want) {
				t.Errorf("preview %q: want substring %q", got, tc.want)
			}
			if strings.Contains(got, tc.deny) {
				t.Fatalf("preview LEAKED a secret value: %q", got)
			}
		})
	}
}

func TestPreviewArgsShowsOrdinaryValues(t *testing.T) {
	got := previewArgs([]byte(`{"repo":"strategy","task":"add the linter"}`))
	if !strings.Contains(got, "repo=strategy") || !strings.Contains(got, "task=add the linter") {
		t.Fatalf("ordinary arguments should be readable, got %q", got)
	}
}

func TestPreviewArgsIsStable(t *testing.T) {
	// Two identical calls must read identically in the log, so keys are sorted
	// rather than left in Go's randomised map order.
	args := []byte(`{"z":"1","a":"2","m":"3"}`)
	first := previewArgs(args)
	for i := 0; i < 20; i++ {
		if got := previewArgs(args); got != first {
			t.Fatalf("preview is not stable: %q != %q", got, first)
		}
	}
	if first != "a=2 m=3 z=1" {
		t.Fatalf("want sorted keys, got %q", first)
	}
}

func TestPreviewArgsDoesNotDescendIntoNestedValues(t *testing.T) {
	// A nested object is the likeliest place for a secret to sit under a name the
	// blocklist has never seen, so nothing nested is ever rendered.
	got := previewArgs([]byte(`{"cfg":{"innocuous_name":"sk-live-secret"},"repo":"x"}`))
	if strings.Contains(got, "sk-live-secret") {
		t.Fatalf("preview descended into a nested object and leaked: %q", got)
	}
	if !strings.Contains(got, "cfg=[object]") {
		t.Fatalf("want nested value summarised, got %q", got)
	}
}

func TestPreviewArgsTruncatesAndFlattens(t *testing.T) {
	long := strings.Repeat("a", previewMaxValue+50)
	got := previewArgs([]byte(`{"task":"` + long + `"}`))
	if len(got) > previewMaxValue+40 {
		t.Fatalf("preview not truncated: %d chars", len(got))
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("truncation should be visible, got %q", got)
	}
	multi := previewArgs([]byte(`{"task":"line one\nline two"}`))
	if strings.Contains(multi, "\n") {
		t.Fatalf("preview must stay on one line, got %q", multi)
	}
}

func TestPreviewArgsHandlesNonObjects(t *testing.T) {
	// Not every capability takes a JSON object. Those still get a hash; they just
	// get no preview, which must not panic or produce noise.
	for _, in := range []string{"", "not json at all", `["a","b"]`, `42`} {
		if got := previewArgs([]byte(in)); got != "" {
			t.Errorf("input %q: want empty preview, got %q", in, got)
		}
	}
}

// ── hash chain ──────────────────────────────────────────────────────────────

func TestChainDetectsDeletionAndTampering(t *testing.T) {
	store := newTestSandboxStore(t)

	// Write three chained events the way recordInvocationDetail does.
	var prev string
	for _, cap := range []string{"a.one", "a.two", "a.three"} {
		ev := InvocationEvent{TS: "2026-07-31T00:00:00Z", CapabilityID: cap, ResultStatus: "ok", PrevHash: prev}
		if _, err := store.InsertInvocationEvent(ev); err != nil {
			t.Fatalf("insert %s: %v", cap, err)
		}
		var err error
		if prev, err = store.LastEventHash(); err != nil {
			t.Fatalf("last hash: %v", err)
		}
	}

	if broken, err := store.VerifyChain(); err != nil || broken != 0 {
		t.Fatalf("fresh chain should verify, got broken=%d err=%v", broken, err)
	}

	// Delete the middle row. Every remaining signature is still valid over its own
	// contents — this is exactly the tampering that is invisible without a chain.
	if _, err := store.db.Exec(`DELETE FROM invocation_log WHERE capability_id = 'a.two'`); err != nil {
		t.Fatalf("delete: %v", err)
	}
	broken, err := store.VerifyChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if broken == 0 {
		t.Fatal("deleting a row went undetected — the chain is not doing its job")
	}
}

func TestChainDetectsEditedRow(t *testing.T) {
	store := newTestSandboxStore(t)
	var prev string
	for _, cap := range []string{"b.one", "b.two"} {
		ev := InvocationEvent{TS: "2026-07-31T00:00:00Z", CapabilityID: cap, ResultStatus: "ok", PrevHash: prev}
		if _, err := store.InsertInvocationEvent(ev); err != nil {
			t.Fatalf("insert: %v", err)
		}
		prev, _ = store.LastEventHash()
	}
	// Rewrite the first row's stored record — e.g. changing a denial into a success.
	var stored string
	if err := store.db.QueryRow(`SELECT event_json FROM invocation_log ORDER BY id ASC LIMIT 1`).Scan(&stored); err != nil {
		t.Fatalf("read: %v", err)
	}
	var ev InvocationEvent
	if err := json.Unmarshal([]byte(stored), &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	ev.ResultStatus = "denied"
	edited, _ := json.Marshal(ev)
	if _, err := store.db.Exec(`UPDATE invocation_log SET event_json = ? WHERE id = (SELECT MIN(id) FROM invocation_log)`, string(edited)); err != nil {
		t.Fatalf("update: %v", err)
	}

	broken, err := store.VerifyChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if broken == 0 {
		t.Fatal("editing a stored record went undetected")
	}
}

func TestChainToleratesPreChainRows(t *testing.T) {
	// Rows written before the chain existed carry no PrevHash. Reporting those as
	// tampering would make the check fire on every real log and be ignored.
	store := newTestSandboxStore(t)
	for _, cap := range []string{"c.old1", "c.old2"} {
		if _, err := store.InsertInvocationEvent(InvocationEvent{TS: "2026-01-01T00:00:00Z", CapabilityID: cap, ResultStatus: "ok"}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	// Then a chained row on top.
	prev, _ := store.LastEventHash()
	if _, err := store.InsertInvocationEvent(InvocationEvent{TS: "2026-07-31T00:00:00Z", CapabilityID: "c.new", ResultStatus: "ok", PrevHash: prev}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if broken, err := store.VerifyChain(); err != nil || broken != 0 {
		t.Fatalf("pre-chain rows must not read as tampering, got broken=%d err=%v", broken, err)
	}
}

func TestLastEventHashOnEmptyLogIsNotAnError(t *testing.T) {
	store := newTestSandboxStore(t)
	h, err := store.LastEventHash()
	if err != nil {
		t.Fatalf("empty log should not error: %v", err)
	}
	if h != "" {
		t.Fatalf("genesis event should chain onto nothing, got %q", h)
	}
}

// ── the new fields round-trip ───────────────────────────────────────────────

func TestNewFieldsPersistAndRoundTrip(t *testing.T) {
	store := newTestSandboxStore(t)
	in := InvocationEvent{
		TS:           "2026-07-31T00:00:00Z",
		CapabilityID: "dev.code.write",
		ResultStatus: "ok",
		WorkItem:     "TICKET-1234",
		Reason:       "add the missing validation to the parser",
		Cost:         &Cost{Amount: 0.42, Unit: "USD", Basis: "example-model-v1"},
		Outcome:      "commit 0a1b2c3, 4 files",
		ArgsPreview:  "repo=strategy",
		ResultHash:   "blake3:deadbeef",
	}
	if _, err := store.InsertInvocationEvent(in); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Columns are what a console filters on.
	var workItem, costUnit, outcome string
	var costAmount float64
	err := store.db.QueryRow(
		`SELECT work_item, cost_amount, cost_unit, outcome FROM invocation_log ORDER BY id DESC LIMIT 1`).
		Scan(&workItem, &costAmount, &costUnit, &outcome)
	if err != nil {
		t.Fatalf("read columns: %v", err)
	}
	if workItem != "TICKET-1234" || costUnit != "USD" || costAmount != 0.42 || outcome == "" {
		t.Fatalf("columns did not round-trip: work_item=%q cost=%v %q outcome=%q",
			workItem, costAmount, costUnit, outcome)
	}

	// event_json is what the signature covers, so it must hold them too.
	var stored string
	if err := store.db.QueryRow(`SELECT event_json FROM invocation_log ORDER BY id DESC LIMIT 1`).Scan(&stored); err != nil {
		t.Fatalf("read json: %v", err)
	}
	var out InvocationEvent
	if err := json.Unmarshal([]byte(stored), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.WorkItem != in.WorkItem || out.Reason != in.Reason || out.Outcome != in.Outcome {
		t.Fatalf("signed record lost fields: %+v", out)
	}
	if out.Cost == nil || out.Cost.Unit != "USD" || out.Cost.Amount != 0.42 {
		t.Fatalf("cost did not survive the signed record: %+v", out.Cost)
	}
}

func TestCostIsAbsentNotZeroWhenUnset(t *testing.T) {
	// Absent and zero are different facts: absent means no cost concept applies,
	// zero means it was measured and free. A console cannot tell them apart if the
	// record silently materialises a zero.
	store := newTestSandboxStore(t)
	if _, err := store.InsertInvocationEvent(InvocationEvent{
		TS: "2026-07-31T00:00:00Z", CapabilityID: "msg.send", ResultStatus: "ok",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var amount *float64
	if err := store.db.QueryRow(`SELECT cost_amount FROM invocation_log ORDER BY id DESC LIMIT 1`).Scan(&amount); err != nil {
		t.Fatalf("read: %v", err)
	}
	if amount != nil {
		t.Fatalf("unset cost must be NULL, not %v", *amount)
	}

	var stored string
	store.db.QueryRow(`SELECT event_json FROM invocation_log ORDER BY id DESC LIMIT 1`).Scan(&stored)
	if strings.Contains(stored, `"cost"`) {
		t.Fatalf("unset cost must be omitted from the signed record, got %s", stored)
	}
}
