package sandbox

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

// testSigner signs events the way recordInvocation does: the event with no
// signer or signature, encoded, signed, base64url.
type testSigner struct {
	aid  string
	priv ed25519.PrivateKey
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testSigner{aid: "ELogSigner", priv: priv}
}

func (ts *testSigner) keys(aid string) (ed25519.PublicKey, error) {
	if aid != ts.aid {
		return nil, fmt.Errorf("unknown signer %s", aid)
	}
	return ts.priv.Public().(ed25519.PublicKey), nil
}

func (ts *testSigner) sign(ev InvocationEvent) InvocationEvent {
	payload, _ := json.Marshal(ev)
	ev.SignerAID = ts.aid
	ev.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ts.priv, payload))
	return ev
}

// verifyFirst checks the log and returns its first fault, the shape most of
// these tests ask about.
func verifyFirst(store *SandboxStore, keys EventKeys, start *ChainStart) (int64, string, error) {
	faults, err := store.VerifyChain(keys, start)
	if err != nil || len(faults) == 0 {
		return 0, "", err
	}
	return faults[0].ID, faults[0].Reason, nil
}

// keptStart is the chain start a log written now keeps for row id.
func keptStart(t *testing.T, store *SandboxStore, id int64) ChainStart {
	t.Helper()
	stored, err := store.eventJSON(id)
	if err != nil {
		t.Fatal(err)
	}
	return ChainStart{ID: id, Hash: HashRecord(stored), Linked: true}
}

// appendChained writes a chained, signed event, as recordInvocation does.
func appendChained(t *testing.T, store *SandboxStore, ts *testSigner, capability string) {
	t.Helper()
	prev, err := store.LastEventHash()
	if err != nil {
		t.Fatalf("last hash: %v", err)
	}
	ev := ts.sign(InvocationEvent{TS: "2026-07-31T00:00:00Z", CapabilityID: capability, ResultStatus: "ok", PrevHash: prev})
	if _, err := store.InsertInvocationEvent(ev); err != nil {
		t.Fatalf("insert %s: %v", capability, err)
	}
}

func TestChainDetectsDeletionAndTampering(t *testing.T) {
	store := newTestSandboxStore(t)
	ts := newTestSigner(t)
	for _, cap := range []string{"a.one", "a.two", "a.three"} {
		appendChained(t, store, ts, cap)
	}
	if broken, why, err := verifyFirst(store, ts.keys, nil); err != nil || broken != 0 {
		t.Fatalf("fresh chain should verify, got broken=%d (%s) err=%v", broken, why, err)
	}

	// Delete the middle row. Every remaining signature is still valid over its own
	// contents — this is exactly the tampering that is invisible without a chain.
	if _, err := store.db.Exec(`DELETE FROM invocation_log WHERE capability_id = 'a.two'`); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if broken, _, err := verifyFirst(store, ts.keys, nil); err != nil || broken == 0 {
		t.Fatalf("deleting a row went undetected (err %v)", err)
	}
}

func TestChainDetectsEditedRow(t *testing.T) {
	store := newTestSandboxStore(t)
	ts := newTestSigner(t)
	for _, cap := range []string{"b.one", "b.two"} {
		appendChained(t, store, ts, cap)
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
	if broken, _, err := verifyFirst(store, ts.keys, nil); err != nil || broken == 0 {
		t.Fatalf("editing a stored record went undetected (err %v)", err)
	}
}

// Somebody who can write to the database rewrites a row AND every link after
// it, so the chain is whole again. Only the signature can tell.
func TestARewrittenChainFailsOnItsSignature(t *testing.T) {
	store := newTestSandboxStore(t)
	ts := newTestSigner(t)
	for _, cap := range []string{"d.one", "d.two", "d.three"} {
		appendChained(t, store, ts, cap)
	}
	rows, err := store.db.Query(`SELECT id, event_json FROM invocation_log ORDER BY id ASC`)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		id int64
		ev InvocationEvent
	}
	var all []row
	for rows.Next() {
		var r row
		var stored string
		rows.Scan(&r.id, &stored)
		json.Unmarshal([]byte(stored), &r.ev)
		all = append(all, r)
	}
	rows.Close()
	// Turn the first denial-free record into something else, keep its old
	// signature, and re-link everything after it.
	prev := ""
	for i := range all {
		if i == 0 {
			all[i].ev.ResultStatus = "denied"
		}
		all[i].ev.PrevHash = prev
		b, _ := json.Marshal(all[i].ev)
		if _, err := store.db.Exec(`UPDATE invocation_log SET event_json = ? WHERE id = ?`, string(b), all[i].id); err != nil {
			t.Fatal(err)
		}
		prev = hashArgs(b)
	}
	broken, why, err := verifyFirst(store, ts.keys, nil)
	if err != nil || broken != all[0].id {
		t.Fatalf("a re-linked rewrite was not caught at its first row: broken=%d (%s) err=%v", broken, why, err)
	}
}

// A row that drops its signature, or its link, after the chain has begun is
// how a rewrite would try to look like an old row.
func TestARowCannotLeaveTheChainOnceItHasBegun(t *testing.T) {
	for name, strip := range map[string]func(*InvocationEvent){
		"signature": func(ev *InvocationEvent) { ev.Signature, ev.SignerAID = "", "" },
		"link":      func(ev *InvocationEvent) { ev.PrevHash = "" },
	} {
		t.Run(name, func(t *testing.T) {
			store := newTestSandboxStore(t)
			ts := newTestSigner(t)
			appendChained(t, store, ts, "e.one")
			prev, _ := store.LastEventHash()
			// Signed after stripping, by the log's own key, so only the missing
			// part can fail it.
			ev := InvocationEvent{TS: "2026-07-31T00:00:00Z", CapabilityID: "e.two", ResultStatus: "ok", PrevHash: prev}
			strip(&ev)
			if name == "link" {
				ev = ts.sign(ev)
			}
			if _, err := store.InsertInvocationEvent(ev); err != nil {
				t.Fatal(err)
			}
			// The start a log written now keeps: linked from its first row.
			start := keptStart(t, store, 1)
			if broken, _, err := verifyFirst(store, ts.keys, &start); err != nil || broken == 0 {
				t.Fatalf("a chained log accepted a row without its %s (err %v)", name, err)
			}
		})
	}
}

// A row signed by a key that is not the log's signer fails.
func TestARowSignedByAnotherKeyFails(t *testing.T) {
	store := newTestSandboxStore(t)
	ts := newTestSigner(t)
	appendChained(t, store, ts, "f.one")
	impostor := newTestSigner(t) // same AID, different key
	prev, _ := store.LastEventHash()
	ev := impostor.sign(InvocationEvent{TS: "2026-07-31T00:00:00Z", CapabilityID: "f.two", ResultStatus: "ok", PrevHash: prev})
	if _, err := store.InsertInvocationEvent(ev); err != nil {
		t.Fatal(err)
	}
	if broken, _, err := verifyFirst(store, ts.keys, nil); err != nil || broken == 0 {
		t.Fatalf("a row signed by another key verified (err %v)", err)
	}
}

func TestChainToleratesPreChainRows(t *testing.T) {
	// Rows written before the chain existed carry no PrevHash and no signature.
	// Reporting those as tampering would make the check fire on every real log
	// and be ignored.
	store := newTestSandboxStore(t)
	for _, cap := range []string{"c.old1", "c.old2"} {
		if _, err := store.InsertInvocationEvent(InvocationEvent{TS: "2026-01-01T00:00:00Z", CapabilityID: cap, ResultStatus: "ok"}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	ts := newTestSigner(t)
	appendChained(t, store, ts, "c.new")
	if broken, why, err := verifyFirst(store, ts.keys, nil); err != nil || broken != 0 {
		t.Fatalf("pre-chain rows must not read as tampering, got broken=%d (%s) err=%v", broken, why, err)
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

// ── where the chain begins, and what may be written after ──────────────────

// keepingSigner is a log signer that keeps where its chain begins, as the
// server's does in its own file outside the database.
type keepingSigner struct {
	*testSigner
	start ChainStart
	kept  bool
	fail  bool
}

func (k *keepingSigner) SignEvent(payload []byte) (string, string, error) {
	if k.fail {
		return "", "", fmt.Errorf("the signing key is unavailable")
	}
	return k.aid, base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.priv, payload)), nil
}
func (k *keepingSigner) ChainStart() (ChainStart, bool, error) { return k.start, k.kept, nil }
func (k *keepingSigner) KeepChainStart(s ChainStart) error {
	k.start, k.kept = s, true
	return nil
}

func newLoggingManager(t *testing.T) (*Manager, *keepingSigner) {
	t.Helper()
	m, err := NewManager(ManagerConfig{DataDir: t.TempDir(), ManifestsDir: t.TempDir()})
	if err != nil {
		t.Skipf("sandbox manager unavailable: %v", err)
	}
	k := &keepingSigner{testSigner: newTestSigner(t)}
	m.SetEventSigner(k)
	return m, k
}

func logEvents(t *testing.T, m *Manager, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if m.RecordGovernanceEvent(CallerContext{CallerAID: "EAgent", Reason: "test"}, id, "ok") == 0 {
			t.Fatalf("event %s not written", id)
		}
	}
}

// Somebody with the database rewrites the log's rows as old unsigned ones,
// then the agent writes its next honest row onto the forgery. The start kept
// outside the database is what says those rows were signed: the first row must
// still be the record kept there, and every row from it on must be signed,
// even when the forger re-makes every link.
func TestRewritingRowsAsOldOnesIsCaught(t *testing.T) {
	for name, from := range map[string]int{"every row": 0, "every row after the first": 1} {
		t.Run(name, func(t *testing.T) {
			m, k := newLoggingManager(t)
			logEvents(t, m, "g.one", "g.two", "g.three")
			if !k.kept || k.start.ID != 1 || !k.start.Linked {
				t.Fatalf("the first signed row was not kept as where the chain begins: %+v", k.start)
			}
			db := m.Store().DB()
			rows, _ := db.Query(`SELECT id, event_json FROM invocation_log ORDER BY id ASC`)
			type row struct {
				id     int64
				stored string
			}
			var all []row
			for rows.Next() {
				var r row
				rows.Scan(&r.id, &r.stored)
				all = append(all, r)
			}
			rows.Close()
			prev := ""
			for i, r := range all {
				if i < from {
					prev = HashRecord([]byte(r.stored))
					continue
				}
				var ev InvocationEvent
				json.Unmarshal([]byte(r.stored), &ev)
				ev.SignerAID, ev.Signature = "", ""
				ev.ResultStatus, ev.CapabilityID = "denied", "forged"
				ev.PrevHash = prev // a careful forger re-makes every link
				b, _ := json.Marshal(ev)
				db.Exec(`UPDATE invocation_log SET event_json = ?, signature = '', signer_aid = '', signed_payload = '',
					result_status = 'denied', capability_id = 'forged', prev_hash = ? WHERE id = ?`, string(b), prev, r.id)
				prev = HashRecord(b)
			}
			logEvents(t, m, "g.honest")
			faults, err := m.Store().VerifyChain(k.keys, &k.start)
			if err != nil || len(faults) == 0 {
				t.Fatalf("a log rewritten as unsigned rows passed as intact (err %v)", err)
			}
		})
	}
}

// Once the chain has begun, an event that cannot be signed is not written:
// an unsigned row would mark the log broken for good.
func TestNoUnsignedRowIsWrittenOnceTheChainHasBegun(t *testing.T) {
	m, k := newLoggingManager(t)
	logEvents(t, m, "h.one")
	k.fail = true
	if id := m.RecordGovernanceEvent(CallerContext{CallerAID: "EAgent"}, "h.two", "ok"); id != 0 {
		t.Fatalf("an unsigned row %d was written after the chain began", id)
	}
	var n int
	m.Store().DB().QueryRow(`SELECT COUNT(*) FROM invocation_log`).Scan(&n)
	if n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
	k.fail = false
	logEvents(t, m, "h.three")
	if faults, err := m.Store().VerifyChain(k.keys, &k.start); err != nil || len(faults) != 0 {
		t.Fatalf("the log should still verify: %v %v", faults, err)
	}
}

// Every failing row is reported, so a damaged row cannot hide a later forgery.
func TestEveryFailingRowIsReported(t *testing.T) {
	m, k := newLoggingManager(t)
	logEvents(t, m, "i.one", "i.two", "i.three", "i.four")
	db := m.Store().DB()
	db.Exec(`UPDATE invocation_log SET signature = 'AAAA', event_json = replace(event_json, '"signature":"', '"signature":"AA') WHERE id = 2`)
	db.Exec(`UPDATE invocation_log SET event_json = replace(event_json, '"i.four"', '"i.FOUR"'), capability_id = 'i.FOUR' WHERE id = 4`)
	faults, err := m.Store().VerifyChain(k.keys, &k.start)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int64]bool{}
	for _, f := range faults {
		seen[f.ID] = true
	}
	if !seen[2] || !seen[4] {
		t.Fatalf("both damaged rows should be reported, got %+v", faults)
	}
}

// A log from before links existed: unsigned rows, then rows signed but not
// linked, then signed and linked. It is honest and must verify, with the start
// recorded at the first start after upgrading.
func TestALogSignedBeforeLinksExistedVerifies(t *testing.T) {
	m, k := newLoggingManager(t)
	store := m.Store()
	for _, cap := range []string{"j.old1", "j.old2"} {
		store.InsertInvocationEvent(InvocationEvent{TS: "2026-07-01T00:00:00Z", CapabilityID: cap, ResultStatus: "ok"})
	}
	for _, cap := range []string{"j.signed1", "j.signed2"} {
		store.InsertInvocationEvent(k.sign(InvocationEvent{TS: "2026-07-24T00:00:00Z", CapabilityID: cap, ResultStatus: "ok"}))
	}
	appendChained(t, store, k.testSigner, "j.linked1")
	appendChained(t, store, k.testSigner, "j.linked2")
	if err := m.EnsureChainStart(); err != nil {
		t.Fatal(err)
	}
	if !k.kept || k.start.ID != 3 || k.start.Linked {
		t.Fatalf("the start after upgrading should be the first signed row, not linked: %+v", k.start)
	}
	if faults, err := store.VerifyChain(k.keys, &k.start); err != nil || len(faults) != 0 {
		t.Fatalf("an honest log from before links existed does not verify: %+v %v", faults, err)
	}
	// And a signed row in that stretch still cannot be edited.
	store.DB().Exec(`UPDATE invocation_log SET event_json = replace(event_json, 'j.signed2', 'j.SIGNED2'), capability_id = 'j.SIGNED2' WHERE id = 4`)
	if faults, _ := store.VerifyChain(k.keys, &k.start); len(faults) == 0 {
		t.Fatal("an edited signed row from before links existed passed")
	}
}

// The columns a reader filters and totals on must say what the record says.
func TestAColumnThatDisagreesWithItsRecordIsCaught(t *testing.T) {
	m, k := newLoggingManager(t)
	logEvents(t, m, "k.one", "k.two")
	m.Store().DB().Exec(`UPDATE invocation_log SET result_status = 'denied' WHERE id = 1`)
	faults, err := m.Store().VerifyChain(k.keys, &k.start)
	if err != nil || len(faults) != 1 || faults[0].ID != 1 || !strings.Contains(faults[0].Reason, "result_status") {
		t.Fatalf("a changed filter column was not caught: %+v %v", faults, err)
	}
}

// The bytes a signature covers are kept, so anybody can check it without this
// code's encoder; and a record that no longer says what was signed fails,
// even the newest, which no later link protects.
func TestTheSignedBytesAreKeptAndBindTheRecord(t *testing.T) {
	m, k := newLoggingManager(t)
	logEvents(t, m, "l.one", "l.two")
	var payload, sigB64 string
	m.Store().DB().QueryRow(`SELECT signed_payload, signature FROM invocation_log WHERE id = 2`).Scan(&payload, &sigB64)
	sig, _ := base64.RawURLEncoding.DecodeString(sigB64)
	if payload == "" || !ed25519.Verify(k.priv.Public().(ed25519.PublicKey), []byte(payload), sig) {
		t.Fatal("the kept bytes do not verify on their own")
	}
	m.Store().DB().Exec(`UPDATE invocation_log SET event_json = replace(event_json, '"reason":"test"', '"reason":"changed"') WHERE id = 2`)
	faults, err := m.Store().VerifyChain(k.keys, &k.start)
	if err != nil || len(faults) != 1 || faults[0].ID != 2 {
		t.Fatalf("the newest record was changed and passed: %+v %v", faults, err)
	}
	m.Store().DB().Exec(`UPDATE invocation_log SET event_json = replace(event_json, '"reason":"changed"', '"reason":"test","extra":1') WHERE id = 2`)
	if faults, _ := m.Store().VerifyChain(k.keys, &k.start); len(faults) != 1 {
		t.Fatalf("a record with a field it was not written with passed: %+v", faults)
	}
}

// A key that cannot be had right now means the log cannot be checked, never
// that it was changed.
func TestAMissingKeyIsCannotCheckNotForged(t *testing.T) {
	m, k := newLoggingManager(t)
	logEvents(t, m, "m.one")
	unavailable := func(string) (ed25519.PublicKey, error) {
		return nil, fmt.Errorf("%w: root seed locked", ErrCannotCheck)
	}
	faults, err := m.Store().VerifyChain(unavailable, &k.start)
	if !errors.Is(err, ErrCannotCheck) || len(faults) != 0 {
		t.Fatalf("an unavailable key should be cannot-check, got %+v %v", faults, err)
	}
}
