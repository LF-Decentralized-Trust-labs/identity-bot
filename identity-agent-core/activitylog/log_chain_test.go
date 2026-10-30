package activitylog_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"identity-agent-core/activitylog"
	"identity-agent-core/activitylog/activitylogtest"
	"identity-agent-core/permission"
	"strings"
	"testing"
)

// newLoggingLog is a log signed by a signer that keeps where its chain
// begins.
func newLoggingLog(t *testing.T) (*activitylog.Log, *activitylogtest.KeepingSigner) {
	t.Helper()
	l := activitylog.NewTestLog(t)
	k := activitylogtest.NewKeepingSigner(t)
	l.SetEventSigner(k)
	return l, k
}

// verifyFirst checks the log and returns its first fault, the shape most of
// these tests ask about.
func verifyFirst(store *activitylog.Log, keys activitylog.EventKeys, start *activitylog.ChainStart) (int64, string, error) {
	faults, err := store.VerifyChain(keys, start)
	if err != nil || len(faults) == 0 {
		return 0, "", err
	}
	return faults[0].ID, faults[0].Reason, nil
}

// keptStart is the chain start a log written now keeps for row id.
func keptStart(t *testing.T, store *activitylog.Log, id int64) activitylog.ChainStart {
	t.Helper()
	stored, err := activitylog.EventJSON(store, id)
	if err != nil {
		t.Fatal(err)
	}
	return activitylog.ChainStart{ID: id, Hash: activitylog.HashRecord(stored), Linked: true}
}

// appendChained writes a chained, signed event, as recordInvocation does.
func appendChained(t *testing.T, store *activitylog.Log, ts *activitylogtest.Signer, capability string) {
	t.Helper()
	prev, err := store.LastEventHash()
	if err != nil {
		t.Fatalf("last hash: %v", err)
	}
	ev := ts.Sign(activitylog.InvocationEvent{TS: "2026-07-31T00:00:00Z", CapabilityID: capability, ResultStatus: "ok", PrevHash: prev})
	if _, err := store.InsertInvocationEvent(ev); err != nil {
		t.Fatalf("insert %s: %v", capability, err)
	}
}

func TestChainDetectsDeletionAndTampering(t *testing.T) {
	store := activitylog.NewTestLog(t)
	ts := activitylogtest.NewSigner(t)
	for _, cap := range []string{"a.one", "a.two", "a.three"} {
		appendChained(t, store, ts, cap)
	}
	if broken, why, err := verifyFirst(store, ts.Keys, nil); err != nil || broken != 0 {
		t.Fatalf("fresh chain should verify, got broken=%d (%s) err=%v", broken, why, err)
	}

	// Delete the middle row. Every remaining signature is still valid over its own
	// contents — this is exactly the tampering that is invisible without a chain.
	if _, err := store.DB().Exec(`DELETE FROM invocation_log WHERE capability_id = 'a.two'`); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if broken, _, err := verifyFirst(store, ts.Keys, nil); err != nil || broken == 0 {
		t.Fatalf("deleting a row went undetected (err %v)", err)
	}
}

func TestChainDetectsEditedRow(t *testing.T) {
	store := activitylog.NewTestLog(t)
	ts := activitylogtest.NewSigner(t)
	for _, cap := range []string{"b.one", "b.two"} {
		appendChained(t, store, ts, cap)
	}
	// Rewrite the first row's stored record — e.g. changing a denial into a success.
	var stored string
	if err := store.DB().QueryRow(`SELECT event_json FROM invocation_log ORDER BY id ASC LIMIT 1`).Scan(&stored); err != nil {
		t.Fatalf("read: %v", err)
	}
	var ev activitylog.InvocationEvent
	if err := json.Unmarshal([]byte(stored), &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	ev.ResultStatus = "denied"
	edited, _ := json.Marshal(ev)
	if _, err := store.DB().Exec(`UPDATE invocation_log SET event_json = ? WHERE id = (SELECT MIN(id) FROM invocation_log)`, string(edited)); err != nil {
		t.Fatalf("update: %v", err)
	}
	if broken, _, err := verifyFirst(store, ts.Keys, nil); err != nil || broken == 0 {
		t.Fatalf("editing a stored record went undetected (err %v)", err)
	}
}

// Somebody who can write to the database rewrites a row AND every link after
// it, so the chain is whole again. Only the signature can tell.
func TestARewrittenChainFailsOnItsSignature(t *testing.T) {
	store := activitylog.NewTestLog(t)
	ts := activitylogtest.NewSigner(t)
	for _, cap := range []string{"d.one", "d.two", "d.three"} {
		appendChained(t, store, ts, cap)
	}
	rows, err := store.DB().Query(`SELECT id, event_json FROM invocation_log ORDER BY id ASC`)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		id int64
		ev activitylog.InvocationEvent
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
		if _, err := store.DB().Exec(`UPDATE invocation_log SET event_json = ? WHERE id = ?`, string(b), all[i].id); err != nil {
			t.Fatal(err)
		}
		prev = activitylog.HashRecord(b)
	}
	broken, why, err := verifyFirst(store, ts.Keys, nil)
	if err != nil || broken != all[0].id {
		t.Fatalf("a re-linked rewrite was not caught at its first row: broken=%d (%s) err=%v", broken, why, err)
	}
}

// A row that drops its signature, or its link, after the chain has begun is
// how a rewrite would try to look like an old row.
func TestARowCannotLeaveTheChainOnceItHasBegun(t *testing.T) {
	for name, strip := range map[string]func(*activitylog.InvocationEvent){
		"signature": func(ev *activitylog.InvocationEvent) { ev.Signature, ev.SignerAID = "", "" },
		"link":      func(ev *activitylog.InvocationEvent) { ev.PrevHash = "" },
	} {
		t.Run(name, func(t *testing.T) {
			store := activitylog.NewTestLog(t)
			ts := activitylogtest.NewSigner(t)
			appendChained(t, store, ts, "e.one")
			prev, _ := store.LastEventHash()
			// Signed after stripping, by the log's own key, so only the missing
			// part can fail it.
			ev := activitylog.InvocationEvent{TS: "2026-07-31T00:00:00Z", CapabilityID: "e.two", ResultStatus: "ok", PrevHash: prev}
			strip(&ev)
			if name == "link" {
				ev = ts.Sign(ev)
			}
			if _, err := store.InsertInvocationEvent(ev); err != nil {
				t.Fatal(err)
			}
			// The start a log written now keeps: linked from its first row.
			start := keptStart(t, store, 1)
			if broken, _, err := verifyFirst(store, ts.Keys, &start); err != nil || broken == 0 {
				t.Fatalf("a chained log accepted a row without its %s (err %v)", name, err)
			}
		})
	}
}

// A row signed by a key that is not the log's signer fails.
func TestARowSignedByAnotherKeyFails(t *testing.T) {
	store := activitylog.NewTestLog(t)
	ts := activitylogtest.NewSigner(t)
	appendChained(t, store, ts, "f.one")
	impostor := activitylogtest.NewSigner(t) // same AID, different key
	prev, _ := store.LastEventHash()
	ev := impostor.Sign(activitylog.InvocationEvent{TS: "2026-07-31T00:00:00Z", CapabilityID: "f.two", ResultStatus: "ok", PrevHash: prev})
	if _, err := store.InsertInvocationEvent(ev); err != nil {
		t.Fatal(err)
	}
	if broken, _, err := verifyFirst(store, ts.Keys, nil); err != nil || broken == 0 {
		t.Fatalf("a row signed by another key verified (err %v)", err)
	}
}

func TestChainToleratesPreChainRows(t *testing.T) {
	// Rows written before the chain existed carry no PrevHash and no signature.
	// Reporting those as tampering would make the check fire on every real log
	// and be ignored.
	store := activitylog.NewTestLog(t)
	for _, cap := range []string{"c.old1", "c.old2"} {
		if _, err := store.InsertInvocationEvent(activitylog.InvocationEvent{TS: "2026-01-01T00:00:00Z", CapabilityID: cap, ResultStatus: "ok"}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	ts := activitylogtest.NewSigner(t)
	appendChained(t, store, ts, "c.new")
	if broken, why, err := verifyFirst(store, ts.Keys, nil); err != nil || broken != 0 {
		t.Fatalf("pre-chain rows must not read as tampering, got broken=%d (%s) err=%v", broken, why, err)
	}
}

func TestLastEventHashOnEmptyLogIsNotAnError(t *testing.T) {
	store := activitylog.NewTestLog(t)
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
	store := activitylog.NewTestLog(t)
	in := activitylog.InvocationEvent{
		TS:           "2026-07-31T00:00:00Z",
		CapabilityID: "dev.code.write",
		ResultStatus: "ok",
		WorkItem:     "TICKET-1234",
		Reason:       "add the missing validation to the parser",
		Cost:         &activitylog.Cost{Amount: 0.42, Unit: "USD", Basis: "example-model-v1"},
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
	err := store.DB().QueryRow(
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
	if err := store.DB().QueryRow(`SELECT event_json FROM invocation_log ORDER BY id DESC LIMIT 1`).Scan(&stored); err != nil {
		t.Fatalf("read json: %v", err)
	}
	var out activitylog.InvocationEvent
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
	store := activitylog.NewTestLog(t)
	if _, err := store.InsertInvocationEvent(activitylog.InvocationEvent{
		TS: "2026-07-31T00:00:00Z", CapabilityID: "msg.send", ResultStatus: "ok",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var amount *float64
	if err := store.DB().QueryRow(`SELECT cost_amount FROM invocation_log ORDER BY id DESC LIMIT 1`).Scan(&amount); err != nil {
		t.Fatalf("read: %v", err)
	}
	if amount != nil {
		t.Fatalf("unset cost must be NULL, not %v", *amount)
	}

	var stored string
	store.DB().QueryRow(`SELECT event_json FROM invocation_log ORDER BY id DESC LIMIT 1`).Scan(&stored)
	if strings.Contains(stored, `"cost"`) {
		t.Fatalf("unset cost must be omitted from the signed record, got %s", stored)
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
			m, k := newLoggingLog(t)
			activitylogtest.WriteEvents(t, m, "g.one", "g.two", "g.three")
			if !k.Kept || k.Start.ID != 1 || !k.Start.Linked {
				t.Fatalf("the first signed row was not kept as where the chain begins: %+v", k.Start)
			}
			db := m.DB()
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
					prev = activitylog.HashRecord([]byte(r.stored))
					continue
				}
				var ev activitylog.InvocationEvent
				json.Unmarshal([]byte(r.stored), &ev)
				ev.SignerAID, ev.Signature = "", ""
				ev.ResultStatus, ev.CapabilityID = "denied", "forged"
				ev.PrevHash = prev // a careful forger re-makes every link
				b, _ := json.Marshal(ev)
				db.Exec(`UPDATE invocation_log SET event_json = ?, signature = '', signer_aid = '', signed_payload = '',
					result_status = 'denied', capability_id = 'forged', prev_hash = ? WHERE id = ?`, string(b), prev, r.id)
				prev = activitylog.HashRecord(b)
			}
			activitylogtest.WriteEvents(t, m, "g.honest")
			faults, err := m.VerifyChain(k.Keys, &k.Start)
			if err != nil || len(faults) == 0 {
				t.Fatalf("a log rewritten as unsigned rows passed as intact (err %v)", err)
			}
		})
	}
}

// Once the chain has begun, an event that cannot be signed is not written:
// an unsigned row would mark the log broken for good.
func TestNoUnsignedRowIsWrittenOnceTheChainHasBegun(t *testing.T) {
	m, k := newLoggingLog(t)
	activitylogtest.WriteEvents(t, m, "h.one")
	k.Fail = true
	if id := m.RecordGovernanceEvent(permission.CallerContext{CallerAID: "EAgent"}, "h.two", "ok"); id != 0 {
		t.Fatalf("an unsigned row %d was written after the chain began", id)
	}
	var n int
	m.DB().QueryRow(`SELECT COUNT(*) FROM invocation_log`).Scan(&n)
	if n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
	k.Fail = false
	activitylogtest.WriteEvents(t, m, "h.three")
	if faults, err := m.VerifyChain(k.Keys, &k.Start); err != nil || len(faults) != 0 {
		t.Fatalf("the log should still verify: %v %v", faults, err)
	}
}

// Every failing row is reported, so a damaged row cannot hide a later forgery.
func TestEveryFailingRowIsReported(t *testing.T) {
	m, k := newLoggingLog(t)
	activitylogtest.WriteEvents(t, m, "i.one", "i.two", "i.three", "i.four")
	db := m.DB()
	db.Exec(`UPDATE invocation_log SET signature = 'AAAA', event_json = replace(event_json, '"signature":"', '"signature":"AA') WHERE id = 2`)
	db.Exec(`UPDATE invocation_log SET event_json = replace(event_json, '"i.four"', '"i.FOUR"'), capability_id = 'i.FOUR' WHERE id = 4`)
	faults, err := m.VerifyChain(k.Keys, &k.Start)
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
	m, k := newLoggingLog(t)
	store := m
	for _, cap := range []string{"j.old1", "j.old2"} {
		store.InsertInvocationEvent(activitylog.InvocationEvent{TS: "2026-07-01T00:00:00Z", CapabilityID: cap, ResultStatus: "ok"})
	}
	for _, cap := range []string{"j.signed1", "j.signed2"} {
		store.InsertInvocationEvent(k.Sign(activitylog.InvocationEvent{TS: "2026-07-24T00:00:00Z", CapabilityID: cap, ResultStatus: "ok"}))
	}
	appendChained(t, store, k.Signer, "j.linked1")
	appendChained(t, store, k.Signer, "j.linked2")
	if err := m.EnsureChainStart(); err != nil {
		t.Fatal(err)
	}
	if !k.Kept || k.Start.ID != 3 || k.Start.Linked {
		t.Fatalf("the start after upgrading should be the first signed row, not linked: %+v", k.Start)
	}
	if faults, err := store.VerifyChain(k.Keys, &k.Start); err != nil || len(faults) != 0 {
		t.Fatalf("an honest log from before links existed does not verify: %+v %v", faults, err)
	}
	// And a signed row in that stretch still cannot be edited.
	store.DB().Exec(`UPDATE invocation_log SET event_json = replace(event_json, 'j.signed2', 'j.SIGNED2'), capability_id = 'j.SIGNED2' WHERE id = 4`)
	if faults, _ := store.VerifyChain(k.Keys, &k.Start); len(faults) == 0 {
		t.Fatal("an edited signed row from before links existed passed")
	}
}

// The columns a reader filters and totals on must say what the record says.
func TestAColumnThatDisagreesWithItsRecordIsCaught(t *testing.T) {
	m, k := newLoggingLog(t)
	activitylogtest.WriteEvents(t, m, "k.one", "k.two")
	m.DB().Exec(`UPDATE invocation_log SET result_status = 'denied' WHERE id = 1`)
	faults, err := m.VerifyChain(k.Keys, &k.Start)
	if err != nil || len(faults) != 1 || faults[0].ID != 1 || !strings.Contains(faults[0].Reason, "result_status") {
		t.Fatalf("a changed filter column was not caught: %+v %v", faults, err)
	}
}

// The bytes a signature covers are kept, so anybody can check it without this
// code's encoder; and a record that no longer says what was signed fails,
// even the newest, which no later link protects.
func TestTheSignedBytesAreKeptAndBindTheRecord(t *testing.T) {
	m, k := newLoggingLog(t)
	activitylogtest.WriteEvents(t, m, "l.one", "l.two")
	var payload, sigB64 string
	m.DB().QueryRow(`SELECT signed_payload, signature FROM invocation_log WHERE id = 2`).Scan(&payload, &sigB64)
	sig, _ := base64.RawURLEncoding.DecodeString(sigB64)
	pub, _ := k.Keys(k.AID)
	if payload == "" || !ed25519.Verify(pub, []byte(payload), sig) {
		t.Fatal("the kept bytes do not verify on their own")
	}
	m.DB().Exec(`UPDATE invocation_log SET event_json = replace(event_json, '"reason":"test"', '"reason":"changed"') WHERE id = 2`)
	faults, err := m.VerifyChain(k.Keys, &k.Start)
	if err != nil || len(faults) != 1 || faults[0].ID != 2 {
		t.Fatalf("the newest record was changed and passed: %+v %v", faults, err)
	}
	m.DB().Exec(`UPDATE invocation_log SET event_json = replace(event_json, '"reason":"changed"', '"reason":"test","extra":1') WHERE id = 2`)
	if faults, _ := m.VerifyChain(k.Keys, &k.Start); len(faults) != 1 {
		t.Fatalf("a record with a field it was not written with passed: %+v", faults)
	}
}

// A key that cannot be had right now means the log cannot be checked, never
// that it was changed.
func TestAMissingKeyIsCannotCheckNotForged(t *testing.T) {
	m, k := newLoggingLog(t)
	activitylogtest.WriteEvents(t, m, "m.one")
	unavailable := func(string) (ed25519.PublicKey, error) {
		return nil, fmt.Errorf("%w: root seed locked", activitylog.ErrCannotCheck)
	}
	faults, err := m.VerifyChain(unavailable, &k.Start)
	if !errors.Is(err, activitylog.ErrCannotCheck) || len(faults) != 0 {
		t.Fatalf("an unavailable key should be cannot-check, got %+v %v", faults, err)
	}
}

// Rows written while signed bytes are always kept must keep them; a record
// may name each key once, spelled as written.
func TestTheSignedBytesCannotBeDroppedAndKeysCannotRepeat(t *testing.T) {
	m, k := newLoggingLog(t)
	activitylogtest.WriteEvents(t, m, "p.one", "p.two", "p.three", "p.four")
	if k.Start.PayloadFrom != 1 {
		t.Fatalf("a chain begun now keeps signed bytes from its first row: %+v", k.Start)
	}
	db := m.DB()
	db.Exec(`UPDATE invocation_log SET signed_payload = '' WHERE id = 2`)
	db.Exec(`UPDATE invocation_log SET event_json = replace(event_json, '{"ts"', '{"capability_id":"p.other","ts"') WHERE id = 3`)
	db.Exec(`UPDATE invocation_log SET event_json = replace(event_json, '"reason"', '"Reason"') WHERE id = 4`)
	faults, err := m.VerifyChain(k.Keys, &k.Start)
	if err != nil {
		t.Fatal(err)
	}
	why := map[int64]string{}
	for _, f := range faults {
		why[f.ID] += f.Reason + "; "
	}
	if !strings.Contains(why[2], "bytes its signature covers are missing") {
		t.Errorf("a row whose signed bytes were dropped passed: %q", why[2])
	}
	if !strings.Contains(why[3], "twice") {
		t.Errorf("a record with a key given twice passed: %q", why[3])
	}
	if !strings.Contains(why[4], "not written with") {
		t.Errorf("a record with a key in another case passed: %q", why[4])
	}
}
