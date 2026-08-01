package sandbox

import "testing"

func seedEvents(t *testing.T, store *SandboxStore, evs ...InvocationEvent) {
	t.Helper()
	for _, ev := range evs {
		if _, err := store.InsertInvocationEvent(ev); err != nil {
			t.Fatalf("insert %s: %v", ev.CapabilityID, err)
		}
	}
}

func TestFilterByWorkItemCrossesCallers(t *testing.T) {
	// The question a reader usually has is not "what did this caller do" but "what
	// was done for this task" — by whoever did it. So the work-item filter must not
	// be implicitly narrowed by caller.
	store := newTestSandboxStore(t)
	seedEvents(t, store,
		InvocationEvent{TS: "2026-07-01T00:00:00Z", CapabilityID: "x.a", ResultStatus: "ok", WorkItem: "W-1", CallerAID: "AID-one"},
		InvocationEvent{TS: "2026-07-02T00:00:00Z", CapabilityID: "x.b", ResultStatus: "ok", WorkItem: "W-1", CallerAID: "AID-two"},
		InvocationEvent{TS: "2026-07-03T00:00:00Z", CapabilityID: "x.c", ResultStatus: "ok", WorkItem: "W-2", CallerAID: "AID-one"},
	)
	got, err := store.QueryInvocationEvents(InvocationEventFilter{WorkItem: "W-1"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 events for W-1 across both callers, got %d", len(got))
	}
	seen := map[string]bool{}
	for _, e := range got {
		seen[e.CallerAID] = true
	}
	if !seen["AID-one"] || !seen["AID-two"] {
		t.Fatalf("work item filter should span callers, saw %v", seen)
	}
}

func TestFilterByStatusAndWindow(t *testing.T) {
	store := newTestSandboxStore(t)
	seedEvents(t, store,
		InvocationEvent{TS: "2026-07-01T00:00:00Z", CapabilityID: "y.a", ResultStatus: "ok"},
		InvocationEvent{TS: "2026-07-05T00:00:00Z", CapabilityID: "y.b", ResultStatus: "denied"},
		InvocationEvent{TS: "2026-07-10T00:00:00Z", CapabilityID: "y.c", ResultStatus: "denied"},
	)
	denied, err := store.QueryInvocationEvents(InvocationEventFilter{ResultStatus: "denied"})
	if err != nil || len(denied) != 2 {
		t.Fatalf("want 2 denied, got %d err=%v", len(denied), err)
	}
	windowed, err := store.QueryInvocationEvents(InvocationEventFilter{
		Since: "2026-07-04T00:00:00Z", Until: "2026-07-06T00:00:00Z"})
	if err != nil || len(windowed) != 1 || windowed[0].CapabilityID != "y.b" {
		t.Fatalf("window filter wrong: %d events, err=%v", len(windowed), err)
	}
}

func TestNewestFirst(t *testing.T) {
	store := newTestSandboxStore(t)
	seedEvents(t, store,
		InvocationEvent{TS: "2026-07-01T00:00:00Z", CapabilityID: "z.old", ResultStatus: "ok"},
		InvocationEvent{TS: "2026-07-02T00:00:00Z", CapabilityID: "z.new", ResultStatus: "ok"},
	)
	got, err := store.QueryInvocationEvents(InvocationEventFilter{})
	if err != nil || len(got) != 2 {
		t.Fatalf("query: %d err=%v", len(got), err)
	}
	if got[0].CapabilityID != "z.new" {
		t.Fatalf("want newest first, got %s", got[0].CapabilityID)
	}
}

func TestEffectiveLimitIsBounded(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, defaultEventLimit}, {-5, defaultEventLimit},
		{50, 50}, {maxEventLimit, maxEventLimit},
		{maxEventLimit + 1, defaultEventLimit}, {1_000_000, defaultEventLimit},
	}
	for _, c := range cases {
		if got := (InvocationEventFilter{Limit: c.in}).EffectiveLimit(); got != c.want {
			t.Errorf("limit %d: want %d, got %d", c.in, c.want, got)
		}
	}
}

func TestGetInvocationEventCarriesItsID(t *testing.T) {
	store := newTestSandboxStore(t)
	id, err := store.InsertInvocationEvent(InvocationEvent{
		TS: "2026-07-01T00:00:00Z", CapabilityID: "one.only", ResultStatus: "ok",
		WorkItem: "W-9", Reason: "because",
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	ev, err := store.GetInvocationEvent(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	// The id lives in the column, not in the stored JSON, so it has to be put back
	// or a caller cannot link a fetched event to anything.
	if ev.ID != id || ev.WorkItem != "W-9" || ev.Reason != "because" {
		t.Fatalf("round trip lost data: %+v", ev)
	}
	if _, err := store.GetInvocationEvent(999999); err == nil {
		t.Fatal("a missing event should be an error, not a zero value")
	}
}

// ── summary ─────────────────────────────────────────────────────────────────

func TestSummaryNeverAddsUnlikeUnits(t *testing.T) {
	// Summing dollars, tokens and requests into one number is arithmetically valid
	// and completely meaningless. Costs stay grouped by unit.
	store := newTestSandboxStore(t)
	seedEvents(t, store,
		InvocationEvent{TS: "2026-07-01T00:00:00Z", CapabilityID: "s.a", ResultStatus: "ok",
			ExecutorType: "local_cli", DurationMs: 100, Cost: &Cost{Amount: 1.50, Unit: "USD"}},
		InvocationEvent{TS: "2026-07-02T00:00:00Z", CapabilityID: "s.b", ResultStatus: "ok",
			ExecutorType: "local_cli", DurationMs: 200, Cost: &Cost{Amount: 2.50, Unit: "USD"}},
		InvocationEvent{TS: "2026-07-03T00:00:00Z", CapabilityID: "s.c", ResultStatus: "denied",
			ExecutorType: "external_api", DurationMs: 5, Cost: &Cost{Amount: 4000, Unit: "tokens"}},
	)
	sum, err := store.SummariseInvocations("")
	if err != nil {
		t.Fatalf("summarise: %v", err)
	}
	if sum.Total != 3 || sum.ByStatus["ok"] != 2 || sum.ByStatus["denied"] != 1 {
		t.Fatalf("status tally wrong: %+v", sum)
	}
	if sum.ByExecutor["local_cli"] != 2 || sum.ByExecutor["external_api"] != 1 {
		t.Fatalf("executor tally wrong: %+v", sum.ByExecutor)
	}
	if sum.CostByUnit["USD"] != 4.0 {
		t.Fatalf("USD total wrong: %v", sum.CostByUnit["USD"])
	}
	if sum.CostByUnit["tokens"] != 4000 {
		t.Fatalf("token total wrong: %v", sum.CostByUnit["tokens"])
	}
	if len(sum.CostByUnit) != 2 {
		t.Fatalf("units must stay separate, got %+v", sum.CostByUnit)
	}
	if sum.TotalDuration != 305 {
		t.Fatalf("duration total wrong: %d", sum.TotalDuration)
	}
}

func TestSummaryDistinguishesUncostedFromFree(t *testing.T) {
	// A total of zero must not be readable as "this was free" when it actually means
	// "nothing reported a cost". Costed is what tells them apart.
	store := newTestSandboxStore(t)
	seedEvents(t, store,
		InvocationEvent{TS: "2026-07-01T00:00:00Z", CapabilityID: "u.a", ResultStatus: "ok"},
		InvocationEvent{TS: "2026-07-02T00:00:00Z", CapabilityID: "u.b", ResultStatus: "ok"},
	)
	sum, err := store.SummariseInvocations("")
	if err != nil {
		t.Fatalf("summarise: %v", err)
	}
	if sum.Total != 2 {
		t.Fatalf("want 2 events, got %d", sum.Total)
	}
	if sum.Costed != 0 {
		t.Fatalf("nothing reported a cost, so Costed must be 0, got %d", sum.Costed)
	}
	if len(sum.CostByUnit) != 0 {
		t.Fatalf("no costs means no unit buckets, got %+v", sum.CostByUnit)
	}

	// Now one that genuinely cost nothing — measured, and free.
	seedEvents(t, store, InvocationEvent{TS: "2026-07-03T00:00:00Z", CapabilityID: "u.c",
		ResultStatus: "ok", Cost: &Cost{Amount: 0, Unit: "USD"}})
	sum, _ = store.SummariseInvocations("")
	if sum.Costed != 1 {
		t.Fatalf("a measured zero cost still counts as costed, got %d", sum.Costed)
	}
	if _, ok := sum.CostByUnit["USD"]; !ok {
		t.Fatal("a measured zero should still create its unit bucket")
	}
}

func TestSummaryHonoursSince(t *testing.T) {
	store := newTestSandboxStore(t)
	seedEvents(t, store,
		InvocationEvent{TS: "2026-06-01T00:00:00Z", CapabilityID: "h.old", ResultStatus: "ok",
			Cost: &Cost{Amount: 99, Unit: "USD"}},
		InvocationEvent{TS: "2026-07-20T00:00:00Z", CapabilityID: "h.new", ResultStatus: "ok",
			Cost: &Cost{Amount: 1, Unit: "USD"}},
	)
	sum, err := store.SummariseInvocations("2026-07-01T00:00:00Z")
	if err != nil {
		t.Fatalf("summarise: %v", err)
	}
	if sum.Total != 1 {
		t.Fatalf("since should exclude the older event, got total %d", sum.Total)
	}
	// The cost query has its own WHERE clause; a since that the counts honour but the
	// costs ignore would report a window's activity against all-time spend.
	if sum.CostByUnit["USD"] != 1 {
		t.Fatalf("cost totals must honour since too, got %v", sum.CostByUnit["USD"])
	}
}

func TestSummaryOnEmptyLog(t *testing.T) {
	sum, err := newTestSandboxStore(t).SummariseInvocations("")
	if err != nil {
		t.Fatalf("an empty log is not an error: %v", err)
	}
	if sum.Total != 0 || len(sum.ByStatus) != 0 || sum.FirstEvent != "" {
		t.Fatalf("empty summary should be empty: %+v", sum)
	}
}
