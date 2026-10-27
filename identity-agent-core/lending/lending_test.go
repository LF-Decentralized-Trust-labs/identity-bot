package lending

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

// memStore is a ledger kept in memory, as the vault keeps it: as JSON.
type memStore struct {
	mu   sync.Mutex
	b    []byte
	fail error
}

func (m *memStore) Read(out any) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return false, m.fail
	}
	if m.b == nil {
		return false, nil
	}
	return true, json.Unmarshal(m.b, out)
}

func (m *memStore) Write(v any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	b, err := json.Marshal(v)
	m.b = b
	return err
}

const ttl = 5 * time.Minute

// signIns is a lend like a brain's sign-in: nothing to withdraw, renewed while
// a run goes on, and remembered for a week after it ends.
var signIns = Service{Kind: "sign_in", IDPrefix: "bl_", KeptAfterEnd: 7 * 24 * time.Hour}

func lendSignIn(t *testing.T, l *Ledger, agent, pool, host string, max int, now time.Time) (Lend, []Ended, error) {
	t.Helper()
	return l.Lend(context.Background(), Lend{Kind: "sign_in", Agent: agent, Pool: pool, Lent: "fp", Host: host,
		Expires: now.Add(ttl)}, Limit{MaxInPool: max}, now)
}

// A lend capped at one run lends to one run at a time, and a run that never
// gives it back frees its place when it lapses unrenewed.
func TestACappedLendFreesAPlaceWhenItLapses(t *testing.T) {
	l := New(&memStore{}, signIns)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	first, _, err := lendSignIn(t, l, "agent", "p", "host-1", 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := lendSignIn(t, l, "agent", "p", "host-2", 1, now.Add(time.Minute)); !errors.Is(err, ErrInUse) {
		t.Fatalf("a second run was lent what is capped at one: %v", err)
	}
	if _, err := l.Renew("sign_in", first.ID, "host-1", "agent", ttl, now.Add(ttl-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lendSignIn(t, l, "agent", "p", "host-2", 1, now.Add(ttl+time.Second)); !errors.Is(err, ErrInUse) {
		t.Fatalf("a renewed lend was let go: %v", err)
	}
	later := now.Add(2*ttl + time.Second)
	second, lapsed, err := lendSignIn(t, l, "agent", "p", "host-2", 1, later)
	if err != nil {
		t.Fatalf("the lapsed lend still holds its place: %v", err)
	}
	if len(lapsed) != 1 || lapsed[0].Lend.ID != first.ID || !lapsed[0].Lapsed {
		t.Fatalf("the lapse was not reported: %+v", lapsed)
	}
	if _, err := l.Return(context.Background(), "sign_in", second.ID, "host-1", "agent", later); !errors.Is(err, ErrNoLend) {
		t.Fatalf("another body gave back a lend it does not hold: %v", err)
	}
	if _, err := l.Return(context.Background(), "sign_in", second.ID, "host-2", "agent", later); err != nil {
		t.Fatal(err)
	}
	if n := l.Count(func(x Lend) bool { return x.Agent == "agent" }, later); n != 0 {
		t.Fatalf("%d in use after the return", n)
	}
}

// A lapsed lend holds no place, but can still be given back for as long as
// its service remembers it; a lapse is reported once.
func TestALapsedLendCanStillBeGivenBack(t *testing.T) {
	l := New(&memStore{}, signIns)
	now := time.Now()
	x, _, err := lendSignIn(t, l, "agent-a", "pool", "h1", 1, now)
	if err != nil {
		t.Fatal(err)
	}
	later := now.Add(ttl + time.Minute)
	if lapsed, err := l.Lapse(later); err != nil || len(lapsed) != 1 {
		t.Fatalf("lapsed: %v %v", lapsed, err)
	}
	if lapsed, _ := l.Lapse(later); len(lapsed) != 0 {
		t.Fatal("a lapse was reported twice")
	}
	if _, err := l.Renew("sign_in", x.ID, "h1", "agent-a", ttl, later); !errors.Is(err, ErrNoLend) {
		t.Fatalf("a lapsed lend was renewed: %v", err)
	}
	got, err := l.Return(context.Background(), "sign_in", x.ID, "h1", "agent-a", later)
	if err != nil || got.Lend.ID != x.ID || got.WasOpen || got.Lend.Lent != "fp" {
		t.Fatalf("giving back a lapsed lend: %+v %v", got, err)
	}
	if _, err := l.Return(context.Background(), "sign_in", x.ID, "h1", "agent-a", later); !errors.Is(err, ErrNoLend) {
		t.Fatal("a lend was given back twice")
	}
	old, _, _ := lendSignIn(t, l, "agent-c", "pool-c", "h3", 0, now)
	_, _ = l.Lapse(later)
	if _, err := l.Return(context.Background(), "sign_in", old.ID, "h3", "agent-c", later.Add(7*24*time.Hour)); !errors.Is(err, ErrNoLend) {
		t.Fatal("a lend that lapsed long ago was still remembered")
	}
}

// A ledger that cannot be read lends nothing, rather than counting no runs.
func TestAnUnreadableLedgerLendsNothing(t *testing.T) {
	l := New(&memStore{fail: errors.New("locked")}, signIns)
	if _, _, err := lendSignIn(t, l, "agent", "p", "h", 1, time.Now()); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("lent past an unreadable ledger: %v", err)
	}
}

// tokens is a lend like GitHub's: its data is tokens, each withdrawn at the
// service on its own, and a grant may stop covering one and not another.
type tokens struct {
	Tokens []string `json:"tokens"`
}

func tokenService(granted map[string]bool, withdrawn *[]string, unreachable *bool) Service {
	return Service{Kind: "tokens", IDPrefix: "gl_",
		Parts: func(d json.RawMessage) []json.RawMessage {
			var t tokens
			_ = json.Unmarshal(d, &t)
			var out []json.RawMessage
			for _, x := range t.Tokens {
				b, _ := json.Marshal(x)
				out = append(out, b)
			}
			return out
		},
		Check: func(x Lend) *Narrowed {
			var t tokens
			_ = json.Unmarshal(x.Data, &t)
			var keep []string
			var gone []json.RawMessage
			for _, tok := range t.Tokens {
				if granted[tok] {
					keep = append(keep, tok)
				} else {
					b, _ := json.Marshal(tok)
					gone = append(gone, b)
				}
			}
			if len(gone) == 0 {
				return nil
			}
			if len(keep) == 0 {
				return &Narrowed{Why: "no longer granted"}
			}
			b, _ := json.Marshal(tokens{Tokens: keep})
			return &Narrowed{Why: "partly no longer granted", Keep: b, Withdraw: gone}
		},
		Withdraw: func(_ context.Context, p json.RawMessage) error {
			if *unreachable {
				return errors.New("unreachable")
			}
			var tok string
			_ = json.Unmarshal(p, &tok)
			*withdrawn = append(*withdrawn, tok)
			return nil
		},
	}
}

func lendTokens(t *testing.T, l *Ledger, host string, now time.Time, toks ...string) Lend {
	t.Helper()
	d, _ := json.Marshal(tokens{Tokens: toks})
	x, _, err := l.Lend(context.Background(), Lend{Kind: "tokens", Agent: "a", Host: host, Expires: now.Add(time.Hour), Data: d},
		Limit{OnePerBody: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

// One sweep ends every kind of lend its grant no longer covers: a token lend
// is narrowed to the tokens still covered, and the rest withdrawn; a sign-in
// lend ends at once. A withdrawal the service could not be reached for is
// tried again, until the lend would have expired.
func TestOneSweepEndsEveryKindOfLend(t *testing.T) {
	granted := map[string]bool{"write": true, "read": true}
	var withdrawn []string
	unreachable := false
	revoked := false
	signIn := signIns
	signIn.Check = func(Lend) *Narrowed {
		if revoked {
			return &Narrowed{Why: "revoked"}
		}
		return nil
	}
	l := New(&memStore{}, signIn, tokenService(granted, &withdrawn, &unreachable))
	now := time.Now()
	ctx := context.Background()
	s, _, _ := lendSignIn(t, l, "a", "p", "h", 1, now)
	lendTokens(t, l, "h", now, "write", "read")

	// Write becomes read: only the write token goes.
	delete(granted, "write")
	ended, err := l.Sweep(ctx, now)
	if err != nil || len(ended) != 1 || !ended[0].Partly || !ended[0].Withdrawn {
		t.Fatalf("narrowing: %+v %v", ended, err)
	}
	if len(withdrawn) != 1 || withdrawn[0] != "write" {
		t.Fatalf("withdrawn: %v", withdrawn)
	}
	if n := l.Count(func(x Lend) bool { return x.Kind == "tokens" }, now); n != 1 {
		t.Fatal("the lend still covered for reading was ended")
	}

	// Revoked: everything ends, the sign-in at once; the service is out of reach.
	revoked, unreachable = true, true
	delete(granted, "read")
	ended, err = l.Sweep(ctx, now)
	if err != nil || len(ended) != 2 {
		t.Fatalf("revoking: %+v %v", ended, err)
	}
	if n := l.Count(func(Lend) bool { return true }, now); n != 0 {
		t.Fatalf("%d lends still hold after revoking", n)
	}
	if _, err := l.Renew("sign_in", s.ID, "h", "a", ttl, now); !errors.Is(err, ErrNoLend) {
		t.Fatal("a revoked AI agent's sign-in lend was renewed")
	}
	// Ended, it can still be given back, for what its run sends back with it.
	if _, ok, _ := l.Find("sign_in", s.ID, "h", "a", now); !ok {
		t.Fatal("an ended sign-in lend was forgotten at once")
	}
	unreachable = false
	if _, err := l.Sweep(ctx, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(withdrawn) != 2 || withdrawn[1] != "read" {
		t.Fatalf("the withdrawal was not tried again: %v", withdrawn)
	}
	all, _ := l.All()
	for _, x := range all {
		if x.Kind == "tokens" {
			t.Fatalf("a token lend fully withdrawn is still remembered: %+v", x)
		}
	}
}

// A body holds one token lend at a time: lending it another ends the first.
func TestABodyHoldsOneTokenLendAtATime(t *testing.T) {
	var withdrawn []string
	unreachable := false
	l := New(&memStore{}, tokenService(map[string]bool{"t1": true, "t2": true, "t3": true}, &withdrawn, &unreachable))
	now := time.Now()
	first := lendTokens(t, l, "h", now, "t1")
	lendTokens(t, l, "other-host", now, "t3")
	lendTokens(t, l, "h", now, "t2")
	if len(withdrawn) != 1 || withdrawn[0] != "t1" {
		t.Fatalf("withdrawn: %v", withdrawn)
	}
	if _, ok, _ := l.Find("tokens", first.ID, "h", "a", now); ok {
		t.Fatal("the first lend is still held")
	}
	got, err := l.ReturnEvery(context.Background(), "tokens", "h", "a", now)
	if err != nil || len(got) != 1 || !got[0].Withdrawn {
		t.Fatalf("returning everything: %+v %v", got, err)
	}
	if n := l.Count(func(Lend) bool { return true }, now); n != 1 {
		t.Fatalf("another body's lend was returned with this one's: %d left", n)
	}
}

// EndAll ends every lend of one kind and says how many could not be
// withdrawn yet.
func TestEndingEveryLendOfAKind(t *testing.T) {
	var withdrawn []string
	unreachable := true
	l := New(&memStore{}, signIns, tokenService(map[string]bool{"t": true}, &withdrawn, &unreachable))
	now := time.Now()
	lendTokens(t, l, "h", now, "t")
	_, _, _ = lendSignIn(t, l, "a", "p", "h", 0, now)
	_, left, err := l.EndAll(context.Background(), "tokens", "disconnected", now)
	if err != nil || left != 1 {
		t.Fatalf("left %d %v", left, err)
	}
	if n := l.Count(func(x Lend) bool { return x.Kind == "sign_in" }, now); n != 1 {
		t.Fatal("ending one kind ended another")
	}
}

// The cap counts the pool, not the AI agent: two AI agents signed in to one
// account share its places; no cap means none; another pool never counts.
func TestACapCountsItsPool(t *testing.T) {
	l := New(&memStore{}, signIns)
	now := time.Now()
	if _, _, err := lendSignIn(t, l, "agent-a", "acct", "h1", 2, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lendSignIn(t, l, "agent-b", "acct", "h2", 2, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lendSignIn(t, l, "agent-c", "acct", "h3", 2, now); !errors.Is(err, ErrInUse) {
		t.Fatalf("a third AI agent on the same account ran past its cap of 2: %v", err)
	}
	if _, _, err := lendSignIn(t, l, "agent-c", "other", "h3", 2, now); err != nil {
		t.Fatalf("another account's runs counted against this one: %v", err)
	}
	for i := 0; i < 20; i++ {
		if _, _, err := lendSignIn(t, l, "keyed", "keyed-pool", "h", 0, now); err != nil {
			t.Fatal(err)
		}
	}
	if n := l.Count(func(x Lend) bool { return x.Pool == "acct" }, now); n != 2 {
		t.Fatalf("%d runs of the account in use, want 2", n)
	}
}
