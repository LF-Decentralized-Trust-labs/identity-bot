package anchored

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"identity-agent-core/witness"
)

// fakeWitnesses answer as witness.Service.AskTips does: each witness gets a
// nonce made for this question, and signs the tip with it.
type fakeWitnesses struct {
	p        *publisher
	tip      Tip
	n        int
	asked    int
	designed [][]string
	nonces   []string
	replay   []witness.AskedTip // when set, answers from an earlier question
}

func (f *fakeWitnesses) AskTips(_ context.Context, aid string, designated []string) []witness.AskedTip {
	f.asked++
	f.designed = append(f.designed, designated)
	if f.replay != nil {
		return f.replay
	}
	var out []witness.AskedTip
	for i := 0; i < f.n; i++ {
		r := f.p.answer(i, f.tip, nonce())
		f.nonces = append(f.nonces, r.Nonce)
		out = append(out, witness.AskedTip{Nonce: r.Nonce, Answer: r.Answer})
	}
	return out
}

func checkerFor(t *testing.T, p *publisher) *Checker {
	return &Checker{Pin: p.pin(), Store: FileFloors{Path: filepath.Join(t.TempDir(), "f")}}
}

func TestTheWitnessesAreAskedAfterTheHistoryIsKnownGoodAndWithTheOnesItNames(t *testing.T) {
	p := onekey(t)
	published(p, 7)
	f := &fakeWitnesses{p: p, tip: p.tip(), n: 2}
	c := checkerFor(t, p)
	res, err := c.CheckAsking(p.bundle(), Resolver{Witnesses: f}.Asker(context.Background()), now)
	if err != nil || res.List.Sequence != 7 {
		t.Fatalf("a good bundle with live witnesses was refused: %v", err)
	}
	var names []string
	for _, w := range p.witness {
		names = append(names, w.pub)
	}
	if f.asked != 1 || !slices.Equal(slices.Sorted(slices.Values(f.designed[0])), slices.Sorted(slices.Values(names))) {
		t.Fatalf("asked %d times, designated %v, history names %v", f.asked, f.designed, names)
	}
	// a history that is not genuine is refused before anybody is asked
	f2 := &fakeWitnesses{p: p, tip: p.tip(), n: 2}
	bad := p.bundle()
	bad.KEL = bad.KEL[:0]
	if _, err := checkerFor(t, p).CheckAsking(bad, Resolver{Witnesses: f2}.Asker(context.Background()), now); err == nil || f2.asked != 0 {
		t.Fatalf("a bundle with no history: %v, witnesses asked %d times", err, f2.asked)
	}
}

// each question carries nonces made for it: a second check never reuses the
// first's, and an answer to an earlier question is not an answer to this one
func TestAnAnswerToAnEarlierQuestionIsNotFresh(t *testing.T) {
	p := onekey(t)
	published(p, 7)
	f := &fakeWitnesses{p: p, tip: p.tip(), n: 2}
	for i := 0; i < 2; i++ {
		if _, err := checkerFor(t, p).CheckAsking(p.bundle(), Resolver{Witnesses: f}.Asker(context.Background()), now); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	for _, n := range f.nonces {
		if seen[n] || len(n) < MinNonceLen {
			t.Fatalf("a nonce was reused or too short: %q", n)
		}
		seen[n] = true
	}
	// the answers the witnesses gave to a question the device is not asking now
	old := &fakeWitnesses{p: p, tip: p.tip(), n: 2}
	stale := old.AskTips(context.Background(), p.aid, nil)
	// the asker records the nonce it sent as the one it sent; a replayed answer
	// carries a nonce the answer does not match once the device's own differs
	for i := range stale {
		stale[i].Nonce = nonce() // what this device sent now is not what the witness signed
	}
	g := &fakeWitnesses{p: p, replay: stale}
	if _, err := checkerFor(t, p).CheckAsking(p.bundle(), Resolver{Witnesses: g}.Asker(context.Background()), now); !errors.Is(err, ErrNotFresh) {
		t.Fatalf("replayed answers: %v", err)
	}
	// witnesses that cannot be reached are not fresh either
	if _, err := checkerFor(t, p).CheckAsking(p.bundle(), Resolver{Witnesses: &fakeWitnesses{p: p, n: 0}}.Asker(context.Background()), now); !errors.Is(err, ErrNotFresh) {
		t.Fatalf("no witness answered: %v", err)
	}
	// and with no one to ask at all
	if _, err := checkerFor(t, p).CheckAsking(p.bundle(), nil, now); !errors.Is(err, ErrNotFresh) {
		t.Fatalf("nobody to ask: %v", err)
	}
}

// the witnesses hold an older tip than the bundle's: the bundle goes past them
func TestTheWitnessesHoldingAnotherTipRefuseTheBundle(t *testing.T) {
	p := onekey(t)
	published(p, 7)
	held := tipAt(p, 1)
	published(p, 8)
	c := checkerFor(t, p)
	if _, err := c.CheckAsking(p.bundle(), Resolver{Witnesses: &fakeWitnesses{p: p, tip: held, n: 2}}.Asker(context.Background()), now); !errors.Is(err, ErrAhead) {
		t.Fatalf("witnesses behind the bundle: %v", err)
	}
	if _, err := c.CheckAsking(p.bundle(), Resolver{Witnesses: &fakeWitnesses{p: p, tip: p.tip(), n: 2}}.Asker(context.Background()), now); err != nil {
		t.Fatalf("the witnesses' own tip was refused: %v", err)
	}
}
