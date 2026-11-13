package anchored

import (
	"errors"
	"testing"
)

// The freshness guard is what stops a stale bundle, or one from a forked
// history, being taken for current. Each case below is one the guard must hold
// with nothing else in the way: the answer is otherwise exactly what a good one
// is (for this publisher, with the nonce asked, from a designated witness).

func TestAnAnswerWithAForgedSignatureIsNotAnAnswer(t *testing.T) {
	p := onekey(t)
	published(p, 7)
	old := p.bundle()
	oldTip := p.tip()
	c8, _ := published(p, 8)
	p.revoke(c8) // what the stale bundle hides

	// forged: the old tip, named by the designated witnesses, with the nonce
	// that was asked, but a signature that is not theirs for that statement
	forge := func(sig func(i int) string) []TipReply {
		var out []TipReply
		for i := 0; i < 2; i++ {
			r := p.answer(i, oldTip, nonce())
			r.Answer.Signature = sig(i)
			out = append(out, r)
		}
		return out
	}
	t.Run("a signature made for another statement", func(t *testing.T) {
		refuse(t, "forged answers naming the old tip", ErrNotFresh, old, p.pin(), forge(func(i int) string {
			return p.answer(i, p.tip(), nonce()).Answer.Signature
		}), Floors{})
	})
	t.Run("a signature by another key", func(t *testing.T) {
		refuse(t, "forged answers signed by a stranger", ErrNotFresh, old, p.pin(), forge(func(int) string {
			q := onekey(t)
			q.aid = p.aid
			return q.answer(0, oldTip, nonce()).Answer.Signature
		}), Floors{})
	})
	t.Run("no signature", func(t *testing.T) {
		refuse(t, "unsigned answers", ErrNotFresh, old, p.pin(), forge(func(int) string { return "" }), Floors{})
	})
	t.Run("the genuine answers are accepted for the same bundle at the old tip", func(t *testing.T) {
		q := onekey(t)
		published(q, 7)
		if _, err := Verify(q.bundle(), q.pin(), q.answers(q.tip(), 2), Floors{}, now); err != nil {
			t.Fatalf("control: %v", err)
		}
	})
}

func TestWitnessesNamingAnotherEventAtTheBundlesTipAreDuplicity(t *testing.T) {
	p := onekey(t)
	published(p, 7)
	mine := p.tip()
	other := Tip{SN: mine.SN, SAID: "EBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}
	// every witness agrees, validly signed, with the nonce asked: at the place
	// the bundle ends they hold a different event
	err := refuse(t, "a fork at the tip", ErrDuplicity, p.bundle(), p.pin(), p.answers(other, 2), Floors{})
	var d *Duplicity
	if !errors.As(err, &d) || d.SN != mine.SN || d.Held != other.SAID || d.Offered != mine.SAID || len(d.Message) == 0 {
		t.Fatalf("the evidence is not both events: %+v (%v)", d, err)
	}
}

func errorsIs(err, target error) bool { return errors.Is(err, target) }
