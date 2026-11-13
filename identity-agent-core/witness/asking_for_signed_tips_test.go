package witness

import (
	"context"
	"strings"
	"testing"

	"identity-agent-core/store"
)

// AskTips sends each witness a nonce made for that question, and returns each
// answer with the nonce it was asked with; a witness it does not know is left out.
func TestAskTipsGivesEveryWitnessAFreshNonceOfItsOwn(t *testing.T) {
	d := newDelegation(t)
	s, mc := testService(t)
	mc.contacts["EWitness"] = store.ContactRecord{AID: "EWitness", OobiURL: "http://w.test", IsWitness: true}
	_ = s.Store.SaveContactMeta(ContactMeta{ContactAID: "EWitness", WitnessKey: d.wkey})
	var sent []string
	s.FetchTip = func(_ context.Context, url string) (TipAnswer, error) {
		_, nonce, _ := strings.Cut(url, "?nonce=")
		sent = append(sent, nonce)
		return d.w.KelTip(d.org, nonce, true)
	}
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		got := s.AskTips(context.Background(), d.org, []string{d.wkey, "an-unknown-witness"})
		if len(got) != 1 || got[0].Nonce == "" || got[0].Answer.Nonce != got[0].Nonce || len(got[0].Nonce) < 16 {
			t.Fatalf("answers %+v", got)
		}
		if seen[got[0].Nonce] {
			t.Fatalf("nonce %q was used twice", got[0].Nonce)
		}
		seen[got[0].Nonce] = true
	}
	if len(sent) != 3 {
		t.Fatalf("an unknown witness was asked: %v", sent)
	}
}
