package witness

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"identity-agent-core/store"
)

// A withdrawal request or confirmation follows the same rule as a witness
// request: a local address the owner recorded is called, one a stranger's
// request left behind is not.
func TestWithdrawalsAreNotSentToAStrangersLocalAddress(t *testing.T) {
	const aid = "EController000000000000000000000000000000000041"
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); w.Write([]byte(`{}`)) }))
	defer srv.Close()

	for source, wantSent := range map[string]bool{"keri": true, ContactSourceInbound: false} {
		hits.Store(0)
		s, _, _ := answerer(t, map[string]store.ContactRecord{aid: {AID: aid, OobiURL: srv.URL + "/public/oobi/" + aid, ContactSource: source}})
		s.PostEvent = s.defaultPostEvent
		err := s.ConfirmWithdrawal(context.Background(), aid, WithdrawalConfirmation{})
		if wantSent != (err == nil) || wantSent != (hits.Load() == 1) {
			t.Errorf("ConfirmWithdrawal with source %q: err=%v hits=%d, want sent=%v", source, err, hits.Load(), wantSent)
		}
		if err := s.Store.SaveContactMeta(ContactMeta{ContactAID: aid, WitnessingFor: true}); err != nil {
			t.Fatal(err)
		}
		hits.Store(0)
		err = s.RequestWithdrawal(context.Background(), aid, WithdrawalShuttingDown)
		if wantSent != (err == nil) || wantSent != (hits.Load() == 1) {
			t.Errorf("RequestWithdrawal with source %q: err=%v hits=%d, want sent=%v", source, err, hits.Load(), wantSent)
		}
	}
}
