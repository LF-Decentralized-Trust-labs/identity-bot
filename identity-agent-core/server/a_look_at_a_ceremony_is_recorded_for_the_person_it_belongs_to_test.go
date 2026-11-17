package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// The person who started an ownership change is told whether each invited
// owner's phone has looked at it, so a change that is stalling is visible. A
// look is the invite's code used on the routes a phone reads the ceremony from.
// It is proof the code was used and nothing more, and is kept only while the
// ceremony is under way.

func aLookWorld(t *testing.T) (*CoreServer, chi.Router, func(time.Time)) {
	t.Helper()
	s := ceremonyServer(t)
	r := chi.NewRouter()
	r.Get("/api/signer/invites/{token}/ceremony-terms", s.handleCeremonyTerms)
	r.Get("/api/signer/invites/{token}/ceremony-event", s.handleCeremonyEvent)
	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	was := ceremonyNow
	t.Cleanup(func() { ceremonyNow = was })
	ceremonyNow = func() time.Time { return now }
	ceremonyMu.Lock()
	if err := s.saveCeremony(collecting("Ada", "Grace")); err != nil {
		t.Fatal(err)
	}
	ceremonyMu.Unlock()
	return s, r, func(to time.Time) { now = to }
}

func look(r chi.Router, route, token string) int {
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/signer/invites/"+token+"/"+route, nil))
	return rec.Code
}

func lastSeen(t *testing.T, s *CoreServer) (ada, grace time.Time) {
	t.Helper()
	ceremonyMu.Lock()
	defer ceremonyMu.Unlock()
	c, err := s.loadCeremony()
	if err != nil || c == nil {
		t.Fatalf("no ceremony: %v", err)
	}
	at := func(p *time.Time) time.Time {
		if p == nil {
			return time.Time{}
		}
		return *p
	}
	return at(c.Invited[0].LastSeenAt), at(c.Invited[1].LastSeenAt)
}

func TestALookIsRecordedAgainstThePersonWhoseCodeItWas(t *testing.T) {
	s, r, _ := aLookWorld(t)
	look(r, "ceremony-terms", "tok-a")
	ada, grace := lastSeen(t, s)
	if want := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC); !ada.Equal(want) {
		t.Fatalf("Ada's look is %v, want %v", ada, want)
	}
	if !grace.IsZero() {
		t.Fatalf("Grace's look is %v though only Ada's code was used", grace)
	}
	// The route that gives the event counts too, whether or not there is one to give yet.
	look(r, "ceremony-event", "tok-b")
	if _, grace = lastSeen(t, s); grace.IsZero() {
		t.Fatal("a read of the event recorded no look")
	}
}

func TestACodeThatIsNobodysRecordsNothing(t *testing.T) {
	s, r, _ := aLookWorld(t)
	for _, tok := range []string{"tok-z", "", "tok-"} {
		look(r, "ceremony-terms", tok)
	}
	if ada, grace := lastSeen(t, s); !ada.IsZero() || !grace.IsZero() {
		t.Fatalf("a look was recorded for a code nobody holds: %v %v", ada, grace)
	}
}

// A phone that asks every few seconds does not rewrite the record every few seconds.
func TestALookIsWrittenOnceAMinute(t *testing.T) {
	s, r, at := aLookWorld(t)
	first := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	look(r, "ceremony-terms", "tok-a")
	at(first.Add(30 * time.Second))
	look(r, "ceremony-terms", "tok-a")
	if ada, _ := lastSeen(t, s); !ada.Equal(first) {
		t.Fatalf("a look half a minute later rewrote the record: %v", ada)
	}
	at(first.Add(61 * time.Second))
	look(r, "ceremony-terms", "tok-a")
	if ada, _ := lastSeen(t, s); !ada.Equal(first.Add(61 * time.Second)) {
		t.Fatalf("a look over a minute later was not recorded: %v", ada)
	}
}

// The owner's screen reads it from the ceremony the owner-only route gives.
func TestTheOwnerReadsWhenEachPhoneLastLooked(t *testing.T) {
	s, r, _ := aLookWorld(t)
	look(r, "ceremony-terms", "tok-a")
	rec := httptest.NewRecorder()
	s.handleGetCeremony(rec, httptest.NewRequest(http.MethodGet, "/api/owners/ceremony", nil))
	var out struct {
		Ceremony struct {
			Invited []struct {
				Name       string `json:"name"`
				LastSeenAt string `json:"last_seen_at"`
			} `json:"invited"`
		} `json:"ceremony"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rec.Body.String(), "0001-01-01T00:00:00Z\",\"") && strings.Contains(rec.Body.String(), `"last_seen_at":"0001`) {
		t.Fatalf("a look that was never made is written as a time: %s", rec.Body.String())
	}
	if len(out.Ceremony.Invited) != 2 || out.Ceremony.Invited[0].LastSeenAt == "" || out.Ceremony.Invited[1].LastSeenAt != "" {
		t.Fatalf("the owner's read does not say who looked: %s", rec.Body.String())
	}
}

// A ceremony that is over keeps no record of when anybody looked.
func TestNoLookIsKeptOnceTheCeremonyIsOver(t *testing.T) {
	for _, status := range []string{ceremonyApplied, ceremonyFailed, ceremonyAbandoned} {
		s, r, _ := aLookWorld(t)
		look(r, "ceremony-terms", "tok-a")
		ceremonyMu.Lock()
		c, _ := s.loadCeremony()
		c.Status = status
		if err := s.saveCeremony(c); err != nil {
			t.Fatal(err)
		}
		ceremonyMu.Unlock()
		if ada, grace := lastSeen(t, s); !ada.IsZero() || !grace.IsZero() {
			t.Errorf("a ceremony that is %s still records a look: %v %v", status, ada, grace)
		}
	}
}

// Nothing is recorded for a ceremony that is not under way, even for a real code.
func TestALookAtAFinishedCeremonyIsNotRecorded(t *testing.T) {
	s, r, _ := aLookWorld(t)
	ceremonyMu.Lock()
	c, _ := s.loadCeremony()
	c.Status = ceremonyApplied
	_ = s.saveCeremony(c)
	ceremonyMu.Unlock()
	look(r, "ceremony-terms", "tok-a")
	if ada, _ := lastSeen(t, s); !ada.IsZero() {
		t.Fatalf("a look at a finished ceremony was recorded: %v", ada)
	}
}

// How long a change has been waiting for signatures is counted from when the
// rotation being signed was prepared, and starts again for a hand-over's second.
func TestTheOwnerIsToldWhenTheRotationBeingSignedWasPrepared(t *testing.T) {
	first := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	second := first.Add(5 * time.Hour)
	was := ceremonyNow
	t.Cleanup(func() { ceremonyNow = was })
	now := first
	ceremonyNow = func() time.Time { return now }

	w := aCeremonyOfTwoDevices(t, true, false)
	if c := w.ceremony(t); c.StageSince == nil || !c.StageSince.Equal(first) {
		t.Fatalf("the first rotation was prepared at %v, the record says %v", first, c.StageSince)
	}
	now = second
	raw1, d1, _ := w.fetch(t, "tok-a")
	w.sign(t, "tok-a", d1, w.a[0].at(t, raw1, 1, -1))
	if code, _ := w.sign(t, "tok-c", d1, w.c[0].at(t, raw1, 2, -1)); code != http.StatusCreated {
		t.Fatalf("the first rotation was not signed: %d", code)
	}
	if c := w.ceremony(t); c.Stage != stageSecond || c.StageSince == nil || !c.StageSince.Equal(second) {
		t.Fatalf("the second rotation was prepared at %v, the record says %v", second, c.StageSince)
	}
}
