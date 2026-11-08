package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"identity-agent-core/witness"

	keri "github.com/grapeid/keri-go"
)

// The key-log reads on a witness are open to peers, and what a witness holds
// is who it witnesses. A stranger must get the same answer for a log that is
// held as for one that is not.

// signedGet reads target as reader, signing with signer, with the stamp given.
func (c *rotatingController) signedGet(t *testing.T, target, reader string, signer keri.Signer, at time.Time) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	stamp := at.UTC().Format(time.RFC3339Nano)
	req.Header.Set(witness.HeaderReader, reader)
	req.Header.Set(witness.HeaderReadStamp, stamp)
	req.Header.Set(witness.HeaderReadSignature,
		sign(t, signer, []byte(witness.ReadStatement(reader, req.URL.Host, witness.ReadTarget(req.URL.RequestURI()), stamp))))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func get(t *testing.T, target string) (int, string) {
	t.Helper()
	resp, err := http.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestAStrangerCannotTellAWitnessedIdentityFromOneItDoesNotWitness(t *testing.T) {
	bob, c := witnessedController(t)
	base := servedThroughTheRealRouter(t, bob)
	const unknown = "EnotWitnessedByAnybodyAtAllAAAAAAAAAAAAAAAAAAA"

	for _, tail := range []string{"", "/event/0"} {
		hs, hb := get(t, base+"/api/witness/kel/"+c.aid+tail)
		us, ub := get(t, base+"/api/witness/kel/"+unknown+tail)
		if hs != us || hb != ub {
			t.Errorf("GET kel%s: held answered %d %q, not held answered %d %q", tail, hs, hb, us, ub)
		}
		if hs == http.StatusOK {
			t.Errorf("GET kel%s gave a stranger the log", tail)
		}
	}
	tip := func(aid string) witness.TipAnswer {
		status, body := get(t, base+"/api/witness/kel/"+aid+"/tip?nonce=n")
		var a witness.TipAnswer
		if status != http.StatusOK || json.Unmarshal([]byte(body), &a) != nil {
			t.Fatalf("tip for %s: %d %s", aid, status, body)
		}
		return a
	}
	if h, u := tip(c.aid), tip(unknown); h.SN != -1 || h.SAID != "" || u.SN != -1 || u.SAID != "" {
		t.Errorf("a stranger learned the tip: held %+v, not held %+v", h, u)
	}
}

func TestOnlyTheIdentityItselfIsAnsweredFromWhatIsHeld(t *testing.T) {
	bob, c := witnessedController(t)
	base := servedThroughTheRealRouter(t, bob)
	target := base + "/api/witness/kel/" + c.aid
	other, _ := keri.GenerateSigner(true)

	for name, tc := range map[string]struct {
		reader string
		signer keri.Signer
		at     time.Time
		want   int
	}{
		"the identity, by its key":           {c.aid, c.signers[0], time.Now(), http.StatusOK},
		"the identity, a stale signature":    {c.aid, c.signers[0], time.Now().Add(-time.Hour), http.StatusNotFound},
		"the identity, another party's key":  {c.aid, other, time.Now(), http.StatusNotFound},
		"another identity, by its own key":   {"Eanother", other, time.Now(), http.StatusNotFound},
		"the identity, key not yet in force": {c.aid, c.signers[1], time.Now(), http.StatusNotFound},
	} {
		resp := c.signedGet(t, target, tc.reader, tc.signer, tc.at)
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("%s: got %d, want %d", name, resp.StatusCode, tc.want)
		}
	}
	// A signature for one address does not open another.
	resp := c.signedGet(t, target, c.aid, c.signers[0], time.Now())
	resp.Body.Close()
	req, _ := http.NewRequest(http.MethodGet, base+"/api/witness/kel/"+c.aid+"/tip?nonce=n", nil)
	for _, h := range []string{witness.HeaderReader, witness.HeaderReadStamp, witness.HeaderReadSignature} {
		req.Header.Set(h, resp.Request.Header.Get(h))
	}
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	var a witness.TipAnswer
	_ = json.NewDecoder(r2.Body).Decode(&a)
	if a.SN != -1 {
		t.Errorf("a signature made for one read opened another: %+v", a)
	}
}

func TestTheWitnessRoutesThatCostWorkAreRateLimited(t *testing.T) {
	bob, c := witnessedController(t)
	base := servedThroughTheRealRouter(t, bob)

	limited := func(do func() int) bool {
		for i := 0; i < 200; i++ {
			if do() == http.StatusTooManyRequests {
				return true
			}
		}
		return false
	}
	// Each is tried on a fresh agent so that the routes do not share a count
	// with the others in this test: the limit is per route family, per agent.
	if !limited(func() int {
		s, _ := get(t, fmt.Sprintf("%s/api/witness/kel/%s/tip?nonce=%s", base, c.aid, url.QueryEscape("n")))
		return s
	}) {
		t.Error("/api/witness/kel/{aid}/tip was never rate limited")
	}
	bob2, _ := witnessedController(t)
	base2 := servedThroughTheRealRouter(t, bob2)
	if !limited(func() int {
		resp, err := http.Post(base2+"/api/witness/event", "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}) {
		t.Error("/api/witness/event was never rate limited")
	}
}

func TestAnIPv6CallerCannotFillTheLimiterWithAddresses(t *testing.T) {
	lim := newIPRateLimiter(60, time.Minute)
	for i := 0; i < maxRateLimitedClients*2; i++ {
		lim.allow(fmt.Sprintf("2001:db8:1:2:%x::%x", i, i+1)) // all in 2001:db8:1:2::/64
	}
	if n := lim.w.Keys(); n != 1 {
		t.Fatalf("one /64 held %d slots in the limiter", n)
	}
	if !lim.allow("2001:db8:ffff::1") {
		t.Fatal("a caller from another network was refused")
	}
	// A v4 address still counts as itself.
	lim.allow("203.0.113.9")
	lim.allow("203.0.113.10")
	if n := lim.w.Keys(); n != 4 {
		t.Fatalf("want 4 callers, got %d", n)
	}
}

// The Identity Agent's own fetches carry the proof, so the controller is
// still answered by its witness while a stranger is not.
func TestTheAgentsOwnFetchesAreAnsweredAsTheController(t *testing.T) {
	bob, c := witnessedController(t)
	base := servedThroughTheRealRouter(t, bob)

	reader := startPeer(t, "reader").svc
	reader.OurAID = func() string { return c.aid }
	reader.SignAsRequester = func(statement string) (string, error) {
		return sign(t, c.signers[0], []byte(statement)), nil
	}
	ctx := t.Context()
	tip, err := reader.FetchTip(ctx, base+"/api/witness/kel/"+c.aid+"/tip?nonce=n1")
	if err != nil || tip.SN != 0 {
		t.Fatalf("the controller's tip fetch: %+v, %v", tip, err)
	}
	if ev, err := reader.FetchEvent(ctx, base+"/api/witness/kel/"+c.aid+"/event/0"); err != nil || ev.RawBytesB64 == "" {
		t.Fatalf("the controller's event fetch: %+v, %v", ev, err)
	}
	reader.SignAsRequester = nil
	if ev, err := reader.FetchEvent(ctx, base+"/api/witness/kel/"+c.aid+"/event/0"); err == nil {
		t.Fatalf("an unsigned fetch was answered: %+v", ev)
	}
}
