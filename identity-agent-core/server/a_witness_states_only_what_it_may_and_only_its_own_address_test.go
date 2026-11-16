package server

import (
	"encoding/json"
	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
	"net/http"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/endpoint"
)

func keyStateOf(t *testing.T, base, path, witnessKey, aid string, headers func(*http.Request)) witnessproto.KeyState {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+path, nil)
	if headers != nil {
		headers(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d", path, resp.StatusCode)
	}
	var ans witnessproto.SignedReply
	if err := json.NewDecoder(resp.Body).Decode(&ans); err != nil {
		t.Fatal(err)
	}
	st, err := witnessproto.VerifyKeyStateNotice(ans, witnessKey, aid, time.Now())
	if err != nil {
		t.Fatalf("GET %s: the notice does not verify: %v", path, err)
	}
	return st
}

// The key state notice is answered as for a log not held unless the asker may
// read the log: a stranger gets the same signed answer for an identity this
// witness holds as for one it never heard of.
func TestAStrangerIsGivenTheNoticeOfALogNotHeld(t *testing.T) {
	bob, c := witnessedController(t)
	base := servedThroughTheRealRouter(t, bob)
	const unknown = "EnotWitnessedByAnybodyAtAllAAAAAAAAAAAAAAAAAAA"

	stranger := keyStateOf(t, base, "/api/witness/ksn/"+c.aid, bob.witnessKey, c.aid, nil)
	if stranger.SN != -1 || stranger.SAID != "" {
		t.Fatalf("a stranger learned what the witness holds: %+v", stranger)
	}
	if never := keyStateOf(t, base, "/api/witness/ksn/"+unknown, bob.witnessKey, unknown, nil); never.SN != stranger.SN || never.SAID != stranger.SAID {
		t.Fatalf("a held log and one never heard of were answered differently: %+v and %+v", stranger, never)
	}

	// The identity itself, by its key, and a verifier that presents the log's
	// inception, are told.
	target := base + "/api/witness/ksn/" + c.aid
	resp := c.signedGet(t, target, c.aid, c.signers[0], time.Now())
	defer resp.Body.Close()
	var ans witnessproto.SignedReply
	if err := json.NewDecoder(resp.Body).Decode(&ans); err != nil {
		t.Fatal(err)
	}
	if st, err := witnessproto.VerifyKeyStateNotice(ans, bob.witnessKey, c.aid, time.Now()); err != nil || st.SN != 0 {
		t.Fatalf("the identity was not told what its witness holds: %v %+v", err, st)
	}
	other, _ := keri.GenerateSigner(true)
	resp2 := c.signedGet(t, target, c.aid, other, time.Now())
	defer resp2.Body.Close()
	var ans2 witnessproto.SignedReply
	_ = json.NewDecoder(resp2.Body).Decode(&ans2)
	if st, err := witnessproto.VerifyKeyStateNotice(ans2, bob.witnessKey, c.aid, time.Now()); err != nil || st.SN != -1 {
		t.Fatalf("a signature by another key opened the notice: %v %+v", err, st)
	}
}

// A witness states where it is reached only for itself, and only at an address
// it knows itself by; what the request says it was addressed to is whatever its
// sender wrote.
func TestAWitnessSignsItsOwnAddressAndNoOtherAndNoneItDoesNotKnow(t *testing.T) {
	bob := startPeer(t, "bob")
	base := servedThroughTheRealRouter(t, bob)
	status := func(path string, host string) (int, *witnessproto.SignedReply) {
		req, _ := http.NewRequest(http.MethodGet, base+path, nil)
		if host != "" {
			req.Host = host
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var ans witnessproto.SignedReply
		if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&ans) != nil {
			return resp.StatusCode, nil
		}
		return resp.StatusCode, &ans
	}

	// An agent that knows no address of its own signs none.
	if code, _ := status("/api/witness/loc/"+bob.witnessKey, "evil.example"); code == http.StatusOK {
		t.Fatal("a location was signed for an agent that knows no address of its own, from the request's say-so")
	}

	bob.core.EndpointService = endpoint.New(nil, 0)
	bob.core.EndpointService.SetOverrideURL("https://bob.example")

	// Another witness's key is not asked of this one.
	if code, _ := status("/api/witness/loc/"+bob.witnessKey+"x", ""); code == http.StatusOK {
		t.Fatal("a location was signed for a witness this is not")
	}
	// Its own, at the address it knows itself by, whatever the request was addressed to.
	code, ans := status("/api/witness/loc/"+bob.witnessKey, "evil.example")
	if code != http.StatusOK || ans == nil {
		t.Fatalf("the witness would not state its own location: %d", code)
	}
	loc, err := witnessproto.VerifyWitnessLocation(*ans, bob.witnessKey)
	if err != nil || loc.URL != "https://bob.example" {
		t.Fatalf("the location was %+v (%v), not the address the agent knows itself by", loc, err)
	}
}
