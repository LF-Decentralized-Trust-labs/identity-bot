package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
)

func aGateAnswering(readWithin time.Duration) (*keyLogGate, http.HandlerFunc) {
	g := newKeyLogGate()
	g.readWithin = readWithin
	return g, g.guard(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})
}

// Four callers that start sending a key log and never finish must not leave
// an honest caller told to come back. The body is read before a checking slot
// is taken, so a sender that stalls holds only its own connection, and loses
// it when the read deadline passes.
func TestCallersThatNeverFinishSendingHoldNoSlot(t *testing.T) {
	_, h := aGateAnswering(300 * time.Millisecond)
	srv := httptest.NewServer(h)
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	for i := 0; i < keyLogChecksAtOnce; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		// A request that promises a body and sends only part of it.
		fmt.Fprintf(c, "POST /public/login/key HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n{\"aid\":")
	}
	time.Sleep(50 * time.Millisecond) // the stalled requests are in

	resp, err := http.Post(srv.URL+"/public/login/key", "application/json", strings.NewReader(`{"aid":"E"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("an honest caller was answered %d while four stalled senders were waiting", resp.StatusCode)
	}
}

// Through the URL relay every caller arrives from the relay's own address.
// Relayed requests draw on a budget of their own, so a burst through the
// relay does not use up a direct caller's share, and the reverse.
func TestRelayedCallersDoNotUseUpDirectCallersShares(t *testing.T) {
	_, h := aGateAnswering(time.Second)
	call := func(relayed bool) int {
		r := httptest.NewRequest(http.MethodPost, "/public/login/key", strings.NewReader(`{}`))
		if relayed {
			r = r.WithContext(relayproto.ContextWithPreamble(r.Context(),
				relayproto.Preamble{Allocation: "a", Mode: relayproto.ModePublic}))
		}
		w := httptest.NewRecorder()
		h(w, r)
		return w.Code
	}
	limited := false
	for i := 0; i < keyLogChecksPerMinuteRelayed+1; i++ {
		if call(true) == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatalf("relayed requests were never limited")
	}
	if code := call(false); code != http.StatusOK {
		t.Fatalf("a direct caller from the same address was answered %d after the relay's budget ran out", code)
	}
}

func relayedCall(h http.HandlerFunc, visitor, forwardedFor string) int {
	r := httptest.NewRequest(http.MethodPost, "/public/login/key", strings.NewReader(`{}`))
	if forwardedFor != "" {
		r.Header.Set("X-Forwarded-For", forwardedFor)
	}
	r = r.WithContext(relayproto.ContextWithPreamble(r.Context(),
		relayproto.Preamble{Allocation: "a", Mode: relayproto.ModePublic, Visitor: visitor}))
	w := httptest.NewRecorder()
	h(w, r)
	return w.Code
}

// When the relay passes on the visitor's address, a relayed caller who uses up
// their share does not stop a second relayed caller.
func TestOneRelayedCallerUsingTheirShareDoesNotStopAnother(t *testing.T) {
	_, h := aGateAnswering(time.Second)
	limited := false
	for i := 0; i < keyLogChecksPerMinute+1; i++ {
		if relayedCall(h, "192.0.2.1", "") == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatalf("a relayed caller was never limited")
	}
	if code := relayedCall(h, "192.0.2.2", ""); code != http.StatusOK {
		t.Fatalf("a second relayed caller was answered %d after the first used up their share", code)
	}
}

// A header the visitor sets names nobody: the share is the preamble's address.
func TestAForwardingHeaderTheVisitorSetsIsIgnored(t *testing.T) {
	_, h := aGateAnswering(time.Second)
	for i := 0; i < keyLogChecksPerMinute; i++ {
		// Each call claims a different address; none may buy a fresh share.
		relayedCall(h, "192.0.2.1", fmt.Sprintf("198.51.100.%d", i%250))
	}
	if code := relayedCall(h, "192.0.2.1", "198.51.100.250"); code != http.StatusTooManyRequests {
		t.Fatalf("a caller got %d by writing a new X-Forwarded-For", code)
	}
	if code := relayedCall(h, "192.0.2.2", "192.0.2.1"); code != http.StatusOK {
		t.Fatalf("a caller was answered %d because a header named someone else's address", code)
	}
}

// A preamble with no address, from an older relay, keeps the one shared
// relayed budget; so does one whose address is not an address.
func TestAPreambleWithNoAddressUsesTheSharedRelayedBudget(t *testing.T) {
	for _, visitor := range []string{"", "not-an-address"} {
		_, h := aGateAnswering(time.Second)
		for i := 0; i < keyLogChecksPerMinute+10; i++ {
			if code := relayedCall(h, visitor, ""); code != http.StatusOK {
				t.Fatalf("visitor %q: call %d answered %d, inside the shared relayed budget", visitor, i, code)
			}
		}
		limited := false
		for i := 0; i < keyLogChecksPerMinuteRelayed; i++ {
			if relayedCall(h, visitor, "") == http.StatusTooManyRequests {
				limited = true
				break
			}
		}
		if !limited {
			t.Fatalf("visitor %q: the shared relayed budget was never used up", visitor)
		}
	}
}

// A relay that names a new visitor on every request gets a fresh share each
// time, but every relayed request also counts against the one relayed budget.
func TestARelayNamingANewVisitorEachTimeIsStoppedByTheRelayedBudget(t *testing.T) {
	_, h := aGateAnswering(time.Second)
	limited := false
	for i := 0; i < keyLogChecksPerMinuteRelayed+1; i++ {
		visitor := fmt.Sprintf("10.%d.%d.1", i/250, i%250)
		if relayedCall(h, visitor, "") == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatalf("%d requests, each naming a different visitor, were never limited", keyLogChecksPerMinuteRelayed+1)
	}
}

// One visitor holds a whole IPv6 /64, so its addresses share one budget; an
// address in another /64 has its own.
func TestRelayedIPv6VisitorsShareTheirSixtyFour(t *testing.T) {
	_, h := aGateAnswering(time.Second)
	for i := 0; i < keyLogChecksPerMinute; i++ {
		if code := relayedCall(h, fmt.Sprintf("2001:db8:1:2::%x", i+1), ""); code != http.StatusOK {
			t.Fatalf("call %d answered %d inside the share", i, code)
		}
	}
	if code := relayedCall(h, "2001:db8:1:2:ffff::9", ""); code != http.StatusTooManyRequests {
		t.Fatalf("another address in the same /64 was answered %d, not told to come back", code)
	}
	if code := relayedCall(h, "2001:db8:1:3::1", ""); code != http.StatusOK {
		t.Fatalf("an address in a different /64 was answered %d", code)
	}
}

// An entry is filed under the identity it holds, but the file name is only
// where it was put. One identity's entry written under another's name is not
// answered for that other identity when the registry is loaded again.
func TestAnEntryFiledUnderAnotherIdentitysNameIsNotBelieved(t *testing.T) {
	dir := t.TempDir()
	x, _, _ := theirKeyLog(t, 1000501)
	_, yLog, yPub := theirKeyLog(t, 1000502)
	if err := os.MkdirAll(filepath.Join(dir, "registered_keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	entry, _ := json.Marshal(registeredKey{KeyLog: yLog, PublicKeyB64: yPub})
	if err := os.WriteFile(filepath.Join(dir, "registered_keys", x+".json"), entry, 0o600); err != nil {
		t.Fatal(err)
	}
	registry := theOrganisationsRegistry(t, &CoreServer{DataDir: dir})
	if got := publishedKey(t, registry, x); got != "" {
		t.Fatalf("another identity's key, filed under this one's name, was answered for it: %s", got)
	}
}
