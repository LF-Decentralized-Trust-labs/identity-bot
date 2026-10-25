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
