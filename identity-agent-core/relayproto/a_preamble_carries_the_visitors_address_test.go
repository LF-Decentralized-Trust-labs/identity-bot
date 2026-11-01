package relayproto

import (
	"net/http"
	"strings"
	"testing"
)

// The Identity Agent sees the address the relay accepted the visitor from, in
// the preamble, and not one the visitor wrote in a header.
func TestThePreambleCarriesTheAddressTheRelayAccepted(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("acme.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic, Host: "acme.relay.test"})
	r.connect(id, http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		p, _ := PreambleFrom(q.Context())
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"visitor":"` + p.Visitor + `"}`))
	}))

	req, _ := http.NewRequest("GET", r.front.URL+"/x", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("Forwarded", "for=203.0.113.9")
	got := decode(t, r.do("acme.relay.test", req))
	if got["visitor"] != "127.0.0.1" {
		t.Fatalf("the preamble named the visitor %q, want the accepted connection's 127.0.0.1", got["visitor"])
	}
}

func TestVisitorAddrIsABareIPOrNothing(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.7:5000":          "192.0.2.7",
		"192.0.2.7":               "192.0.2.7",
		"[2001:db8::1]:443":       "2001:db8::1",
		"[::ffff:192.0.2.7]:1":    "192.0.2.7",
		"[fe80::1%eth0]:80":       "fe80::1",
		"":                        "",
		"not an address":          "",
		strings.Repeat("a", 5000): "",
	} {
		if got := VisitorAddr(in); got != want {
			t.Errorf("VisitorAddr(%q) = %q, want %q", in, got, want)
		}
	}
}
