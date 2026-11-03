package vault

import (
	"net/http"
	"testing"
)

// The written rule for a host pattern: no port covers every port of the host,
// a port covers that port only; "*." is one label and "**." is one or more.
func TestMatchHostPortReadsHostsAndPorts(t *testing.T) {
	for _, c := range []struct {
		pattern, domain string
		want            bool
	}{
		{"api.example.org", "api.example.org", true},
		{"api.example.org", "API.example.org", true},
		{"api.example.org", "api.example.org:8443", true}, // no port: any port
		{"api.example.org", "api.example.org:443", true},
		{"api.example.org", "other.example.org", false},
		{"api.example.org:8443", "api.example.org:8443", true}, // a port: that port only
		{"api.example.org:8443", "api.example.org:443", false},
		{"api.example.org:8443", "api.example.org", false},
		{"*.example.org", "a.example.org", true},
		{"*.example.org", "a.example.org:9", true},
		{"*.example.org", "a.b.example.org", false},
		{"*.example.org", "example.org", false},
		{"*.example.org", ".example.org", false},
		{"*.example.org:8080", "a.example.org:8080", true},
		{"*.example.org:8080", "a.example.org:80", false},
		{"**.example.org", "a.example.org", true},
		{"**.example.org", "a.b.example.org:1", true},
		{"**.example.org", "example.org", false},
		{"**.example.org", ".example.org", false},
		{"**.example.org:443", "a.b.example.org:443", true},
		{"**.example.org:443", "a.b.example.org:444", false},
		{"**.example.org:443", "a.b.example.org", false},
		{"*", "a", false},
		{"**", "a", false},
		{"", "", false},
		{"a.example.org", "xa.example.org", false},
	} {
		host, port, _ := splitHostPort(c.domain)
		if got := MatchHostPort(c.pattern, host, port); got != c.want {
			t.Errorf("MatchHostPort(%q, %q, %q) = %v, want %v", c.pattern, host, port, got, c.want)
		}
	}
}

// The vault passes the port a request is dialled on, so a credential whose
// domain names a port is injected on that port only, and the scheme's default
// stands in when the URL names none.
func TestDestinationHostPort(t *testing.T) {
	for _, c := range []struct{ url, host, port string }{
		{"https://API.example.org/x", "api.example.org", "443"},
		{"http://api.example.org/x", "api.example.org", "80"},
		{"https://api.example.org:8443/x", "api.example.org", "8443"},
	} {
		req, _ := http.NewRequest("GET", c.url, nil)
		if h, p := destinationHostPort(req); h != c.host || p != c.port {
			t.Errorf("%s: got %s:%s, want %s:%s", c.url, h, p, c.host, c.port)
		}
	}
	for _, c := range []struct {
		url  string
		want bool
	}{
		{"https://api.example.org:8443/x", true},
		{"https://api.example.org/x", false},
		{"https://api.example.org:9443/x", false},
	} {
		req, _ := http.NewRequest("GET", c.url, nil)
		h, p := destinationHostPort(req)
		if got := MatchHostPort("api.example.org:8443", h, p); got != c.want {
			t.Errorf("%s: %v, want %v", c.url, got, c.want)
		}
	}
}
