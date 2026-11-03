package vault

import "testing"

// The written rule for a host pattern: no port covers every port of the host,
// a port covers that port only; "*." is one label and "**." is one or more.
func TestMatchDomainReadsHostsAndPorts(t *testing.T) {
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
		if got := MatchDomain(c.pattern, c.domain); got != c.want {
			t.Errorf("MatchDomain(%q, %q) = %v, want %v", c.pattern, c.domain, got, c.want)
		}
	}
}
