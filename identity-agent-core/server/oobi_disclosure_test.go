package server

import (
	"os"
	"regexp"
	"testing"
)

// The OOBI endpoint is served unauthenticated to anyone who knows the AID, and
// the whole router is reachable while a tunnel is up. Nothing personal may ride
// along by default.
//
// This guards the handler source itself rather than the response, because the
// defect being prevented is a line of code re-attaching personal data — which a
// response-shape test would only catch if the fixture happened to populate a
// profile. Cheap, and it fails loudly on reintroduction.
func TestOobiServeDisclosesNoPersonalData(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}

	body := extractFunc(string(src), "func (s *CoreServer) handleOobiServe(")
	if body == "" {
		t.Fatal("could not locate handleOobiServe — did it move? update this test")
	}
	body = stripComments(body)

	// Each of these previously appeared in the response and disclosed personal
	// data to unauthenticated callers.
	for _, banned := range []string{
		`resp["jcard"]`,
		`resp["photo"]`,
		"ToJCard",
		"profile.Photo",
		"profile.FullName",
	} {
		if contains(body, banned) {
			t.Errorf("handleOobiServe references %q — the public OOBI must not disclose "+
				"personal data. Personal data reaches a counterparty through a consented "+
				"exchange, never through an unauthenticated OOBI fetch.", banned)
		}
	}
}

func extractFunc(src, sig string) string {
	i := indexOf(src, sig)
	if i < 0 {
		return ""
	}
	depth, start := 0, -1
	for j := i; j < len(src); j++ {
		switch src[j] {
		case '{':
			if start < 0 {
				start = j
			}
			depth++
		case '}':
			depth--
			if depth == 0 && start >= 0 {
				return src[start : j+1]
			}
		}
	}
	return ""
}

var commentRe = regexp.MustCompile(`(?m)//.*$`)

func stripComments(s string) string { return commentRe.ReplaceAllString(s, "") }

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

func contains(h, n string) bool { return indexOf(h, n) >= 0 }
