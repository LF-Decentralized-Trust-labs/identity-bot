package relay

import (
	"testing"
)

func TestCanonicalBodyStable(t *testing.T) {
	body := map[string]interface{}{
		"v": JSONVersion, "raid": "ERAID", "intent": "serve-didwebs-artifacts",
		"signed_by": "EEnrollment", "ttl_hint": "persistent",
	}
	a, err := canonicalBody(body)
	if err != nil {
		t.Fatal(err)
	}
	b, err := canonicalBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("canonical unstable: %s vs %s", a, b)
	}
}