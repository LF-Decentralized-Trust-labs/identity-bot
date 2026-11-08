package witnessproto

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestTheSignedDigestStatementIsTheSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("kel-digest-statement-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []struct {
		Name      string  `json:"name"`
		AID       string  `json:"aid"`
		Seq       int     `json:"seq"`
		Digest    *string `json:"digest"`
		FirstSeen *string `json:"first_seen_at"`
		Observed  *string `json:"observed_since"`
		Statement string  `json:"statement"`
	}
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 2 {
		t.Fatal("the vectors have lost cases")
	}
	for _, v := range vs {
		got, err := DigestStatement(v.AID, v.Seq, v.Digest, v.FirstSeen, v.Observed)
		if err != nil || got != v.Statement {
			t.Errorf("%s: got %q, %v; the vectors say %q", v.Name, got, err, v.Statement)
		}
	}
}

// Two different answers must never share a statement.
func TestAFieldThatCouldBlurTwoAnswersIsRefused(t *testing.T) {
	d := "ab"
	for _, aid := range []string{"", "-", "E\naid=x", "E\x00"} {
		if _, err := DigestStatement(aid, 1, &d, nil, nil); err == nil {
			t.Errorf("aid %q was signable", aid)
		}
	}
	bad := "x\ndigest=y"
	if _, err := DigestStatement("E", 1, &bad, nil, nil); err == nil {
		t.Error("a digest with a line break was signable")
	}
	empty := ""
	if _, err := DigestStatement("E", 1, &empty, nil, nil); err == nil {
		t.Error("an empty digest was signable instead of absent")
	}
	if _, err := DigestStatement("E", -1, nil, nil, nil); err == nil {
		t.Error("a negative sequence was signable")
	}
	a, _ := DigestStatement("E", 1, nil, nil, nil)
	if !strings.HasPrefix(a, DigestStatementTag+"\n") {
		t.Error("the statement does not open with its tag")
	}
}
