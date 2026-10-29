package server

import (
	"net/http"
	"testing"

	"identity-agent-core/conversationbundle"
)

// A person's words are kept as the bytes their app signed, so a message
// holding characters a JSON encoder escapes, sent as JSON laid out with
// spaces, is recorded and still verifies once the conversation is exported.
func TestAPersonsWordsAreKeptAsTheAppSignedThem(t *testing.T) {
	w := exportWorld(t)
	body := "{\"to\": \"" + w.a.PairwiseAID + "\",\n  \"body\": \"Is 2 < 3 && 5 > 4?\", \"nonce\": \"n_escaped_characters\"}"
	code, out := w.personSends(t, w.a, body)
	if code != http.StatusCreated {
		t.Fatalf("the person's message: %d %v", code, out)
	}
	r := conversationbundle.Verify(w.bundle(t, out["conversation"].(string)))
	if !r.Verified {
		t.Fatalf("the person's own message does not verify:\n%s", faultsOf(r))
	}
}
