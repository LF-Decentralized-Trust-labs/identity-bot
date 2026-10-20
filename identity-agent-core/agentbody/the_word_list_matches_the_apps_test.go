package agentbody

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The same standard word list is embedded here, for the words an Identity Agent
// and a machine show, and in the app client, for recovery phrases. Two copies
// of a list drift, so the app's copy is checked against this one: a person
// should never meet two different lists under one name.
func TestTheAppClientCarriesTheSameWordList(t *testing.T) {
	dart, err := os.ReadFile("../../packages/agent_client/lib/crypto/wordlist.dart")
	if err != nil {
		t.Skipf("the app client is not beside this module: %v", err)
	}
	words := regexp.MustCompile(`'([a-z]+)'`).FindAllStringSubmatch(string(dart), -1)
	got := make([]string, len(words))
	for i, w := range words {
		got[i] = w[1]
	}
	if strings.Join(got, "\n") != strings.Join(wordlist, "\n") {
		t.Fatal("the app client's word list is not the one embedded here")
	}
}
