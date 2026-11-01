package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"strings"
	"testing"
)

// A recovery phrase is read against the published BIP-39 English word list,
// and the app client carries its own copy of that list. The copy is checked
// against the list's published digest, so a person never meets a list that
// differs from the one every other wallet uses.
func TestTheAppClientCarriesTheStandardWordList(t *testing.T) {
	dart, err := os.ReadFile("../../packages/agent_client/lib/crypto/wordlist.dart")
	if err != nil {
		t.Skipf("the app client is not beside this module: %v", err)
	}
	found := regexp.MustCompile(`'([a-z]+)'`).FindAllStringSubmatch(string(dart), -1)
	words := make([]string, len(found))
	for i, w := range found {
		words[i] = w[1]
	}
	sum := sha256.Sum256([]byte(strings.Join(words, "\n") + "\n"))
	if got := hex.EncodeToString(sum[:]); got != "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda" {
		t.Fatalf("the app client's %d words are not the published BIP-39 English list: %s", len(words), got)
	}
}
