package login

import (
	"crypto/ed25519"

	"encoding/base64"
	"identity-agent-core/iacrypto"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The registry POST is reached (the relationship has a seed and an inception),
// and goes through PeerClient, not the plain HTTPClient.
func TestThePairwiseKeyIsPostedToTheRegistryThroughThePeerClient(t *testing.T) {
	var calls []string
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, "registry "+r.URL.Path)
	}))
	defer reg.Close()
	h := &Handler{
		HTTPClient: &http.Client{Transport: recordingTransport{"plain", &calls}},
		PeerClient: func(string) *http.Client {
			return &http.Client{Transport: countingTransport{"guarded", &calls}}
		},
	}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	next := make([]byte, 32)
	next[0] = 9
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	nextPub := ed25519.NewKeyFromSeed(next).Public().(ed25519.PublicKey)
	icp, err := iacrypto.BuildEd25519Inception(pub, nextPub)
	if err != nil {
		t.Fatal(err)
	}
	rel := &SiteRelationship{
		PairwiseAID:  icp.AID,
		RelayOOBI:    reg.URL + "/oobi/" + icp.AID,
		SeedB64:      b64(seed),
		InceptionB64: icp.RawBytesB64,
	}
	if err := h.registerPairwiseOnDevRelay(rel, nil); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0] != "guarded /_dev/register" || calls[1] != "registry /_dev/register" {
		t.Fatalf("the registry POST was not made through the peer client: %v", calls)
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
