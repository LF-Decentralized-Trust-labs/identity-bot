package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/store"
)

// aMintedSigner is a pairwise identity written down the way minting writes it:
// the inception registered for its introduction, and its signed bytes stored.
func aMintedSigner(t *testing.T, s *CoreServer) (aid string, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	nextPub, _, _ := ed25519.GenerateKey(rand.Reader)
	icp, err := iacrypto.BuildEd25519Inception(pub, nextPub)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(icp.RawBytesB64)
	sig, err := login.SignString(string(raw), priv.Seed())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(icp.InceptionEvent)
	if err := s.DataStore.SaveEvent(store.EventRecord{
		AID: icp.AID, SequenceNumber: 0, EventType: "icp", EventJSON: string(body),
		PublicKey: icp.PublicKey, RawBytesB64: icp.RawBytesB64, CesrSignature: sig,
	}); err != nil {
		t.Fatal(err)
	}
	registerPairwiseKEL(icp.AID, []map[string]interface{}{icp.InceptionEvent})
	return icp.AID, pub
}

func anAgentServingIntroductions(t *testing.T) (*CoreServer, *httptest.Server) {
	t.Helper()
	ds, err := store.NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &CoreServer{DataStore: ds}
	r := chi.NewRouter()
	r.Get("/public/oobi/{aid}", s.handleOobiServe)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return s, srv
}

// The key that checks a signed request comes from the signer's key log, which
// proves itself. It used to come from a did.json beside the introduction, which
// proves nothing: whoever serves the address chooses the key.
func TestASignersKeyComesFromItsOwnKeyLog(t *testing.T) {
	s, srv := anAgentServingIntroductions(t)
	aid, pub := aMintedSigner(t, s)

	got, err := s.resolveSignerKey(srv.URL + "/public/oobi/" + aid)
	if err != nil {
		t.Fatalf("a minted signer's key could not be established: %v", err)
	}
	if string(got) != string(pub) {
		t.Fatal("the key established is not the signer's")
	}
}

// An introduction that serves some other identity's log, or a key of its own
// choosing, establishes no key for the identifier it names.
func TestAnIntroductionServingAnotherIdentitysLogEstablishesNothing(t *testing.T) {
	s, _ := anAgentServingIntroductions(t)
	other, _ := aMintedSigner(t, s)
	victim := "EAnIdentifierThatThisLogDoesNotDerive0000000"

	// Somebody's server answers for the victim with another identity's log.
	r := chi.NewRouter()
	r.Get("/public/oobi/{aid}", func(w http.ResponseWriter, req *http.Request) {
		raws, sigs, _ := s.fullySignedLogOf(other)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"aid": victim, "raw_events_b64": raws, "cesr_signatures": sigs,
		})
	})
	r.Get("/public/{aid}/did.json", func(w http.ResponseWriter, req *http.Request) {
		t.Errorf("a did.json was read to check a signature: %s", req.URL.Path)
	})
	liar := httptest.NewServer(r)
	defer liar.Close()

	_, err := s.resolveSignerKey(liar.URL + "/public/oobi/" + victim)
	if err == nil {
		t.Fatal("a log that derives another identity established a key for the victim")
	}
	if !strings.Contains(err.Error(), "not "+victim) {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}
