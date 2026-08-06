package server

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// A stub standing in for the manufacturer's service, so these tests neither
// depend on it being reachable nor add load to it.
func certServiceStub(t *testing.T, hits *int) *httptest.Server {
	t.Helper()
	leaf := []byte("leaf-der-bytes")
	chainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("intermediate")})
	chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("root")})...)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hits++
		if strings.HasSuffix(r.URL.Path, "/cert_chain") {
			_, _ = w.Write(chainPEM)
			return
		}
		_, _ = w.Write(leaf)
	}))
}

// The firmware level decides which certificate is issued, so a wrong decode
// asks for a certificate that will not verify the report — a failure that
// reads as tampering rather than as a lookup mistake.
//
// Pinned to the value a real machine reported, and the query it produced did
// return a certificate.
func TestTheFirmwareLevelIsSplitTheWayTheServiceIndexesIt(t *testing.T) {
	// 0x1515000000000009 little-endian is 0900000000001515 on the wire.
	bl, tee, snp, ucode := decodeTCBParts(0x1515000000000009)
	if bl != 9 || tee != 0 || snp != 21 || ucode != 21 {
		t.Fatalf("decoded bl=%d tee=%d snp=%d ucode=%d, want 9/0/21/21", bl, tee, snp, ucode)
	}
}

// Asked once, then remembered. An agent that fetched on every request would be
// making a request whose answer cannot change, and doing it against somebody
// else's service.
func TestTheChainIsFetchedOnceAndThenRemembered(t *testing.T) {
	hits := 0
	srv := certServiceStub(t, &hits)
	defer srv.Close()

	dir := t.TempDir()
	c := newSNPCertificateChain("Genoa", dir)
	c.HTTPClient = srv.Client()
	base := amdKDSBaseForTest
	amdKDSBaseForTest = srv.URL
	defer func() { amdKDSBaseForTest = base }()

	chip := make([]byte, 64)
	for i := range chip {
		chip[i] = byte(i)
	}

	first, err := c.forReport(context.Background(), chip, 0x1515000000000009)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if len(first) != 3 {
		t.Fatalf("got %d certificates, want leaf + intermediate + root", len(first))
	}
	afterFirst := hits

	if _, err := c.forReport(context.Background(), chip, 0x1515000000000009); err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if hits != afterFirst {
		t.Fatalf("asked the service again: %d requests, want %d", hits, afterFirst)
	}

	// And a fresh instance reads what the first one wrote, so a restart does
	// not ask again either.
	c2 := newSNPCertificateChain("Genoa", dir)
	c2.HTTPClient = srv.Client()
	if _, err := c2.forReport(context.Background(), chip, 0x1515000000000009); err != nil {
		t.Fatalf("after restart: %v", err)
	}
	if hits != afterFirst {
		t.Fatalf("a restart asked the service again: %d requests, want %d", hits, afterFirst)
	}
}

// A 404 is almost always the family name rather than the processor, and the
// message has to say so or the next person loses an afternoon to it.
func TestAnUnknownFamilySaysWhatIsActuallyWrong(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newSNPCertificateChain("Siena", t.TempDir())
	c.HTTPClient = srv.Client()
	base := amdKDSBaseForTest
	amdKDSBaseForTest = srv.URL
	defer func() { amdKDSBaseForTest = base }()

	_, err := c.forReport(context.Background(), make([]byte, 64), 1)
	if err == nil {
		t.Fatal("a missing certificate was not reported as an error")
	}
	if !strings.Contains(err.Error(), "Genoa") {
		t.Fatalf("the error does not say which family to ask for instead: %v", err)
	}
}

// A cache that cannot be written costs one request on the next start. Failing
// the attestation over it would trade something that matters for something
// that does not.
func TestAnUnwritableCacheDoesNotFailTheAttestation(t *testing.T) {
	hits := 0
	srv := certServiceStub(t, &hits)
	defer srv.Close()

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skip("cannot make a read-only directory here")
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()

	c := newSNPCertificateChain("Genoa", dir)
	c.HTTPClient = srv.Client()
	base := amdKDSBaseForTest
	amdKDSBaseForTest = srv.URL
	defer func() { amdKDSBaseForTest = base }()

	if _, err := c.forReport(context.Background(), make([]byte, 64), 1); err != nil {
		t.Fatalf("an unwritable cache failed the attestation: %v", err)
	}
}
