package server

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/backup/remote/fakedrive"
	"identity-agent-core/store"
)

const harnessMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

// aSealedArchive is an archive of one identity, sealed to harnessMnemonic, that
// says it was made at madeAt.
func aSealedArchive(t *testing.T, madeAt string) []byte {
	idJSON, _ := json.Marshal(store.IdentityState{AID: "EharnessIdentity", PublicKey: "dGVzdA==",
		NextKeyDigest: "digest", Created: "2026-01-01T00:00:00Z", EventCount: 1})
	bundle := &backup.PayloadBundle{
		Ordered:  []backup.PayloadSection{{Name: "identity_state", Data: idJSON}, {Name: "contacts", Data: []byte("null")}},
		Sections: map[string][]byte{"identity_state": idJSON, "contacts": []byte("null")},
	}
	plain, err := backup.SerializePayloadBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bek, _ := backup.NewBEK()
	ct, nonce, _ := backup.EncryptPayload(bek, plain)
	kek, _ := backup.SeedKEKFromMnemonic(harnessMnemonic)
	wrapped, wrapNonce, _ := backup.WrapBEK(kek, bek)
	m := backup.NewManifest("EharnessIdentity", []string{backup.TierCritical}, "full")
	m.CreatedAt = madeAt
	m.PayloadNonceB64 = backup.EncodeB64(nonce)
	m.KeySlots = []backup.KeySlot{{Type: backup.SlotSeedHD, WrappedBEKB64: backup.EncodeB64(wrapped), NonceB64: backup.EncodeB64(wrapNonce)}}
	for _, sec := range bundle.Ordered {
		m.Sections = append(m.Sections, backup.SectionMeta{Name: sec.Name, DigestBlake3QB64: backup.DigestSectionMust(sec.Data), SizePlaintext: len(sec.Data)})
	}
	arch := &backup.ArchiveFile{Manifest: m, Ciphertext: ct}
	seed, _ := backup.MnemonicToBIP39Seed(harnessMnemonic, "")
	if err := backup.SignWithSeed(arch, seed); err != nil {
		t.Fatal(err)
	}
	raw, err := backup.EncodeArchive(arch)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A real core, the real routes, and a stand-in Google behind them, for driving
// an app against when the build has no Google OAuth client. Not a test of
// anything: it serves until the file named by DRIVE_HARNESS_STOP appears, and
// writes where it is listening to DRIVE_HARNESS_ADDR (port from DRIVE_HARNESS_PORT,
// which the AUTH address needs). The local owner secret is "harness-local-owner-secret".
// Skipped unless both are set.
//
// The stand-in's "Google sign-in page" is the AUTH address the core hands out;
// the harness serves DRIVE_HARNESS_ADDR+".google" JSON so a driver can ask it
// for a code without a browser (/code?challenge=...), as Google would after the
// person consents.
func TestServeACoreWithAFakeGoogleForTheApps(t *testing.T) {
	addrFile, stopFile := os.Getenv("DRIVE_HARNESS_ADDR"), os.Getenv("DRIVE_HARNESS_STOP")
	if addrFile == "" || stopFile == "" {
		t.Skip("harness only: set DRIVE_HARNESS_ADDR and DRIVE_HARNESS_STOP")
	}
	d := fakedrive.New("harness-app.apps.example")
	defer d.Close()
	defer backup.PointGoogleDriveAt(d.Endpoints())()

	port := os.Getenv("DRIVE_HARNESS_PORT")
	if port == "" {
		port = "0"
	}
	portNumber, _ := strconv.Atoi(port)
	s := &CoreServer{DataDir: t.TempDir(), localOwnerSecret: "harness-local-owner-secret", Port: portNumber}
	s.backupService().Google = &backup.GoogleSignIn{
		ClientID: "harness-app.apps.example", Endpoints: d.Endpoints(),
		AuthURL: "http://127.0.0.1:" + port + "/__google/consent",
	}
	mux := http.NewServeMux()
	mux.Handle("/", s.Handler())
	// What Google's consent page does once the person agrees: hands back a code
	// bound to the challenge in the address.
	mux.HandleFunc("/__google/consent", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := d.IssueCode(q.Get("code_challenge"))
		w.Header().Set("Location", q.Get("redirect_uri")+"?code="+code+"&state="+q.Get("state"))
		w.WriteHeader(http.StatusFound)
	})
	// Puts an archive in the person's Drive as another of their machines would:
	// /__google/archive?made=<RFC3339 inside the archive>&name=<file name>
	mux.HandleFunc("/__google/archive", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if err := s.backupService().PutArchiveInDrive("google-drive", q.Get("name"), aSealedArchive(t, q.Get("made"))); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(ln, mux)
	if err := os.WriteFile(addrFile, []byte(ln.Addr().String()), 0o600); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(stopFile); err == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}
