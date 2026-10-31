package brr_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
	keri "github.com/grapeid/keri-go"

	"identity-agent-core/brr"
	"identity-agent-core/iacrypto"
)

// issuer is a real KERI issuer: a self-addressing identifier, its signed key
// event log, and the key it has committed to rotate to.
type issuer struct {
	aid      string
	current  ed25519.PrivateKey
	next     ed25519.PrivateKey
	lastSAID string
	sn       int
	messages [][]byte
}

func newSigner(t *testing.T) (ed25519.PrivateKey, *keri.SoftwareSigner) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	s, err := keri.NewSoftwareSigner(seed, true)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed), s
}

func signerOf(t *testing.T, priv ed25519.PrivateKey) *keri.SoftwareSigner {
	t.Helper()
	s, err := keri.NewSoftwareSigner(priv.Seed(), true)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	cur, curSigner := newSigner(t)
	nxt, nxtSigner := newSigner(t)
	pub, _ := curSigner.PublicKey()
	npub, _ := nxtSigner.PublicKey()
	nd, err := keri.NextDigest(npub)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.BuildInception(keri.InceptionInput{Keys: []string{pub}, NextDigests: []string{nd}, Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := keri.ParseEvent(ev)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := keri.SignEvent(ev, curSigner)
	if err != nil {
		t.Fatal(err)
	}
	return &issuer{aid: parsed.Identifier, current: cur, next: nxt, lastSAID: parsed.SAID, messages: [][]byte{signed.Message}}
}

// rotate moves to the committed next key and commits to a new one.
func (is *issuer) rotate(t *testing.T) {
	t.Helper()
	newNext, newNextSigner := newSigner(t)
	pub, _ := signerOf(t, is.next).PublicKey()
	npub, _ := newNextSigner.PublicKey()
	nd, err := keri.NextDigest(npub)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.BuildRotation(keri.RotationInput{Prefix: is.aid, Keys: []string{pub}, PriorSAID: is.lastSAID, SN: is.sn + 1, NextDigests: []string{nd}})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := keri.SignEvent(ev, signerOf(t, is.next))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := keri.ParseEvent(ev)
	if err != nil {
		t.Fatal(err)
	}
	is.sn++
	is.lastSAID = parsed.SAID
	is.current, is.next = is.next, newNext
	is.messages = append(is.messages, signed.Message)
}

// fork is a copy holding the same keys whose log goes its own way from here.
func (is *issuer) fork() *issuer {
	cp := *is
	cp.messages = append([][]byte(nil), is.messages...)
	return &cp
}

func (is *issuer) kel(t *testing.T) []byte {
	t.Helper()
	out, err := keri.ExportKEL(is.messages)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (is *issuer) client(t *testing.T, url string) *brr.Client {
	t.Helper()
	c, err := brr.NewClient(url, is.aid, is.current)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// registry founds a registry governed by issuerAID, returning its prefix and
// its inception event.
func registry(t *testing.T, issuerAID string) (string, []byte) {
	t.Helper()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	raw, err := keri.BuildRegistryInception(keri.RegistryInput{Issuer: issuerAID, Nonce: base64.RawURLEncoding.EncodeToString(nonce)})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.VerifyTELEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	return ev.SAID, raw
}

// enrollingRegistry is a stand-in for the revocation registry that enforces
// its enrolment contract: the enrolment is signed by the presented key over
// every field, the registry inception digests to the prefix and names the
// issuer, the key event log derives the issuer and names the presented key as
// current, and an enrolled registry keeps its issuer and refuses, with 409, a
// log that forks from the one it holds.
type enrollingRegistry struct {
	mu   sync.Mutex
	held map[string]heldRegistry
	last *brr.EnrollRequest
}

type heldRegistry struct {
	issuer string
	key    ed25519.PublicKey
	events [][]byte
}

func newEnrollingRegistry(t *testing.T) (*enrollingRegistry, *httptest.Server) {
	t.Helper()
	reg := &enrollingRegistry{held: map[string]heldRegistry{}}
	srv := httptest.NewServer(http.HandlerFunc(reg.enroll))
	t.Cleanup(srv.Close)
	return reg, srv
}

func refuse(w http.ResponseWriter, code int, why string) {
	w.WriteHeader(code)
	_, _ = w.Write([]byte(why))
}

func (reg *enrollingRegistry) enroll(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/registry/enroll" {
		refuse(w, http.StatusNotFound, "not found")
		return
	}
	var req brr.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		refuse(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.RegistryPrefix == "" || req.IssuerAID == "" || req.IssuerPubKeyB64 == "" || req.KEL == "" || req.RegistryInception == "" {
		refuse(w, http.StatusBadRequest, "registry_prefix, issuer_aid, issuer_public_key_b64, kel and registry_inception required")
		return
	}
	raw, err := iacrypto.DecodeSized(req.IssuerPubKeyB64, ed25519.PublicKeySize, false)
	presented := ed25519.PublicKey(raw)
	if err != nil {
		refuse(w, http.StatusBadRequest, "issuer_public_key_b64 unreadable")
		return
	}
	canonical, err := brr.EnrollCanonical(req)
	if err != nil {
		refuse(w, http.StatusBadRequest, err.Error())
		return
	}
	sig, err := iacrypto.DecodeBase64URLSized(req.Signature, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(presented, canonical, sig) {
		refuse(w, http.StatusUnauthorized, "issuer signature invalid")
		return
	}
	inception, err := iacrypto.DecodeBase64URL(req.RegistryInception)
	if err != nil {
		refuse(w, http.StatusBadRequest, "registry_inception unreadable")
		return
	}
	ev, err := keri.VerifyTELEvent(inception)
	var fields map[string]json.RawMessage
	var named string
	if err == nil {
		err = json.Unmarshal(inception, &fields)
	}
	if err == nil {
		err = json.Unmarshal(fields["ii"], &named)
	}
	if err != nil || ev.Ilk != "vcp" || ev.SAID != req.RegistryPrefix || named != req.IssuerAID {
		refuse(w, http.StatusForbidden, "could not confirm this registry belongs to that issuer")
		return
	}
	stream, err := iacrypto.DecodeBase64URL(req.KEL)
	if err != nil {
		refuse(w, http.StatusBadRequest, "kel unreadable")
		return
	}
	current, err := relayproto.CurrentKey(req.IssuerAID, stream)
	if err != nil || !current.Equal(presented) {
		refuse(w, http.StatusForbidden, "could not confirm this key belongs to that issuer")
		return
	}
	events, err := keri.ParseKELStream(stream)
	if err != nil {
		refuse(w, http.StatusBadRequest, "kel does not parse")
		return
	}

	reg.mu.Lock()
	defer reg.mu.Unlock()
	reg.last = &req
	held, ok := reg.held[req.RegistryPrefix]
	switch {
	case !ok:
	case held.issuer != req.IssuerAID:
		refuse(w, http.StatusConflict, "this registry is enrolled to another issuer")
		return
	case extends(held.events, events):
	case extends(events, held.events) && held.key.Equal(presented):
		return // an older copy of the held log, with the key held: nothing changes
	default:
		refuse(w, http.StatusConflict, "the key event log presented forks from the one this registry holds")
		return
	}
	reg.held[req.RegistryPrefix] = heldRegistry{issuer: req.IssuerAID, key: presented, events: events}
	w.WriteHeader(http.StatusOK)
}

// extends reports whether longer holds every event of shorter, in order.
func extends(shorter, longer [][]byte) bool {
	if len(longer) < len(shorter) {
		return false
	}
	for i := range shorter {
		if !bytes.Equal(shorter[i], longer[i]) {
			return false
		}
	}
	return true
}

// An enrolment carries the issuer's key event log and the registry's
// inception, both signed with the rest of it, and a registry that checks both
// takes it.
func TestARegistryIsEnrolledWithTheIssuersLogAndItsInception(t *testing.T) {
	reg, srv := newEnrollingRegistry(t)
	is := newIssuer(t)
	prefix, inception := registry(t, is.aid)
	got, err := is.client(t, srv.URL).Enroll(is.kel(t), inception)
	if err != nil {
		t.Fatalf("a proven enrolment was not taken: %v", err)
	}
	if got != prefix {
		t.Fatalf("enrolled %q, the registry the inception founds is %q", got, prefix)
	}
	if reg.last.KEL != base64.RawURLEncoding.EncodeToString(is.kel(t)) ||
		reg.last.RegistryInception != base64.RawURLEncoding.EncodeToString(inception) {
		t.Fatal("the enrolment does not carry the issuer's log and the registry's inception in base64url")
	}

	// After a rotation, the newer log extends the one held and moves the key.
	is.rotate(t)
	if _, err := is.client(t, srv.URL).Enroll(is.kel(t), inception); err != nil {
		t.Fatalf("enrolling again with the rotated log was refused: %v", err)
	}
}

// A log that forks from the one the registry holds is refused with 409, and
// the client reports that as a refusal, not as a failure to try again.
func TestAForkedLogIsARefusal(t *testing.T) {
	_, srv := newEnrollingRegistry(t)
	is := newIssuer(t)
	_, inception := registry(t, is.aid)
	other := is.fork()
	is.rotate(t)
	if _, err := is.client(t, srv.URL).Enroll(is.kel(t), inception); err != nil {
		t.Fatal(err)
	}
	other.rotate(t) // the same keys, a different history
	_, err := other.client(t, srv.URL).Enroll(other.kel(t), inception)
	if !errors.Is(err, brr.ErrRefused) || !strings.Contains(err.Error(), "forks") {
		t.Fatalf("a forked log was not reported as a refusal: %v", err)
	}
}

// The registry's own checks refuse what the client cannot know is wrong: a
// registry founded by somebody else.
func TestARegistryOfAnotherIssuerIsNotEnrolled(t *testing.T) {
	_, srv := newEnrollingRegistry(t)
	is, someoneElse := newIssuer(t), newIssuer(t)
	_, theirs := registry(t, someoneElse.aid)
	_, err := is.client(t, srv.URL).Enroll(is.kel(t), theirs)
	if err == nil || errors.Is(err, brr.ErrRefused) || !strings.Contains(err.Error(), "403") {
		t.Fatalf("enrolling another issuer's registry: %v", err)
	}
}

// A client whose key its own log has rotated away from finds out before it
// sends anything: the log names a different current key.
func TestAKeyTheLogHasRotatedAwayFromIsNotSent(t *testing.T) {
	reg, srv := newEnrollingRegistry(t)
	is := newIssuer(t)
	_, inception := registry(t, is.aid)
	stale := is.client(t, srv.URL)
	is.rotate(t)
	if _, err := stale.Enroll(is.kel(t), inception); err == nil {
		t.Fatal("a key the log has rotated away from was used to enrol")
	}
	if reg.last != nil {
		t.Fatal("an enrolment the log does not support was sent")
	}
	if _, err := is.client(t, srv.URL).Enroll(is.kel(t), []byte(`{"not":"an event"}`)); err == nil {
		t.Fatal("something that is not a registry inception was accepted")
	}
}
