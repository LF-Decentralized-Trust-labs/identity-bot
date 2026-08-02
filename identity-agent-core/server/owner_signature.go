package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/store"
)

// Proving you are the owner when you are not at the keyboard.
//
// The old test for "is this the owner" was: did the request originate on this
// machine and arrive unforwarded. That is true and sufficient on a laptop. It
// is never true on hardware the owner rents — where they reach the agent over
// the network — and the escape hatch was itself gated the same way: minting a
// token required a local call, on a box nobody can ever be local to. The one
// door to the room was locked from inside the room.
//
// So the owner signs the request. The owner's AID is sealed into the box when
// it is provisioned, the agent verifies each request against that key, and
// locality stops being a security boundary — it stays only as a convenience for
// the machine you are sitting at.

// Headers carrying the proof.
const (
	headerOwnerSig       = "X-IA-Owner-Sig"       // CESR qb64 Ed25519 signature
	headerOwnerTimestamp = "X-IA-Owner-Timestamp" // RFC3339, inside signedRequestWindow
	headerOwnerAID       = "X-IA-Owner-AID"       // optional: which owner key signed
)

// ownerAuthorityFile records whose signature counts as the owner's. It is
// written at provisioning on hardware the owner does not physically hold.
const ownerAuthorityFile = "owner_authority.json"

// OwnerAuthority is the identity permitted to act as the owner of this agent.
type OwnerAuthority struct {
	AID string `json:"aid"`
	// PublicKey is the owner's current signing key. Accepted in CESR qb64,
	// base64 or hex — see login.DecodeVerkey.
	PublicKey string `json:"public_key"`
	// SealedAt records when provisioning fixed this, for the audit trail.
	SealedAt string `json:"sealed_at,omitempty"`
}

// ownerAuthority returns who may act as the owner.
//
// The order is the security property. An identity that named its owner in its
// own inception event has settled the question permanently, and nothing on disk
// may disagree with it. Only where there is no such anchor does the sealed
// record answer — which is the case it was written for, a box provisioned for
// an owner before it had an identity at all. With neither, an agent running on
// its owner's own machine is its own authority, so signing works there with no
// setup.
func (s *CoreServer) ownerAuthority() (*OwnerAuthority, error) {
	// With no identity of its own, the sealed record is all there is — and that
	// is precisely the state provisioning writes it in, on a box that has not
	// been adopted yet.
	var identity *store.IdentityState
	if s.DataStore != nil {
		identity, _ = s.DataStore.GetIdentity()
	}
	if identity == nil || identity.PublicKey == "" {
		return s.sealedOwnerAuthority()
	}

	// THE LOG ANSWERS FIRST, and this ordering is the whole point.
	//
	// It used to read the file first and return, so an identity that named its
	// owner in its own inception event could be overridden by whoever could
	// write a file next to the database. That is exactly the failure the anchor
	// was introduced to remove, and leaving the file in front of it meant the
	// anchor decided nothing: a second signer could still silently replace the
	// first by re-sealing.
	//
	// An identity that named an owner when it was created has settled the
	// question permanently — the identifier IS the digest of that event, so the
	// answer cannot be edited, only re-founded. Nothing on disk gets to disagree
	// with it.
	if owner, aerr := s.ownerFromOwnIdentity(identity.AID); aerr == nil && owner != "" {
		key, kerr := s.publicKeyOf(owner)
		if kerr != nil {
			// Refused rather than falling through. Falling back here would mean
			// an identity whose owner cannot be resolved quietly starts
			// answering to itself, which is the failure this whole design
			// exists to remove.
			return nil, fmt.Errorf(
				"this identity names %s as its owner but that identity cannot be resolved: %w",
				owner, kerr)
		}
		return &OwnerAuthority{AID: owner, PublicKey: key}, nil
	}

	// No anchor. That is the ordinary case for a person's own agent, and for a
	// box provisioned for an owner whose identity is delegated rather than
	// anchored — which is what the sealed file was written for.
	if sealed, serr := s.sealedOwnerAuthority(); serr == nil {
		return sealed, nil
	}
	return &OwnerAuthority{AID: identity.AID, PublicKey: identity.PublicKey}, nil
}

// sealedOwnerAuthority reads the owner recorded at provisioning.
//
// Kept for the case it was written for: hardware the owner does not physically
// hold, sealed before the box ever reaches the network, where there is no
// identity yet to carry an anchor. It is no longer consulted for an identity
// that names its own owner.
func (s *CoreServer) sealedOwnerAuthority() (*OwnerAuthority, error) {
	raw, err := os.ReadFile(filepath.Join(s.DataDir, ownerAuthorityFile))
	if err != nil {
		return nil, fmt.Errorf("no owner authority is sealed")
	}
	var oa OwnerAuthority
	if jerr := json.Unmarshal(raw, &oa); jerr != nil {
		return nil, fmt.Errorf("owner authority record is unreadable: %w", jerr)
	}
	if oa.PublicKey == "" {
		return nil, fmt.Errorf("owner authority record carries no public key")
	}
	return &oa, nil
}

// SealOwnerAuthority fixes who may act as the owner. Provisioning calls this
// before the box ever reaches the network, which is what makes remote ownership
// possible without a bootstrap token.
func (s *CoreServer) SealOwnerAuthority(oa OwnerAuthority) error {
	if oa.AID == "" || oa.PublicKey == "" {
		return fmt.Errorf("owner authority needs both an AID and a public key")
	}
	if _, err := login.DecodeVerkey(oa.PublicKey); err != nil {
		return fmt.Errorf("owner public key: %w", err)
	}
	if oa.SealedAt == "" {
		oa.SealedAt = time.Now().UTC().Format(time.RFC3339)
	}
	raw, err := json.MarshalIndent(oa, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.DataDir, ownerAuthorityFile), raw, 0o600)
}

// decodeOwnerKey and verifyOwnerString are the two steps of verification,
// separated so an interop test can exercise the construction directly rather
// than through the freshness window — a pinned vector is necessarily old.
func decodeOwnerKey(key string) ([]byte, error) { return login.DecodeVerkey(key) }

func verifyOwnerString(body, sig string, pub []byte) (bool, error) {
	return login.VerifyString(body, sig, pub)
}

// canonicalRequestString is the exact text an owner signs. Method, path,
// timestamp and a digest of the body — so a captured signature cannot be moved
// to a different endpoint, replayed later, or reused with a different body.
func canonicalRequestString(method, path, timestamp string, body []byte) string {
	return strings.Join([]string{
		"IA-REQ-V1",
		strings.ToUpper(method),
		path,
		timestamp,
		iacrypto.Blake3QB64Must(body),
	}, "\n")
}

// SignOwnerRequest produces the signature a client sends in X-IA-Owner-Sig.
// Exported so the desktop app, the CLI and the tests all sign the same bytes
// rather than each inventing a format.
func SignOwnerRequest(method, path, timestamp string, body, seed []byte) (string, error) {
	return login.SignString(canonicalRequestString(method, path, timestamp, body), seed)
}

// verifyOwnerSignature returns nil when the request carries a valid, unexpired,
// unreplayed signature from the owner authority.
func (s *CoreServer) verifyOwnerSignature(r *http.Request) error {
	sig := r.Header.Get(headerOwnerSig)
	if sig == "" {
		return fmt.Errorf("no owner signature")
	}
	stamp := r.Header.Get(headerOwnerTimestamp)
	if stamp == "" {
		return fmt.Errorf("a signed request must carry %s", headerOwnerTimestamp)
	}
	signedAt, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return fmt.Errorf("%s must be RFC3339", headerOwnerTimestamp)
	}
	now := time.Now().UTC()
	if diff := now.Sub(signedAt); diff > signedRequestWindow || diff < -signedRequestWindow {
		return fmt.Errorf("signed request is outside the %s window", signedRequestWindow)
	}

	authority, err := s.ownerAuthority()
	if err != nil {
		return err
	}
	if claimed := r.Header.Get(headerOwnerAID); claimed != "" && authority.AID != "" && claimed != authority.AID {
		return fmt.Errorf("this agent's owner is a different identity")
	}
	pub, err := login.DecodeVerkey(authority.PublicKey)
	if err != nil {
		return err
	}

	// Read the body to digest it, then put it back — the handler still needs it.
	var body []byte
	if r.Body != nil {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			return fmt.Errorf("read body: %w", err)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	ok, err := login.VerifyString(canonicalRequestString(r.Method, r.URL.Path, stamp, body), sig, pub)
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	if !ok {
		return fmt.Errorf("signature does not match the owner key")
	}

	// Valid — and now spent. Checked last so a bad signature cannot burn a good
	// one by presenting it first.
	if rememberSignature(sig, now) {
		return fmt.Errorf("this signed request has already been used")
	}
	return nil
}
