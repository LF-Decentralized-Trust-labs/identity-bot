package server

import (
	"bytes"
	"encoding/json"
	"errors"
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
		// THE SEALED KEY ANSWERS BEFORE THE CONTACT RECORD, and that ordering is
		// as load-bearing as the one above it.
		//
		// publicKeyOf resolves a counterparty's key from contacts, and contacts
		// are written by handlers that fetch a record from an address the CALLER
		// names — POST /api/contacts, /api/contacts/resolve, /api/scan/execute,
		// /api/ask/create, and whatever is added next. Reading the owner's key
		// from there meant anyone who could reach any one of those could write
		// the key that decides whether they are the owner, and then be the
		// owner. Proven end to end through the scan route, which nothing had
		// thought to close, after the two obvious contact routes were closed.
		//
		// A VERIFIED KEY EVENT LOG ANSWERS FIRST, because it is the only source
		// that tracks a rotation.
		//
		// The owner of a paired machine is a pairwise identity the owner's own
		// device minted for it, and that identity can rotate its keys. Nothing
		// rewrites the sealed record when it does - changing owners is a
		// separate ceremony - so the sealed key is the key as it was at pairing
		// and no later. Asking it first, as this did briefly, means an owner who
		// rotates is refused by their own machine, permanently, with no way back
		// in. That is worse than the hole the ordering was closing.
		//
		// A verified log cannot be written by a caller, which is what makes it
		// safe to prefer: the validators bind the log to the identifier before
		// trusting anything in it, so forging one means forging a
		// self-addressing identifier.
		if key, kerr := s.ownerKeyFromAVerifiedLog(owner); kerr == nil {
			return &OwnerAuthority{AID: owner, PublicKey: key}, nil
		}

		// Then the record sealed at provisioning or pairing. This is the
		// founding case: at the moment a machine is adopted its owner is not yet
		// a contact, so nothing has a log for them and this is the only key
		// there is. Matched on AID, so the log still decides WHO the owner is
		// and the file only supplies key material for the owner it named.
		if sealed, serr := s.sealedOwnerAuthority(); serr == nil && sealed.AID == owner &&
			sealed.PublicKey != "" {
			return &OwnerAuthority{AID: owner, PublicKey: sealed.PublicKey}, nil
		}

		// And last, an unverified contact row. Kept because refusing here would
		// lock an owner out of their own agent, which is worse than the narrowed
		// risk - but it stays last, because those rows are written by handlers
		// that fetch a record from an address the caller supplies.
		key, kerr := s.publicKeyOf(owner)
		if kerr != nil {
			// Refused rather than falling through. Falling back to this agent's
			// own identity would mean an identity whose owner cannot be resolved
			// quietly starts answering to itself, which is the failure this
			// whole design exists to remove.
			return nil, fmt.Errorf(
				"this identity names %s as its owner but that identity cannot be resolved, "+
					"and no key for it was sealed at founding: %w",
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
// errNoOwnerSealed means nobody has claimed this agent yet.
//
// A distinct value because it is not a fault and the two callers want opposite
// things from it: a signature check must refuse, while a screen asking who owns
// this agent needs to say "nobody yet" rather than report a failure. Sharing
// one error made an unclaimed agent look broken.
var errNoOwnerSealed = errors.New("no owner authority is sealed")

func (s *CoreServer) sealedOwnerAuthority() (*OwnerAuthority, error) {
	raw, err := os.ReadFile(filepath.Join(s.DataDir, ownerAuthorityFile))
	if err != nil {
		return nil, errNoOwnerSealed
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
	// CREATE OR FAIL, and the kernel decides which — not a check above this line.
	//
	// Checking first and writing second is two operations, and everything that
	// seals an owner does it from a request. Two concurrent redeems of a
	// founding invite both read "nothing sealed", both pass, and the later write
	// wins: an attacker racing the real founder seals their own key and the
	// founder is refused from then on. The use-count on the invite is racy by
	// the same mechanism, so one token is enough.
	//
	// A mutex would close it for one process and not for two, and — worse — it
	// would live in whichever caller remembered it. This is exported and called
	// from adoption as well as from redeeming an invite, so the guarantee has to
	// be here, where it cannot be forgotten.
	//
	// O_EXCL also makes the write itself all-or-nothing at creation. Truncating
	// an existing file and writing over it can be interrupted, and half a record
	// reads back as unreadable rather than as unclaimed.
	f, err := os.OpenFile(filepath.Join(s.DataDir, ownerAuthorityFile),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("this agent already answers to an owner — replacing one " +
				"is an ownership ceremony, not a seal")
		}
		return err
	}
	defer f.Close()
	if _, err := f.Write(raw); err != nil {
		return err
	}
	return f.Sync()
}

// ReSealOwnerAuthority replaces the record for a path that legitimately changes
// who a machine answers to.
//
// Separate from SealOwnerAuthority, and named so it cannot be reached by
// accident. Sealing is once; replacing is a decision somebody with authority
// already made — an ownership ceremony, or a restore that puts back what was
// there. A caller that only means to seal must not be able to replace by
// forgetting a flag, which is why this is a second function rather than an
// argument.
func (s *CoreServer) ReSealOwnerAuthority(oa OwnerAuthority) error {
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
	// Written beside and renamed over, so a reader never sees half a record.
	// A partial owner record is worse than none: it reads as unreadable, which
	// is a different answer from unclaimed and sends a screen somewhere else.
	dir := s.DataDir
	tmp, err := os.CreateTemp(dir, ownerAuthorityFile+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, ownerAuthorityFile))
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

// ownerKeyFromAVerifiedLog resolves the owner's signing key, accepting only a
// key this agent verified against a key event log.
//
// Deliberately NOT publicKeyOf. That function answers "what key do we have on
// file for this counterparty", which is the right question for talking to
// somebody and the wrong one for deciding who may administer this agent: it
// accepts a contact row, and contact rows are written by handlers that fetch a
// record from an address the caller supplies. Anything that could reach one of
// those could otherwise write the key that decides whether it is the owner.
//
// Kept separate rather than tightening publicKeyOf, because the two callers want
// different things. Refusing an unverified key when addressing a counterparty
// would break ordinary messaging with everybody whose log has not been walked;
// accepting one here hands over the agent.
func (s *CoreServer) ownerKeyFromAVerifiedLog(aid string) (string, error) {
	if s.DataStore == nil {
		return "", fmt.Errorf("no store to resolve %s from", aid)
	}
	record, err := s.DataStore.GetContactKEL(aid)
	if err != nil || record == nil {
		return "", fmt.Errorf("no verified key event log on file for %s", aid)
	}
	if !record.KelVerified {
		// Present but unverified is the exact state a written-in record is in.
		return "", fmt.Errorf(
			"the key on file for %s came from a record this agent has not verified "+
				"against a key event log, so it does not decide who the owner is", aid)
	}
	if record.CurrentPublicKey == "" {
		return "", fmt.Errorf("the verified log for %s names no current key", aid)
	}
	return record.CurrentPublicKey, nil
}
