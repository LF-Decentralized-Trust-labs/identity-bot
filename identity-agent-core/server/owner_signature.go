package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"identity-agent-core/atomicfile"
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
	// headerOwnerFor names the Identity Agent the request is meant for. It is
	// inside the signature, and any other Identity Agent refuses the request.
	headerOwnerFor = "X-IA-Owner-For"
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
		//
		// A LOG MAY ONLY MOVE THE KEY FORWARD from the key this machine already
		// trusts. Where the owner's key was sealed, a verified log is accepted
		// only if that key appears in it, at or before the tip it names; a log
		// cut off before the sealed key is an older history of the same
		// identity, and anyone holding a retired key can get this machine to
		// resolve one (an OOBI from a site or an ask) which verifies cleanly.
		// Accepting it would make the retired key the owner and refuse the
		// current one. Such a log is ignored and the sealed key answers.
		sealed, serr := s.sealedOwnerAuthority()
		if theSealCannotBeRead(serr) {
			return nil, fmt.Errorf("this machine has an owner sealed and the record cannot be read, so nobody may speak for it: %w", serr)
		}
		haveSealed := serr == nil && sealed != nil && sealed.AID == owner && sealed.PublicKey != ""
		if key, ok := s.ownerKeyThatMovesForward(owner); ok {
			return &OwnerAuthority{AID: owner, PublicKey: key}, nil
		}

		// Then the record sealed at provisioning or pairing. This is the
		// founding case: at the moment a machine is adopted its owner is not yet
		// a contact, so nothing has a log for them and this is the only key
		// there is. Matched on AID, so the log still decides WHO the owner is
		// and the file only supplies key material for the owner it named.
		if haveSealed {
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
	sealed, serr := s.sealedOwnerAuthority()
	if theSealCannotBeRead(serr) {
		return nil, fmt.Errorf("the owner record sealed on this machine cannot be read, so nobody may speak for it: %w", serr)
	}
	if serr == nil {
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
// theSealCannotBeRead is whether sealedOwnerAuthority failed for any reason
// other than there being no seal. Callers that go on to ask a log or a contact
// row who the owner is must refuse instead, since they would be answering in
// the seal's place.
func theSealCannotBeRead(serr error) bool {
	return serr != nil && !errors.Is(serr, errNoOwnerSealed)
}

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
		if errors.Is(err, fs.ErrNotExist) {
			return nil, errNoOwnerSealed
		}
		// A seal that is there and cannot be read is not "nothing sealed":
		// treating it so would let a log or a contact row decide who the owner
		// is on a machine that has an owner, and a read fault should not be
		// something anybody can use.
		return nil, fmt.Errorf("owner authority record cannot be read: %w", err)
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
	// Written whole beside the record and linked into place only once it is
	// on disk (atomicfile.Create). Creating the record and then writing into
	// it, as this did, left an empty or half-written record if the process
	// stopped in between, and half a record reads back as unreadable rather
	// than as unclaimed: the agent answered to nobody and could not be claimed.
	if err := atomicfile.Create(filepath.Join(s.DataDir, ownerAuthorityFile), raw, 0o600); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("this agent already answers to an owner — replacing one " +
				"is an ownership ceremony, not a seal")
		}
		return err
	}
	return nil
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
	return atomicfile.Write(filepath.Join(dir, ownerAuthorityFile), raw, 0o600)
}

// decodeOwnerKey and verifyOwnerString are the two steps of verification,
// separated so an interop test can exercise the construction directly rather
// than through the freshness window — a pinned vector is necessarily old.
func decodeOwnerKey(key string) ([]byte, error) { return login.DecodeVerkey(key) }

func verifyOwnerString(body, sig string, pub []byte) (bool, error) {
	return login.VerifyString(body, sig, pub)
}

// canonicalOwnerRequest is the exact text an owner signs: the Identity Agent it
// is for, method, path, timestamp and a digest of the body — so a captured
// signature cannot be presented to a different Identity Agent, moved to a
// different endpoint, replayed later, or reused with a different body.
//
// The Identity Agent is named because one owner key can own more than one, and
// each keeps its own memory of spent signatures: without the name, a request
// captured on its way to one could be presented to another within the window.
func canonicalOwnerRequest(target, method, path, timestamp string, body []byte) string {
	return canonicalOwnerRequestOver(target, method, path, timestamp, iacrypto.Blake3QB64Must(body))
}

// canonicalOwnerRequestOver is canonicalOwnerRequest from the body's digest,
// which is what lets a request be checked before its body is read: the client
// sends the digest in X-IA-Body-Digest (body_digest_header.go). The one place the
// string is built.
func canonicalOwnerRequestOver(target, method, path, timestamp, bodyDigest string) string {
	return strings.Join([]string{
		"IA-REQ-V2",
		target,
		strings.ToUpper(method),
		path,
		timestamp,
		bodyDigest,
	}, "\n")
}

// canonicalRequestString is the first form of that string, with no Identity
// Agent named. An owner's request is no longer accepted in it. It remains the
// form a machine an identity owns signs its notifications in (asset_notify.go),
// whose signer has its own key per machine.
func canonicalRequestString(method, path, timestamp string, body []byte) string {
	return strings.Join([]string{
		"IA-REQ-V1",
		strings.ToUpper(method),
		path,
		timestamp,
		iacrypto.Blake3QB64Must(body),
	}, "\n")
}

// SignOwnerRequest produces the signature a client sends in X-IA-Owner-Sig, for
// the Identity Agent whose identifier is target (sent in X-IA-Owner-For).
// Exported so the desktop app, the CLI and the tests all sign the same bytes
// rather than each inventing a format.
//
// A caller sends the request with X-IA-Body-Digest set to iacrypto.Blake3QB64 of
// the same body, so the agent verifies this signature before reading any of the
// body. The header becomes required in a later version.
func SignOwnerRequest(target, method, path, timestamp string, body, seed []byte) (string, error) {
	return login.SignString(canonicalOwnerRequest(target, method, path, timestamp, body), seed)
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

	// The digest the signature covers. With X-IA-Body-Digest it is the one the
	// client declared and NOTHING of the body is read until the signature has
	// verified, so a caller without the key makes the agent read nothing.
	// Without it (an older client) the body is read to digest it, bounded by
	// maxSignedBodyBytes only; the header becomes required in a later version.
	digest, declared, err := theDigestTheRequestDeclares(r)
	if err != nil {
		return err
	}
	if !declared {
		body, err := readSignedBody(r)
		if err != nil {
			return err
		}
		digest = iacrypto.Blake3QB64Must(body)
	}

	target, err := s.theIdentityAgentAnOwnerNames(r)
	if err != nil {
		return err
	}
	message := canonicalOwnerRequestOver(target, r.Method, r.URL.Path, stamp, digest)
	ok, err := login.VerifyString(message, sig, pub)
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	if !ok {
		return fmt.Errorf("signature does not match the owner key")
	}
	// An owner at stage two signs with both keys; checked before the signature
	// is spent, so a request missing the second does not burn the first.
	pqKey, pqAt, err := s.ownerPostQuantumKey(authority)
	if err != nil {
		return err
	}
	if pqKey != "" {
		if err := thePostQuantumSignatureOfAnOwnerRequest(r, pqKey, pqAt, message); err != nil {
			return err
		}
	}

	// Verified, so spent NOW -- before any of the body is read. A signature is
	// good for one request. If a mismatched body left it unspent, whoever held
	// one captured request could resend it many times inside the window, each
	// time making the agent read up to the route's bound; and resends with the
	// right body, sent in parallel, would all be read before the first spent it.
	// A mismatch burns the signature instead. That costs the real sender nothing:
	// anyone holding the capture could already race them. Checked after the
	// signature verifies so a bad signature cannot burn a good one by presenting
	// it first.
	if rememberSignature(sig, now) {
		return fmt.Errorf("this signed request has already been used")
	}

	// Signed by the owner, so the body may now be read -- up to the route's
	// bound -- and must be the one that was signed.
	if declared {
		if err := readTheBodyAgainst(r, digest); err != nil {
			return err
		}
	}
	return nil
}

// ownerKeyThatMovesForward is the one place the forward-only rule lives: the key
// from the verified log held for aid, but only if that log does not contradict
// the key this machine sealed for the same identifier (see ownerAuthority).
// Every question of the form "which key speaks for this owner" goes through
// here, so no route can be answered by a replayed older log that another route
// would have refused.
func (s *CoreServer) ownerKeyThatMovesForward(aid string) (string, bool) {
	key, err := s.ownerKeyFromAVerifiedLog(aid)
	if err != nil {
		return "", false
	}
	sealed, serr := s.sealedOwnerAuthority()
	if theSealCannotBeRead(serr) {
		return "", false
	}
	if serr == nil && sealed != nil && sealed.AID == aid && sealed.PublicKey != "" &&
		!s.theLogReachesTheKey(aid, sealed.PublicKey) {
		return "", false
	}
	return key, true
}

// theLogReachesTheKey reports whether the verified log held for aid names key
// in one of its events, so that the log's tip is that key or a successor of it.
// Keys are compared as decoded bytes, since a sealed key may be written in
// CESR, base64 or hex.
func (s *CoreServer) theLogReachesTheKey(aid, key string) bool {
	if s.DataStore == nil {
		return false
	}
	record, err := s.DataStore.GetContactKEL(aid)
	if err != nil || record == nil {
		return false
	}
	want, err := login.DecodeVerkey(key)
	if err != nil {
		return false
	}
	for _, ev := range record.KEL {
		for _, k := range stringsOf(ev["k"]) {
			if got, derr := login.DecodeVerkey(k); derr == nil && bytes.Equal(got, want) {
				return true
			}
		}
	}
	return false
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

// theIdentityAgentAnOwnerNames is the Identity Agent an owner-signed request is
// meant for, refused unless it is this one. An Identity Agent with no
// identifier yet — a machine not yet founded, being claimed — is named by
// nobody, so it accepts only a request that names nobody, and refuses those
// the moment it has one.
func (s *CoreServer) theIdentityAgentAnOwnerNames(r *http.Request) (string, error) {
	named := strings.TrimSpace(r.Header.Get(headerOwnerFor))
	me, err := s.whoThisIdentityAgentIs()
	if err != nil {
		return "", err
	}
	if named != me {
		if named == "" {
			return "", fmt.Errorf("a signed request must name the Identity Agent it is for in %s", headerOwnerFor)
		}
		return "", fmt.Errorf("this request was signed for a different Identity Agent")
	}
	return named, nil
}
