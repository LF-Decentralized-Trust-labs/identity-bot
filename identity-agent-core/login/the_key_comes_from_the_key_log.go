package login

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/keriengine"

	keri "github.com/grapeid/keri-go"
)

// The key a sign-in is checked against comes from the identity's key log, and
// from nothing else.
//
// An identifier here is a digest of its own inception event, so the one thing
// that ties a key to an identifier is a key log whose inception derives it.
// A did.json document is not that: it is a key somebody chose to serve at an
// address, and the address was named by the very assertion being checked, so
// whoever wrote the assertion also chose where its key would be read from.
// Accepting that key let anybody sign in as any identifier they could name.
//
// So every place that needs an identity's key asks one of the two functions
// below, and both answer only from a log that validates: its events chain, its
// inception derives the identifier, and every event is signed by the key it
// declares.

// KeyLog is an identity's key log as it travels: each event exactly as it was
// serialised, and the controller's signature over those bytes.
type KeyLog struct {
	RawEventsB64   []string `json:"raw_events_b64"`
	CesrSignatures []string `json:"cesr_signatures"`
}

// EncodeKeyLog packs a key log into the single string an assertion carries.
func EncodeKeyLog(rawEvents [][]byte, signatures []string) (string, error) {
	if len(rawEvents) == 0 || len(rawEvents) != len(signatures) {
		return "", fmt.Errorf("a key log needs one signature per event (%d events, %d signatures)",
			len(rawEvents), len(signatures))
	}
	kl := KeyLog{CesrSignatures: signatures}
	for _, raw := range rawEvents {
		kl.RawEventsB64 = append(kl.RawEventsB64, base64.StdEncoding.EncodeToString(raw))
	}
	b, err := json.Marshal(kl)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DecodeKeyLog reads a key log in the form EncodeKeyLog writes. It checks
// nothing; KeyFromKeyLog is what says whether the log proves anything.
func DecodeKeyLog(encoded string) (KeyLog, error) {
	var kl KeyLog
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return kl, fmt.Errorf("the key log is not readable: %w", err)
	}
	if err := json.Unmarshal(b, &kl); err != nil {
		return kl, fmt.Errorf("the key log is not readable: %w", err)
	}
	return kl, nil
}

// A key log carried with a sign-in, or published to a registry, is a pairwise
// identity's: an inception, and at most a little after it. The bounds keep
// anybody from making this agent hold or check a long one on their behalf.
const (
	MaxKeyLogEvents = 8
	MaxKeyLogBytes  = 64 << 10
)

// KeyFromKeyLog returns aid's current signing key from a key log carried with
// a sign-in, or says why the log does not establish one.
//
// It reaches out to nothing: everything it needs is in the log, and the log
// proves itself or it does not.
func KeyFromKeyLog(aid, encoded string) ([]byte, error) {
	if aid == "" {
		return nil, fmt.Errorf("no identifier was named, so there is nothing for a key log to belong to")
	}
	if encoded == "" {
		return nil, fmt.Errorf("no key log came with this, so nothing ties a key to %s", aid)
	}
	if len(encoded) > MaxKeyLogBytes {
		return nil, fmt.Errorf("the key log of %s is longer than a sign-in carries (%d bytes, at most %d)",
			aid, len(encoded), MaxKeyLogBytes)
	}
	kl, err := DecodeKeyLog(encoded)
	if err != nil {
		return nil, err
	}
	if len(kl.RawEventsB64) > MaxKeyLogEvents {
		return nil, fmt.Errorf("the key log of %s has %d events; a sign-in carries at most %d",
			aid, len(kl.RawEventsB64), MaxKeyLogEvents)
	}
	raws, err := drivers.DecodeRawEvents(kl.RawEventsB64)
	if err != nil {
		return nil, err
	}
	res, err := drivers.ValidateKELFromBytes(drivers.ValidateKELInput{
		AID:            aid,
		RawEvents:      raws,
		CesrSignatures: kl.CesrSignatures,
	})
	if err != nil {
		return nil, err
	}
	if err := unprovableRotation(aid, raws); err != nil {
		return nil, err
	}
	// A key log carried this way comes without its delegator's, so a
	// delegated inception in it claims an approval nothing here can see. A
	// sign-in's pairwise identity is never delegated; one that says it is
	// was not made by an Identity Agent's sign-in.
	if icp, err := keri.ParseEvent(raws[0]); err == nil && (icp.Ilk == "dip" || icp.Delegator != "") {
		return nil, fmt.Errorf("the key log of %s opens with a delegated inception, and no delegator's "+
			"log comes with it to show the delegation was approved", aid)
	}
	return currentKey(aid, res.KelVerified, res.ValidationErrors, res.CurrentPublicKey)
}

// VerifiedIdentity is what an identity's introduction proved: its current key,
// and the canonical bytes of the log that proved it, for a caller that has to
// read an event (a delegated inception, say) from the bytes that were checked.
type VerifiedIdentity struct {
	Key       []byte
	RawEvents [][]byte
	// NamesWitnesses says the identity's inception designates witnesses, and
	// Witnessed that every event the introduction served carried enough of
	// their receipts.
	NamesWitnesses, Witnessed bool
}

// KeyFromOOBI resolves aid's introduction and returns its current signing key,
// only if the key log served there validates and belongs to aid.
//
// Whoever serves the introduction controls every byte of it, which is why the
// address is no part of the trust: a log that derives aid proves itself from
// anywhere, and one that does not proves nothing from anywhere.
func KeyFromOOBI(client *http.Client, oobiURL, aid string) ([]byte, error) {
	id, err := IdentityFromOOBI(client, oobiURL, aid)
	if err != nil {
		return nil, err
	}
	return id.Key, nil
}

// IdentityFromOOBI is KeyFromOOBI with the verified log kept.
//
// A delegated inception is accepted as the identity's own log without its
// delegator's approval being checked: the key is the identity's whoever
// delegated it. Anything that relies on the delegation itself checks it
// (verifyDelegationAnchor).
func IdentityFromOOBI(client *http.Client, oobiURL, aid string) (VerifiedIdentity, error) {
	return identityFromOOBI(client, oobiURL, aid, true)
}

// identityFromOOBI resolves and validates aid's introduction. mustBeCurrent
// says the caller relies on the identity's present authority, so a rotation
// nothing can prove the newest is refused. Every caller does today, a
// delegator's approval included: a retired key can sign a new approval on a
// branch made from the shorter log, so "what the log once signed" is not a
// weaker question (verifyDelegationAnchor).
func identityFromOOBI(client *http.Client, oobiURL, aid string, mustBeCurrent bool) (VerifiedIdentity, error) {
	if aid == "" {
		return VerifiedIdentity{}, fmt.Errorf("no identifier was named, so there is nothing for an introduction to belong to")
	}
	var c keriengine.HTTPClient
	if client != nil {
		c = client
	}
	res, err := keriengine.ResolveOobiWith(c, oobiURL)
	if err != nil {
		return VerifiedIdentity{}, err
	}
	if res.CID != aid {
		return VerifiedIdentity{}, fmt.Errorf("the introduction at %s is for %s, not %s", oobiURL, res.CID, aid)
	}
	key, err := currentKey(aid, res.KelVerified, res.ValidationErrors, res.CurrentPublicKey)
	if err != nil {
		return VerifiedIdentity{}, err
	}
	if mustBeCurrent {
		if err := unprovableRotation(aid, res.RawEvents); err != nil {
			return VerifiedIdentity{}, err
		}
	}
	names, err := namesWitnesses(aid, res.RawEvents)
	if err != nil {
		return VerifiedIdentity{}, err
	}
	return VerifiedIdentity{Key: key, RawEvents: res.RawEvents, NamesWitnesses: names, Witnessed: res.Witnessed}, nil
}

// namesWitnesses reports whether aid's inception designates witnesses.
func namesWitnesses(aid string, raws [][]byte) (bool, error) {
	if len(raws) == 0 {
		return false, nil
	}
	icp, err := keri.ParseEvent(raws[0])
	if err != nil {
		return false, fmt.Errorf("the inception of %s does not parse: %w", aid, err)
	}
	return len(icp.Witnesses) > 0, nil
}

// unprovableRotation refuses a rotated log from an identity that names no
// witnesses.
//
// A log proves who signed it, never that it is the newest. Whoever still holds
// a key a rotation retired can present the log as it stood before the
// rotation, and nothing in that shorter log says otherwise; only witnesses
// who saw the rotation can. An identity with none has nobody to ask, so its
// rotation could never retire a key, and a log that shows one is claiming
// something nothing here can prove. Such an identity is never rotated: its key
// is retired by ending the relationship it was made for.
//
// An identity that names witnesses is accepted as its log stands. Asking its
// witnesses for their newest event, so a shortened log is caught, is not done
// here yet.
func unprovableRotation(aid string, raws [][]byte) error {
	if len(raws) < 2 {
		return nil
	}
	icp, err := keri.ParseEvent(raws[0])
	if err != nil {
		return fmt.Errorf("the inception of %s does not parse: %w", aid, err)
	}
	if len(icp.Witnesses) > 0 {
		return nil
	}
	for i, raw := range raws[1:] {
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			return fmt.Errorf("event %d of %s does not parse: %w", i+1, aid, err)
		}
		if ev.Establishment() {
			return fmt.Errorf("%s names no witnesses, so nothing can show its rotation is the newest; "+
				"an identity without witnesses is never rotated, and its key is retired by ending "+
				"the relationship it was made for", aid)
		}
	}
	return nil
}

// OOBIFor is where aid's introduction is published under base, the form every
// introduction in this protocol takes.
func OOBIFor(base, aid string) string {
	if i := strings.Index(base, "/oobi/"); i >= 0 {
		base = base[:i]
	}
	return trimSlash(base) + "/oobi/" + aid
}

func currentKey(aid string, verified bool, problems []string, currentQB64 string) ([]byte, error) {
	if !verified {
		why := "it does not validate"
		if len(problems) > 0 {
			why = strings.Join(problems, "; ")
		}
		return nil, fmt.Errorf("the key log of %s establishes no key: %s", aid, why)
	}
	return iacrypto.KeyFromVerkeyQB64(currentQB64)
}
