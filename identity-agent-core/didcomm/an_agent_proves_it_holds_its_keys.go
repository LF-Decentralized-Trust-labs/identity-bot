package didcomm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// An Identity Agent proving, to whoever asks, that it holds the keys its
// identifier has in force.
//
// WHY. An address that serves an identifier's key log has shown only that it
// can copy a public document: a reverse proxy in front of the real agent
// serves the same log. What the proxy cannot do is sign, because the keys the
// log commits to (ADR-061 section 8) are held by the agent and nowhere else.
// So the asker chooses a fresh value and the agent signs it with those keys.
//
// THE FORM. The asker supplies three things: the identifier it believes it is
// talking to, the origin it dialled (scheme://host:port, ADR-062's one
// spelling), and a challenge it made up for this question. The agent signs all
// three, with the time, under both halves of its hybrid signing key, and
// answers with the keys it signed with. The asker then:
//
//  1. requires the answer to name the identifier, origin and challenge it
//     asked, and a time close to its own clock;
//  2. checks the keys against its own verified copy of the identifier's WHOLE
//     key log with CheckKeysBelongTo, which takes the keyset the log anchored
//     last and so refuses keys the identifier has replaced; and
//  3. verifies both signatures with those keys.
//
// WHAT EACH PART DEFENDS.
//   - The challenge defends against replay: an answer to another challenge
//     does not verify, so a recorded answer is useless, and a proxy that
//     relays the asker's challenge gets nothing it can reuse.
//   - The origin defends against a proxy that relays everything, challenge
//     included. The agent signs only for an origin that is its own, and the
//     asker requires the signed origin to be the one it dialled, so a relay
//     must either be refused by the agent or hand back an answer for an
//     address that is not the one dialled.
//   - The log defends against an agent that signs with keys of its own: they
//     are not the ones the identifier committed to.
//
// WHAT IT DOES NOT SHOW. That the agent is the identifier's agent today and
// not an older host of the same keys, which is the key log's business
// (rotation), and that nothing else on the machine could also sign. The
// signature is made with the keyset the Identity Agent uses for messaging, not
// the identifier's KERI controlling key, which does not live on the agent
// (identity_signing.go).

// KeyProofForm is the first line of what is signed. A change to the form is a
// new line, so a signature made for this is never another form's.
const KeyProofForm = "IA-KEYS-IN-FORCE-PROOF-V1"

// KeyProofIssuedLayout is the one spelling of the time in a proof: UTC, whole
// seconds, a literal Z (the same as an endpoint record's).
const KeyProofIssuedLayout = "2006-01-02T15:04:05Z"

// KeyProofMaxAge and KeyProofMaxAhead bound how far a proof's time may be from
// the asker's clock. The challenge is what makes a proof fresh; the time makes
// a proof that is old on its face refusable without remembering challenges.
const (
	KeyProofMaxAge   = 2 * time.Minute
	KeyProofMaxAhead = 1 * time.Minute
)

// KeyProof is what an Identity Agent answers with.
type KeyProof struct {
	// DID is the keys signed with: the public half of the agent's keyset, with
	// the identity's signature over them where this agent can make one.
	DID       DID    `json:"did"`
	Origin    string `json:"origin"`
	Challenge string `json:"challenge"`
	Issued    string `json:"issued"`
	EdSig     string `json:"ed_sig"`    // base64url, Ed25519 over KeyProofInput
	DsaSig    string `json:"mldsa_sig"` // base64url, ML-DSA-65 over KeyProofInput
}

// KeyProofInput is the exact bytes signed. Length-prefixed, as
// DID.SigningInput is, because the challenge and origin are strings a caller
// chooses and a delimiter only separates fields that cannot contain it.
func KeyProofInput(aid, origin, challenge, issued string) []byte {
	var b bytes.Buffer
	b.WriteString(KeyProofForm)
	for _, f := range []string{aid, origin, challenge, issued} {
		_ = binary.Write(&b, binary.BigEndian, uint32(len(f)))
		b.WriteString(f)
	}
	return b.Bytes()
}

// ProveKeysInForce signs a challenge with ks. kelSig, when the caller can make
// one, is the identity's signature over the keys (DID.KelSig), carried so that
// an identifier whose log anchors no keyset can still be checked.
//
// It does not look at the key log: which keyset is in force is the caller's
// to choose, and the asker checks the answer against the log either way.
func ProveKeysInForce(ks *KeySet, kelSig, origin, challenge string, now time.Time) (*KeyProof, error) {
	did, err := ks.DID()
	if err != nil {
		return nil, err
	}
	did.KelSig = kelSig
	issued := now.UTC().Truncate(time.Second).Format(KeyProofIssuedLayout)
	edSig, dsaSig := signHybrid(ks, KeyProofInput(ks.AID, origin, challenge, issued))
	return &KeyProof{
		DID: *did, Origin: origin, Challenge: challenge, Issued: issued,
		EdSig: b64.EncodeToString(edSig), DsaSig: b64.EncodeToString(dsaSig),
	}, nil
}

// CheckKeyProof decides whether p is a fresh answer, for the identifier, origin
// and challenge the asker chose, signed by the keys that identifier has in
// force. kelEvents is the identifier's whole verified key log and currentKey
// the signing key it ends with, exactly as CheckKeysBelongTo takes them.
//
// Every refusal names what was wrong, in words the asker can show.
func CheckKeyProof(p *KeyProof, aid, origin, challenge string, kelEvents []map[string]interface{},
	currentKey string, now time.Time) error {
	if p == nil {
		return fmt.Errorf("no proof was given")
	}
	// The question first: an answer to another question proves nothing here,
	// however well it is signed.
	if p.DID.AID != aid {
		return fmt.Errorf("the answer is for %q, not %s", p.DID.AID, aid)
	}
	if p.Origin != origin {
		return fmt.Errorf("the answer was signed for %q, not for the address %q that was asked",
			p.Origin, origin)
	}
	if p.Challenge != challenge {
		return fmt.Errorf("the answer is to a different challenge, so it may be a recorded one")
	}
	issued, err := time.Parse(KeyProofIssuedLayout, p.Issued)
	if err != nil || issued.Format(KeyProofIssuedLayout) != p.Issued {
		return fmt.Errorf("the answer's time is not in the form %s", KeyProofIssuedLayout)
	}
	if age := now.Sub(issued); age > KeyProofMaxAge {
		return fmt.Errorf("the answer is %s old", age.Round(time.Second))
	} else if -age > KeyProofMaxAhead {
		return fmt.Errorf("the answer is dated %s ahead of this clock", (-age).Round(time.Second))
	}

	// The keys are the identifier's, in force now.
	if _, err := CheckKeysBelongTo(&p.DID, kelEvents, currentKey); err != nil {
		return err
	}

	pd, err := p.DID.parse()
	if err != nil {
		return fmt.Errorf("the keys in the answer are unusable: %w", err)
	}
	edSig, dsaSig, ok := hybridSignatures(p.EdSig, p.DsaSig)
	if !ok {
		return fmt.Errorf("the answer's signatures are not readable")
	}
	if !verifyHybrid(pd, KeyProofInput(aid, origin, challenge, p.Issued), edSig, dsaSig) {
		return fmt.Errorf("the answer is not signed by the keys %s has in force", aid)
	}
	return nil
}
