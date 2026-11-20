package setupfile

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strconv"

	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/strictjson"
	"identity-agent-core/statements"
)

// SealForm is the first line of the statement a seal signs. It is a reserved
// header of docs/statement-signature.md: a statement made unasked, which no
// Identity Agent signs in answer to an Ask.
const SealForm = "set-up-seal/1"

// Seal is an exporting Identity Agent's signature over a file's contents.
//
// A seal that holds proves one thing: these contents left that Identity Agent
// as they are now. It gives nothing in the file any authority, it does not say
// the contents are true or wise, and it is not required: a person may edit a
// file before importing it, and the review says what a file's seal was found
// to be.
//
// Only the device that holds the identity's key can make one. An Identity
// Agent whose key is on another device exports unsealed, unless that device
// signs. An identity whose key state holds more than one key does not seal in
// this version.
type Seal struct {
	// By is the identifier of the Identity Agent that sealed the file.
	By string `json:"by"`
	// KelSN is the sequence number of the establishment event that set the
	// key that signed. It is inside the signed bytes.
	KelSN uint64 `json:"kel_sn"`
	// Contents is the digest of the contents that were sealed.
	Contents string `json:"contents"`
	// Signature is Ed25519 over SealInput, as a CESR indexed signature
	// (code A, index 0).
	Signature string `json:"signature"`
}

// SealStatement is the statement a seal signs: three lines, the form, the
// digest of the file's contents, and the sequence number of the key event
// whose key signs.
func SealStatement(contents string, kelSN uint64) string {
	return SealForm + "\ncontents=" + contents + "\nkel-sn=" + strconv.FormatUint(kelSN, 10)
}

// SealInput is the bytes a seal's signature is over. It is the statement
// signature envelope (docs/statement-signature.md, "A statement made
// unasked") with SealStatement as the statement and the sealing Identity
// Agent's own identifier on the "asker" line: nobody asked, so the signer
// names itself.
func SealInput(by, contents string, kelSN uint64) ([]byte, error) {
	if !iacrypto.IsIdentifierQB64(by) || !isQB64("E", contents) {
		return nil, errors.New("a seal names the Identity Agent that made it and the digest of what it sealed")
	}
	return statements.Envelope(by, SealStatement(contents, kelSN))
}

// NewSeal seals contents with a signer the caller supplies, which returns the
// 64-byte Ed25519 signature of the bytes it is given.
func NewSeal(by string, kelSN uint64, contents string, sign func([]byte) ([]byte, error)) (Seal, error) {
	input, err := SealInput(by, contents, kelSN)
	if err != nil {
		return Seal{}, err
	}
	raw, err := sign(input)
	if err != nil {
		return Seal{}, err
	}
	sig, err := iacrypto.MatterIndexedSigQB64("A", 0, raw, 88)
	if err != nil {
		return Seal{}, err
	}
	return Seal{By: by, KelSN: kelSN, Contents: contents, Signature: sig}, nil
}

// SealState is what a file's seal turned out to be.
type SealState string

const (
	// Unsealed is a file with no seal.
	Unsealed SealState = "unsealed"
	// Sealed is a seal that holds: its signature verifies under the key the
	// sealer's key log names at the seal's sequence number, that key is the
	// one in force, and the contents are those sealed.
	Sealed SealState = "sealed"
	// SealedByAnEarlierKey is a seal that verifies over these contents under
	// a key the sealer has since rotated away from. It was true once; whoever
	// holds a key the sealer left can still make one.
	SealedByAnEarlierKey SealState = "sealed_by_an_earlier_key"
	// Changed is a file that carries a seal made for other contents: the
	// signature verifies, over a digest that is not this file's. The file may
	// have been edited since it was sealed, or the seal may have been copied
	// from another file, so the sealer is not named: it may never have seen
	// this one.
	Changed SealState = "changed"
	// Broken is a seal whose signature does not verify under the sealer's
	// key: it proves nothing, and names nobody.
	Broken SealState = "broken"
	// Unchecked is a seal whose signature was not checked, because the
	// sealer's key could not be found. It names nobody.
	Unchecked SealState = "unchecked"
)

func readSeal(raw json.RawMessage) (*Seal, error) {
	notOne := refuse(BadSeal, "seal", "the seal is not written as a seal is")
	members, ok := strictObject(raw)
	if !ok || len(members) != 4 || OnlyMembers(members, "", "by", "kel_sn", "contents", "signature") != nil {
		return nil, notOne
	}
	var s Seal
	var okBy, okContents, okSig bool
	s.By, okBy = Text(members["by"])
	s.Contents, okContents = Text(members["contents"])
	s.Signature, okSig = Text(members["signature"])
	sn, err := strictjson.WholeNumber(json.Number(members["kel_sn"]))
	code, index, _, sigErr := iacrypto.DecodeIndexedEd25519SignatureQB64(s.Signature)
	if !okBy || !okContents || !okSig || err != nil || sn < 0 || sigErr != nil || code != 'A' || index != 0 ||
		!iacrypto.IsIdentifierQB64(s.By) || !isQB64("E", s.Contents) {
		return nil, notOne
	}
	s.KelSN = uint64(sn)
	return &s, nil
}

// KeyAt is what a sealer's key log says of one sequence number.
type KeyAt struct {
	// Key is the one Ed25519 key the establishment event at that sequence
	// number put in force.
	Key ed25519.PublicKey
	// InForce is whether that event is still the log's latest establishment
	// event, so the key is the one in force now.
	InForce bool
}

// Resolver finds, in a key log the caller verified itself, the key an
// identifier's establishment event at a sequence number put in force. It
// returns an error when there is no such event, when the log could not be
// had or verified, and when the key state there holds more than one key,
// which a seal of this version cannot be checked against. A key is never
// taken from the file, and a file carries none.
type Resolver func(by string, kelSN uint64) (KeyAt, error)

// SealOutcome is what CheckSeal found, for one file. It is made only by
// CheckSeal, so nothing can call a file sealed with a key of its own choosing.
type SealOutcome struct {
	state    SealState
	by       string
	contents string
	seal     Seal // the seal that was checked; the zero seal for a file with none
}

// State is what the seal was found to be.
func (o SealOutcome) State() SealState { return o.state }

// By is the Identity Agent that sealed these contents: set when the seal's
// signature verifies over this file's own contents, and "" otherwise.
func (o SealOutcome) By() string { return o.by }

// of is whether the outcome is what was found of this file: these contents,
// under this seal or the lack of one.
func (o SealOutcome) of(r *Result) bool {
	seal := Seal{}
	if r.Seal != nil {
		seal = *r.Seal
	}
	return o.state != "" && o.contents == r.Contents && o.seal == seal
}

// CheckSeal says what the file's seal is worth. The signature is checked
// first, over what the seal itself says it sealed: a seal that does not verify
// is broken whatever the file holds, so a seal forged in somebody's name is
// never reported as that Identity Agent's file, changed. A nil resolver, or
// one that cannot find the key, leaves a seal unchecked.
func (r *Result) CheckSeal(resolve Resolver) SealOutcome {
	out := SealOutcome{state: Unsealed, contents: r.Contents}
	s := r.Seal
	if s == nil {
		return out
	}
	out.state, out.seal = Unchecked, *s
	if resolve == nil {
		return out
	}
	at, err := resolve(s.By, s.KelSN)
	if err != nil {
		return out
	}
	input, err := SealInput(s.By, s.Contents, s.KelSN)
	_, _, raw, sigErr := iacrypto.DecodeIndexedEd25519SignatureQB64(s.Signature)
	if err != nil || sigErr != nil || len(at.Key) != ed25519.PublicKeySize || !ed25519.Verify(at.Key, input, raw) {
		out.state = Broken
		return out
	}
	switch {
	case s.Contents != r.Contents:
		out.state = Changed
	case !at.InForce:
		out.state, out.by = SealedByAnEarlierKey, s.By
	default:
		out.state, out.by = Sealed, s.By
	}
	return out
}
