// Package binding is the statement by which a person joins two of their
// identifiers to one record at a site, and the check that it is theirs (ADR-082).
//
// A person has a different identifier at every site they deal with. Where a site
// (a utility app a person's organisation runs, say) must keep something under one
// record for a person who reaches it by more than one identifier, the person says
// so once: one statement naming both identifiers, the organisation and the site,
// signed with BOTH keys over the same bytes. A statement signed by one key only
// proves one key was held, and is refused: someone who holds only the new
// identifier cannot have it joined to a record that is not theirs.
package binding

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
)

// Version names the statement's format. It is part of the signed bytes.
const Version = "BIND1"

// Roles a statement may join an identifier in.
const (
	RolePerson = "person"
	RoleOwner  = "owner"
)

// Statement is what both keys sign. Every field is signed, so neither signer can
// be shown one thing and made to sign another, and a statement made for one
// invite, site or organisation cannot be carried to another.
type Statement struct {
	V string `json:"v"`
	// Org is the identifier of the organisation that asked.
	Org string `json:"org"`
	// Site is the site the new identifier is the person's at.
	Site string `json:"site"`
	// Record is an identifier the record already holds, or the one it starts
	// from. Any identifier already joined to the record may stand here.
	Record string `json:"record"`
	// New is the identifier being joined to it.
	New string `json:"new"`
	// Invite is the digest of the single-use invite this answers, never its code.
	Invite string `json:"invite"`
	// Role is person, or owner for the one who owns the organisation.
	Role string `json:"role"`
}

// identifierForm is what every field naming an identifier or a digest must look like: the characters of a
// qb64 value and nothing else. That keeps the signed bytes plain ASCII, so every implementation writes them
// the same way (a character a JSON writer may escape is never in them).
var identifierForm = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// Link is a statement with the two signatures, each with the key that made it.
type Link struct {
	Statement Statement `json:"statement"`
	RecordKey string    `json:"record_key"`
	RecordSig string    `json:"record_sig"`
	NewKey    string    `json:"new_key"`
	NewSig    string    `json:"new_sig"`
}

// SignedBytes is the one string both keys sign.
func (s Statement) SignedBytes() []byte {
	b, _ := json.Marshal(s)
	return b
}

// Expect is what the one verifying a link already knows, so the link has to
// fit it rather than say what to expect.
type Expect struct {
	Org    string
	Site   string
	Invite string // the digest of the invite that was redeemed
	// KeyIsCurrent says whether key is a current signing key of the identifier.
	// It is the verifier's own record of the identifier's key log, never the
	// link's word for it.
	KeyIsCurrent func(identifier, key string) error
}

// Sign makes a link from the two keys' seeds. The keys named are the ones the
// seeds make, as a verifier will check.
func Sign(s Statement, recordSeed, newSeed []byte) (Link, error) {
	body := string(s.SignedBytes())
	rs, err := login.SignString(body, recordSeed)
	if err != nil {
		return Link{}, fmt.Errorf("the record's key could not sign: %w", err)
	}
	ns, err := login.SignString(body, newSeed)
	if err != nil {
		return Link{}, fmt.Errorf("the new identifier's key could not sign: %w", err)
	}
	rk, err := iacrypto.MatterFixedQB64("D", ed25519.NewKeyFromSeed(recordSeed).Public().(ed25519.PublicKey))
	if err != nil {
		return Link{}, err
	}
	nk, err := iacrypto.MatterFixedQB64("D", ed25519.NewKeyFromSeed(newSeed).Public().(ed25519.PublicKey))
	if err != nil {
		return Link{}, err
	}
	return Link{Statement: s, RecordKey: rk, RecordSig: rs, NewKey: nk, NewSig: ns}, nil
}

// Verify checks a link and says why it refuses one.
func (l Link) Verify(e Expect) error {
	s := l.Statement
	switch {
	case s.V != Version:
		return errors.New("that is not a statement of a binding")
	case s.Role != RolePerson && s.Role != RoleOwner:
		return errors.New("a binding names a person or the owner")
	case s.Org == "" || s.Site == "" || s.Record == "" || s.New == "" || s.Invite == "":
		return errors.New("a binding names the organisation, the site, both identifiers and the invite")
	case !identifierForm.MatchString(s.Org) || !identifierForm.MatchString(s.Site) || !identifierForm.MatchString(s.Record) ||
		!identifierForm.MatchString(s.New) || !identifierForm.MatchString(s.Invite):
		return errors.New("every identifier and the invite are written as an identifier is: letters, digits, - and _")
	case s.Record == s.New:
		return errors.New("a binding joins two identifiers, not one to itself")
	case e.Org == "" || e.Site == "" || e.Invite == "" || e.KeyIsCurrent == nil:
		return errors.New("the check was not told what to expect")
	case s.Org != e.Org:
		return errors.New("this binding is for another organisation")
	case s.Site != e.Site:
		return errors.New("this binding is for another site")
	case s.Invite != e.Invite:
		return errors.New("this binding answers another invite")
	}
	if l.RecordKey == l.NewKey {
		return errors.New("the two identifiers have one key between them: a binding is signed by two keys")
	}
	body := string(s.SignedBytes())
	if err := checkOne("the record's", s.Record, l.RecordKey, l.RecordSig, body, e); err != nil {
		return err
	}
	return checkOne("the new identifier's", s.New, l.NewKey, l.NewSig, body, e)
}

func checkOne(who, identifier, key, sig, body string, e Expect) error {
	if key == "" || sig == "" {
		return fmt.Errorf("%s key has not signed: a binding is signed with both keys", who)
	}
	if strings.TrimSpace(key) != key {
		return fmt.Errorf("%s key is not written as a key is", who)
	}
	raw, _, err := iacrypto.DecodeEd25519Key(key, false)
	if err != nil {
		return fmt.Errorf("%s key is not a key: %w", who, err)
	}
	if err := e.KeyIsCurrent(identifier, key); err != nil {
		return fmt.Errorf("%s key is not a key of %s: %w", who, identifier, err)
	}
	ok, err := login.VerifyDetachedSig(body, sig, raw)
	if err != nil || !ok {
		return fmt.Errorf("%s signature does not verify over the statement", who)
	}
	return nil
}
