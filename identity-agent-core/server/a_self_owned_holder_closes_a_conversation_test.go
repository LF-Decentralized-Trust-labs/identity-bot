package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/agentmessage"
	"identity-agent-core/backup"
	"identity-agent-core/internal/coretypes"
)

type anEd25519Key struct{ priv ed25519.PrivateKey }

func (k anEd25519Key) PublicKey() ([]byte, error)    { return k.priv.Public().(ed25519.PublicKey), nil }
func (k anEd25519Key) Sign(d []byte) ([]byte, error) { return ed25519.Sign(k.priv, d), nil }

// The holder of an Identity Agent that answers to nobody else signs as its owner
// with its own identity key (ADR-077 amendment). Their statement closes a
// conversation, they stand as owner, and nobody else's key, no other route and
// no Identity Agent that has an owner of its own gives the same.
func TestTheHolderOfASelfOwnedAgentClosesAndStandsAsOwner(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	rootSeed, err := ensureRootSeed(s.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := backup.DerivePairwiseSeed(rootSeed, 0, 0)
	holderKey := anEd25519Key{ed25519.NewKeyFromSeed(seed)}
	stranger := anEd25519Key{ed25519.NewKeyFromSeed(make([]byte, 32))}

	n := 0
	ask := func(key anEd25519Key, path, kind string, admitted bool, mutate func(*agentmessage.PersonStatement)) (coretypes.Signer, error) {
		t.Helper()
		n++
		nonce := "holder-" + string(rune('a'+n))
		body, _ := json.Marshal(agentmessage.PersonMessage{Conversation: "c1", Nonce: nonce})
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
		if admitted {
			r = r.WithContext(context.WithValue(r.Context(), theGateAdmittedTheOwnerKey{}, "signed"))
		}
		salt, _ := agentmessage.NewSalt()
		fp, _ := agentmessage.Fingerprint(salt, nil)
		id, vk, _ := agentbody.Identity(key)
		st := agentmessage.PersonStatement{
			Agent: s.thisIdentityAgentsIdentifier(), Conversation: "c1", MessageID: nonce, Kind: kind, From: "EOURS", Signer: id,
			Nonce: "nonce-0123456789abcdef" + nonce, Time: time.Now().UTC().Format(time.RFC3339),
			FingerprintVersion: agentmessage.FingerprintV1, Fingerprint: fp,
		}
		if mutate != nil {
			mutate(&st)
		}
		sig, _ := agentbody.Sign(key, st.Bytes())
		js, _ := json.Marshal(agentmessage.PersonProof{Statement: st, Verkey: vk, Signature: sig})
		r.Header.Set(headerSpeakingFor, st.From)
		r.Header.Set(headerPersonStatement, base64.RawURLEncoding.EncodeToString(js))
		r.Header.Set(headerPersonSalt, base64.RawURLEncoding.EncodeToString(salt))
		person, _, err := s.thePersonAsking(r)
		return person, err
	}
	closeRoute := "/api/mcp/conversations/c1/close"

	person, err := ask(holderKey, closeRoute, agentmessage.PersonKindClose, true, nil)
	if err != nil {
		t.Fatalf("the holder's close was refused: %v", err)
	}
	if person.AID != "EOURS" || person.Standing != "owner" {
		t.Fatalf("the holder is recorded as %+v, not as the identity's owner", person)
	}
	if !s.personStillStands(person) {
		t.Fatal("the holder of a self-owned Identity Agent does not stand as its owner")
	}

	for name, c := range map[string]func() error{
		"a key that is not the identity's": func() error {
			_, e := ask(stranger, closeRoute, agentmessage.PersonKindClose, true, nil)
			return e
		},
		"a request the gate did not admit as the owner's": func() error {
			_, e := ask(holderKey, closeRoute, agentmessage.PersonKindClose, false, nil)
			return e
		},
		"a route that is not a close, reopen or limit": func() error {
			_, e := ask(holderKey, "/api/mcp/agents/a1/conversations", agentmessage.PersonKindMessage, true,
				func(s *agentmessage.PersonStatement) { s.To = "Eagent" })
			return e
		},
		"a statement from somebody else": func() error {
			_, e := ask(holderKey, closeRoute, agentmessage.PersonKindClose, true,
				func(s *agentmessage.PersonStatement) { s.From = "ESOMEONE" })
			return e
		},
	} {
		if e := c(); e == nil {
			t.Errorf("%s was admitted as the holder", name)
		}
	}

	// Another person is not the owner of this Identity Agent.
	if s.personStillStands(coretypes.Signer{AID: "ESOMEONE", Standing: "owner"}) {
		t.Error("somebody else stands as the owner of a self-owned Identity Agent")
	}

	// An Identity Agent with an owner of its own does not answer to its identity.
	if err := s.SealOwnerAuthority(OwnerAuthority{AID: "EOWNER", PublicKey: base64.RawURLEncoding.EncodeToString(stranger.priv.Public().(ed25519.PublicKey))}); err != nil {
		t.Fatal(err)
	}
	if s.personStillStands(person) {
		t.Fatal("the identity still stands as owner once a named owner is sealed")
	}
	if _, err := ask(holderKey, closeRoute, agentmessage.PersonKindClose, true, nil); err == nil {
		t.Fatal("the identity's key closes a conversation of an Identity Agent that has an owner of its own")
	}
}
