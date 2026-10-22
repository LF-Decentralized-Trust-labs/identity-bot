package server

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/schemas"
)

// Whoever authorised a credential is named in it.
//
// An AI agent's grant and the credential that makes a machine its body were
// issued by the identity and named nobody: who created the AI agent, or who
// compared the six words and approved the machine, was a local field at best.
// Anything the AI agent then did traced back to the identity and stopped.
//
// Now each such credential carries an edge to the Controller Grant of the
// machine the request came from, and the request itself as that machine signed
// it. The Controller Grant names the signer the machine acts as and is anchored
// in the identity's key log, so the chain runs from what was done, through the
// person who authorised it and the machine they used, to the identity's own
// keys, and every link can be checked without asking this Identity Agent.
//
// A request made with the identity's own key, by the device holding it, has
// no machine between it and the identity: the issuer is the authority, and
// there is nothing further to name.

// authority is who authorised a credential: the Controller Grant of the
// machine the request came from, and the request as the machine signed it.
// The zero value is the identity's own key.
type authority struct {
	// ControllerGrant is the machine's Controller Grant credential, when it
	// has one. A grant made before machines were given one leaves this empty
	// and the request still recorded.
	ControllerGrant string
	Request         *signedRequest
}

// signedRequest is a request exactly as the machine that made it signed it.
type signedRequest struct {
	Signer    string `json:"signer"`
	Signed    string `json:"signed"`
	Signature string `json:"signature"`
}

// authorityOf is who authorised the request r: the controller that signed it,
// if one did.
func (s *CoreServer) authorityOf(r *http.Request) (authority, error) {
	grant, ok := TheControllerThatAsked(r)
	if !ok {
		return authority{}, nil
	}
	signed, sig, err := s.theRequestAsSigned(r, grant)
	if err != nil {
		return authority{}, err
	}
	return authority{
		ControllerGrant: grant.CredentialSAID,
		Request:         &signedRequest{Signer: grant.ControllerAID, Signed: signed, Signature: sig},
	}, nil
}

// theRequestAsSigned is the string a controller signed for r and its
// signature, rebuilt as of the moment it was signed, so what is kept is exactly
// what the signature covers whatever has expired since.
func (s *CoreServer) theRequestAsSigned(r *http.Request, grant ControllerGrant) (string, string, error) {
	stamp := strings.TrimSpace(r.Header.Get(headerControllerTimestamp))
	at, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return "", "", err
	}
	signed, _, err := s.theStringThisMachineSigned(r, grant.ControllerAID, stamp, at.UTC())
	if err != nil {
		return "", "", err
	}
	return signed, strings.TrimSpace(r.Header.Get(headerControllerSig)), nil
}

// name writes the authority into a credential about to be issued: an edge to
// the Controller Grant and the signed request among its attributes. A schema
// that admits neither is left as it is.
func (a authority) name(kind *schemas.AssetGrant, claims map[string]interface{}) map[string]interface{} {
	if !kind.HasEdges() {
		return nil
	}
	if a.Request != nil {
		claims["request"] = map[string]interface{}{
			"signer": a.Request.Signer, "signed": a.Request.Signed, "signature": a.Request.Signature,
		}
	}
	if a.ControllerGrant == "" {
		return nil
	}
	return map[string]interface{}{
		"authorised_by": map[string]interface{}{"n": a.ControllerGrant, "s": schemas.ControllerGrant.Schema.SAID},
	}
}

// grantController records that a machine may act for this identity and issues
// its Controller Grant, anchored in the identity's key log. A machine whose
// grant cannot be anchored is not granted: what it did could never be shown to
// rest on anybody's authority. A grant it replaces has its credential revoked.
func (s *CoreServer) grantController(g ControllerGrant, now time.Time) (ControllerGrant, error) {
	before, had, err := s.controllers().Get(g.ControllerAID)
	if err != nil {
		return ControllerGrant{}, err
	}
	granted, err := s.controllers().Grant(g, now)
	if err != nil {
		return ControllerGrant{}, err
	}
	said, err := s.issueControllerGrant(granted)
	if err != nil {
		// Not granted after all. The machine had no grant, or the one it had
		// is put back as it was.
		if had {
			if _, rerr := s.controllers().Grant(before, before.GrantedAt); rerr != nil {
				log.Printf("[controller] %s: the earlier grant could not be put back: %v", g.ControllerAID, rerr)
			}
		} else if rerr := s.controllers().Revoke(g.ControllerAID); rerr != nil {
			log.Printf("[controller] %s: an unanchored grant could not be removed: %v", g.ControllerAID, rerr)
		}
		return ControllerGrant{}, fmt.Errorf("the machine's grant could not be anchored, so it was not granted: %w", err)
	}
	if err := s.controllers().SetCredential(granted.ControllerAID, said); err != nil {
		return ControllerGrant{}, err
	}
	granted.CredentialSAID = said
	if had && before.CredentialSAID != "" && before.CredentialSAID != said {
		s.withdrawControllerGrant(before.CredentialSAID)
	}
	return granted, nil
}

// issueControllerGrant issues the credential for a grant already recorded.
func (s *CoreServer) issueControllerGrant(g ControllerGrant) (string, error) {
	if s.DataStore == nil || s.KeriDriver == nil {
		return "", fmt.Errorf("this Identity Agent has no key log to anchor the grant in")
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return "", fmt.Errorf("this Identity Agent has no identity to grant for")
	}
	claims := map[string]interface{}{
		"name": g.Label, "label": g.Label, "public_key": g.PublicKey, "grade": string(g.Grade),
	}
	if g.Signer != "" {
		claims["signer"] = g.Signer
	}
	expiry := ""
	if !g.ExpiresAt.IsZero() {
		expiry = g.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return s.issueAssetCredential(schemas.ControllerGrant, g.ControllerAID, identity.AID, claims, expiry, authority{})
}

// revokeController takes a machine's authorisation away, and withdraws its
// Controller Grant. The machine stops at once whatever happens to the
// withdrawal: someone removing a stolen laptop must never be told to wait for
// a key log.
func (s *CoreServer) revokeController(aid string) error {
	g, had, err := s.controllers().Get(aid)
	if err != nil {
		return err
	}
	if err := s.controllers().Revoke(aid); err != nil {
		return err
	}
	if had && g.CredentialSAID != "" {
		s.withdrawControllerGrant(g.CredentialSAID)
	}
	return nil
}

// bindSigner records which signer a machine acts as, and re-issues its
// Controller Grant to say so: the credential is what shows, to anybody, whose
// authority the machine carries.
func (s *CoreServer) bindSigner(aid, signer string) (ControllerGrant, error) {
	before, _, err := s.controllers().Get(aid)
	if err != nil {
		return ControllerGrant{}, err
	}
	g, err := s.controllers().BindSigner(aid, signer)
	if err != nil || g.Signer == before.Signer || g.CredentialSAID == "" {
		return g, err
	}
	said, err := s.issueControllerGrant(g)
	if err != nil {
		return g, fmt.Errorf("the machine now acts as %s, but its grant could not be re-issued to say so: %w", signer, err)
	}
	if err := s.controllers().SetCredential(aid, said); err != nil {
		return g, err
	}
	s.withdrawControllerGrant(g.CredentialSAID)
	g.CredentialSAID = said
	return g, nil
}

// withdrawControllerGrant revokes a Controller Grant credential, saying so when
// the revocation cannot be written to the registry.
func (s *CoreServer) withdrawControllerGrant(said string) {
	rec, err := s.DataStore.GetCredential(said)
	if err != nil || rec == nil {
		log.Printf("[controller] grant credential %s is not on record, so it could not be withdrawn", said)
		return
	}
	if _, err := s.revokeIssuedCredential(rec); err != nil {
		log.Printf("[controller] grant credential %s: its revocation was not recorded in the registry: %v", said, err)
	}
	if err := s.DataStore.UpdateCredentialStatus(said, "revoked"); err != nil {
		log.Printf("[controller] grant credential %s not marked revoked: %v", said, err)
	}
}
