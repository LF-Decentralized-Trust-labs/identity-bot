package server

// A grant issued where the identity's key is held on another device.
//
// Issuing a Controller Grant or an AI Agent Grant appends an interaction to
// the identity's key log, which only the device holding the key may sign.
// Where that is another device, the grant is built here exactly as it will be
// issued, checked against the request it rests on, and kept; the interaction
// that anchors it is queued for that device to sign, as a signing request
// whose payload is exactly those bytes and whose summary says what signing it
// grants. When the signature comes back it is checked against the identity's
// current key, the grant is appended exactly as built, and the machine or AI
// agent stops waiting. Nothing is written into the key log here unsigned.
//
// The device signing it is trusted to sign only an interaction that extends
// the key log as it holds it: an interaction built here on a key log that has
// moved on is refused when it comes back, and built again.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"identity-agent-core/drivers"
	"identity-agent-core/login"
	"identity-agent-core/schemas"
)

// signingKindGrant is the signing request for a grant's anchoring interaction.
const signingKindGrant = "grant-issuance"

// pendingIssuance is a grant built and waiting for its interaction to be
// signed by the device that holds the identity's key.
type pendingIssuance struct {
	Schema        string                   `json:"schema"`
	Claims        map[string]interface{}   `json:"claims"`
	Edges         map[string]interface{}   `json:"edges,omitempty"`
	Prepared      drivers.PreparedIssuance `json:"prepared"`
	Holder        string                   `json:"holder"`
	Expiry        string                   `json:"expiry,omitempty"`
	RequestDigest string                   `json:"request_digest,omitempty"`
	About         string                   `json:"about,omitempty"`
	Grant         string                   `json:"controller_grant,omitempty"`
	Request       *signedRequest           `json:"request,omitempty"`
}

func (p pendingIssuance) by() authority {
	return authority{About: p.About, ControllerGrant: p.Grant, Request: p.Request}
}

func grantKindNamed(schema string) *schemas.AssetGrant {
	switch schema {
	case schemas.AIAgentGrant.Schema.SAID:
		return schemas.AIAgentGrant
	case schemas.ControllerGrant.Schema.SAID:
		return schemas.ControllerGrant
	}
	return nil
}

// awaitSignature keeps a prepared grant and asks the device that holds the
// identity's key to sign its anchoring interaction.
func (s *CoreServer) awaitSignature(kind *schemas.AssetGrant, p *drivers.PreparedIssuance, claims, edges map[string]interface{},
	holder, expiry, requestDigest string, by authority) (string, error) {
	pending := pendingIssuance{Schema: kind.Schema.SAID, Claims: claims, Edges: edges, Prepared: *p, Holder: holder, Expiry: expiry,
		RequestDigest: requestDigest, About: by.About, Grant: by.ControllerGrant, Request: by.Request}
	body, err := json.Marshal(pending)
	if err != nil {
		return "", err
	}
	summary, detail := s.whatSigningGrants(kind, p, holder)
	id, err := s.EnqueueSigningRequest(p.Issuer, signingKindGrant, summary, detail, p.IxnRaw, PresentationConsent)
	if err != nil {
		return "", err
	}
	if err := s.DataStore.SavePendingIssuance(id, string(body)); err != nil {
		return "", err
	}
	return id, nil
}

// whatSigningGrants is what the person is shown: what signing this grants,
// and to whom.
func (s *CoreServer) whatSigningGrants(kind *schemas.AssetGrant, p *drivers.PreparedIssuance, holder string) (string, string) {
	var acdc struct {
		A map[string]interface{} `json:"a"`
	}
	_ = json.Unmarshal(p.AcdcRaw, &acdc)
	name, _ := acdc.A["name"].(string)
	switch kind {
	case schemas.ControllerGrant:
		grade, _ := acdc.A["grade"].(string)
		return fmt.Sprintf("Let the machine %q act for you", name),
			fmt.Sprintf("Signing this grants the machine %s (%s) authority to act for this identity, at the %s grade. "+
				"Your key is on this device, so the grant waits for it here.", name, holder, grade)
	default:
		var caps []string
		if list, ok := acdc.A["capabilities"].([]interface{}); ok {
			for _, c := range list {
				if v, ok := c.(string); ok {
					caps = append(caps, v)
				}
			}
		}
		what := "nothing"
		if len(caps) > 0 {
			what = strings.Join(caps, ", ")
		}
		return fmt.Sprintf("Let the AI agent %q do what it was granted", name),
			fmt.Sprintf("Signing this grants the AI agent %s (%s): %s. Until it is signed the AI agent may do nothing. "+
				"Your key is on this device, so the grant waits for it here.", name, holder, what)
	}
}

// errGrantSignature is a signature for a waiting grant that does not hold.
var errGrantSignature = errors.New("the signature does not hold for the identity's current key")

// completeWaitingGrant appends a waiting grant with the signature the device
// that holds the key made over its interaction, and stops the machine or AI
// agent waiting. A signature that does not hold changes nothing; a grant whose
// key log has moved on is built again and asked for afresh.
func (s *CoreServer) completeWaitingGrant(requestID, signature string) error {
	body, ok, err := s.DataStore.GetPendingIssuance(requestID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no grant waits for this signature")
	}
	var pending pendingIssuance
	if err := json.Unmarshal([]byte(body), &pending); err != nil {
		return err
	}
	kind := grantKindNamed(pending.Schema)
	if kind == nil {
		return fmt.Errorf("the waiting grant is of no kind this agent issues")
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil || identity.AID != pending.Prepared.Issuer {
		return fmt.Errorf("the waiting grant is not this identity's")
	}
	pub, err := login.DecodeVerkey(identity.PublicKey)
	if err != nil {
		return err
	}
	if ok, err := login.VerifyString(string(pending.Prepared.IxnRaw), signature, pub); err != nil || !ok {
		return errGrantSignature
	}
	preparer, can := s.KeriDriver.(drivers.PreparedIssuer)
	if !can {
		return fmt.Errorf("this engine cannot append a prepared grant")
	}
	// Checked again against the request: the grant it rests on may have been
	// withdrawn meanwhile.
	by := pending.by()
	if err := s.checkAuthorisationOf(pending.Prepared.AcdcRaw, pending.Prepared.Issuer, "", "", by); err != nil {
		return fmt.Errorf("the waiting grant no longer rests on its request: %w", err)
	}
	s.engineKeepsCredentialLogs()
	s.signedElsewhere.Store(base64.StdEncoding.EncodeToString(pending.Prepared.IxnRaw), signature)
	defer s.signedElsewhere.Delete(base64.StdEncoding.EncodeToString(pending.Prepared.IxnRaw))
	result, err := preparer.AppendPreparedIssuance(pending.Prepared.Issuer, &pending.Prepared)
	if errors.Is(err, drivers.ErrStalePreparation) {
		// Built on a key log that has moved on: built again and asked afresh.
		_ = s.DataStore.DeletePendingIssuance(requestID)
		fresh, perr := preparer.PrepareCredentialInRegistry(pending.Prepared.Issuer, pending.Claims, pending.Schema, pending.Holder,
			pending.Edges, pending.Prepared.Registry)
		if perr == nil {
			if _, perr = s.awaitSignature(kind, fresh, pending.Claims, pending.Edges, pending.Holder, pending.Expiry, pending.RequestDigest, by); perr == nil {
				return fmt.Errorf("%w; it has been built again and asked for afresh", err)
			}
		}
		return fmt.Errorf("%w, and it could not be built again: %v", err, perr)
	}
	if err != nil {
		return fmt.Errorf("the waiting grant could not be appended: %w", err)
	}
	said, err := s.finishIssuance(kind, result, pending.Holder, pending.Prepared.Issuer, pending.Expiry,
		pending.Prepared.Registry, pending.RequestDigest, by)
	if err != nil {
		return err
	}
	_ = s.DataStore.DeletePendingIssuance(requestID)
	s.grantArrived(kind, pending, said)
	return nil
}

// grantArrived stops a machine or AI agent waiting for its grant.
func (s *CoreServer) grantArrived(kind *schemas.AssetGrant, pending pendingIssuance, said string) {
	switch kind {
	case schemas.ControllerGrant:
		s.grantsMu.Lock()
		defer s.grantsMu.Unlock()
		g, had, err := s.controllers().Get(pending.Holder)
		if err != nil || !had {
			log.Printf("[grants] machine %s was granted %s and is no longer paired", pending.Holder, said)
			return
		}
		g.CredentialSAID, g.CredentialPending = said, false
		if err := s.controllers().Put(g); err != nil {
			log.Printf("[grants] machine %s was granted %s and could not be marked so: %v", pending.Holder, said, err)
		}
	case schemas.AIAgentGrant:
		mcpTokensMu.Lock()
		defer mcpTokensMu.Unlock()
		toks := s.loadMCPTokens()
		for i := range toks {
			if toks[i].AgentAID == pending.Holder {
				toks[i].GrantSAID, toks[i].GrantPending = said, false
			}
		}
		if err := s.saveMCPTokens(toks); err != nil {
			log.Printf("[grants] AI agent %s was granted %s and its token could not be marked so: %v", pending.Holder, said, err)
		}
	}
}
