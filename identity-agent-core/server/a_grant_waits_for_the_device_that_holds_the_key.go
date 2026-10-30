package server

// A grant issued where the identity's key is held on another device.
//
// Issuing a Controller Grant or an AI Agent Grant appends an interaction to
// the identity's key log, which only the device holding the key may sign.
// Where that is another device, the grant is built here exactly as it will be
// issued, checked against the signed request it rests on, and kept; the
// interaction that anchors it is queued for that device to sign, together
// with the credential and its issuance event, so the device can check what it
// is asked to sign and show what the credential itself says
// (authorisation.WhatSigningGrants), never anything written here about it.
// Where the identity has no registry yet, the registry's inception is asked
// for first, and the grant is built on it once it is signed.
//
// When a signature comes back it must be over the request's own payload,
// which must be the interaction kept; the credential is derived again from
// what was kept and compared; the machine or AI agent must still be there and
// still be what the grant says; and nothing may have been granted it
// meanwhile. Only then is the grant appended with that signature. At most one
// grant waits for each machine or AI agent: asking again, or removing it,
// withdraws the one waiting. Nothing is written into the key log here
// unsigned.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"identity-agent-core/authorisation"
	"identity-agent-core/drivers"
	"identity-agent-core/login"
	"identity-agent-core/schemas"
	"identity-agent-core/store"
)

// The signing requests for a grant's, and a registry's, anchoring interaction.
const (
	signingKindGrant    = "grant-issuance"
	signingKindRegistry = "registry-inception"
	// signingKindRevocation withdraws a grant the device signed that is not
	// wanted here (the_device_log_is_adopted.go).
	signingKindRevocation = "grant-revocation"
	// waitingBehind is a grant kept behind the interaction already waiting:
	// only one interaction waits at a time, since each extends the same tip.
	waitingBehind = "behind"
)

// grantSpec is everything a grant is built from, so it can be built again.
type grantSpec struct {
	Schema        string                 `json:"schema"`
	Issuer        string                 `json:"issuer"`
	Claims        map[string]interface{} `json:"claims"`
	Edges         map[string]interface{} `json:"edges,omitempty"`
	Holder        string                 `json:"holder"`
	Expiry        string                 `json:"expiry,omitempty"`
	RequestDigest string                 `json:"request_digest,omitempty"`
	About         string                 `json:"about,omitempty"`
	Grant         string                 `json:"controller_grant,omitempty"`
	Request       *signedRequest         `json:"request,omitempty"`
}

func (g grantSpec) by() authority {
	return authority{About: g.About, ControllerGrant: g.Grant, Request: g.Request}
}

// pendingIssuance is what waits for the device that holds the identity's key:
// a grant built and waiting for its interaction to be signed, or a registry's
// inception the grant waits behind.
type pendingIssuance struct {
	Kind     string                    `json:"kind"`
	Spec     grantSpec                 `json:"spec"`
	Prepared *drivers.PreparedIssuance `json:"prepared,omitempty"`
	Registry *drivers.PreparedRegistry `json:"registry,omitempty"`
	// Revocation, with the credential it withdraws, is a grant the device
	// signed that is not wanted here. Revokes names that credential.
	Revocation  *drivers.PreparedRevocation `json:"revocation,omitempty"`
	Revokes     string                      `json:"revokes,omitempty"`
	RevokedAcdc []byte                      `json:"revoked_acdc,omitempty"`
	// Closed says why an interaction no longer waits here (withdrawn): it is
	// kept, since the device may already have signed it, until the key log
	// moves past its place.
	Closed string `json:"closed,omitempty"`
}

// interaction is what a row asks the device to sign, if anything.
func (p pendingIssuance) interaction() []byte {
	switch {
	case p.Prepared != nil:
		return p.Prepared.IxnRaw
	case p.Registry != nil:
		return p.Registry.IxnRaw
	case p.Revocation != nil:
		return p.Revocation.IxnRaw
	}
	return nil
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

// errNeedsSignedRequest is a grant asked for, where the key is on another
// device, by a request that was not signed: there is nothing to show that
// device as the authority for it.
var errNeedsSignedRequest = errors.New("where the identity's key is on another device, a grant is asked for only by a signed request")

// awaitSignature keeps a prepared grant and asks the device that holds the
// identity's key to sign its anchoring interaction, withdrawing any grant
// already waiting for the same machine or AI agent.
func (s *CoreServer) awaitSignature(kind *schemas.AssetGrant, p *drivers.PreparedIssuance, spec grantSpec) (string, error) {
	if spec.Request == nil {
		return "", errNeedsSignedRequest
	}
	shown, err := authorisation.WhatSigningGrants(p.IxnRaw, p.IssRaw, p.AcdcRaw)
	if err != nil {
		return "", err
	}
	return s.queueForTheKey(signingKindGrant, pendingIssuance{Kind: signingKindGrant, Spec: spec, Prepared: p}, p.IxnRaw, summaryOf(shown))
}

// awaitRegistry asks the device that holds the identity's key to sign the
// inception of its registry, with the grant that waits behind it.
func (s *CoreServer) awaitRegistry(p *drivers.PreparedRegistry, spec grantSpec) (string, error) {
	if spec.Request == nil {
		return "", errNeedsSignedRequest
	}
	shown, err := authorisation.WhatSigningRegisters(p.IxnRaw, p.VcpRaw)
	if err != nil {
		return "", err
	}
	return s.queueForTheKey(signingKindRegistry, pendingIssuance{Kind: signingKindRegistry, Spec: spec, Registry: p}, p.IxnRaw, summaryOf(shown))
}

func (s *CoreServer) queueForTheKey(kind string, pending pendingIssuance, payload []byte, summary string) (string, error) {
	if len(s.unsignedOwnEvents()) > 0 {
		return "", errUnsignedKeyLog
	}
	s.withdrawWaitingFor(pending.Spec.Holder)
	// The same thing is never asked of the device twice: what is already
	// waiting or kept behind for it stands.
	for _, row := range s.waitingRows() {
		if !sameSubject(row.Pending, pending) {
			continue
		}
		if row.Pending.Kind == waitingBehind || s.stillAsked(row) {
			return "", fmt.Errorf("%w (%s)", errAlreadyAsked, row.ID)
		}
	}
	// One interaction waits for the device at a time: each extends the
	// identity's key log at its tip, and two built on one tip would ask the
	// device for two events at one place. Another is kept behind it and built
	// once it lands.
	if s.anInteractionWaits() {
		behind := pendingIssuance{Kind: waitingBehind, Spec: pending.Spec}
		body, err := json.Marshal(behind)
		if err != nil {
			return "", err
		}
		id := fmt.Sprintf("%s-%020d", waitingBehind, time.Now().UnixNano())
		return id, s.DataStore.SavePendingIssuance(id, string(body))
	}
	body, err := json.Marshal(pending)
	if err != nil {
		return "", err
	}
	id, err := s.EnqueueSigningRequest(pending.Spec.Issuer, kind, summary,
		"Your key is on this device, so this waits for it here. What is shown is read from the credential itself.",
		payload, PresentationConsent)
	if err != nil {
		return "", err
	}
	if err := s.DataStore.SavePendingIssuance(id, string(body)); err != nil {
		return "", err
	}
	return id, nil
}

// summaryOf is the one line shown, made from what the credential says.
func summaryOf(t *authorisation.ToSign) string {
	if t.Revokes {
		return fmt.Sprintf("Withdraw the grant to %q, signed earlier and not wanted", t.Name)
	}
	switch t.Kind {
	case "machine":
		return fmt.Sprintf("Let the machine %q (key %s) act for you", t.Name, t.KeyFingerprint)
	case "ai_agent":
		what := "nothing"
		if len(t.Capabilities) > 0 {
			what = strings.Join(t.Capabilities, ", ")
		}
		return fmt.Sprintf("Let the AI agent %q do: %s", t.Name, what)
	default:
		return "Make the registry this identity issues its grants into"
	}
}

// waitingRow is one row of what waits for the device that holds the key.
type waitingRow struct {
	ID      string
	Pending pendingIssuance
}

func (s *CoreServer) waitingRows() []waitingRow {
	rows, err := s.DataStore.ListPendingIssuances()
	if err != nil {
		return nil
	}
	var out []waitingRow
	for id, body := range rows {
		var p pendingIssuance
		if json.Unmarshal([]byte(body), &p) == nil {
			out = append(out, waitingRow{ID: id, Pending: p})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// withdrawWaitingFor withdraws whatever waits for the device that holds the
// key on behalf of holder, and the request asking it to sign.
func (s *CoreServer) withdrawWaitingFor(holder string) {
	if holder == "" {
		return
	}
	for _, row := range s.waitingRows() {
		if row.Pending.Spec.Holder != holder || row.Pending.Closed != "" {
			continue
		}
		if row.Pending.interaction() == nil {
			_ = s.DataStore.DeletePendingIssuance(row.ID)
		} else {
			// Kept: the device may have signed it already, and if it has its
			// key log is this identity's, and is taken up here.
			row.Pending.Closed = "withdrawn"
			if body, err := json.Marshal(row.Pending); err == nil {
				_ = s.DataStore.SavePendingIssuance(row.ID, string(body))
			}
		}
		if req, err := s.DataStore.GetSigningRequest(row.ID); err == nil && req != nil && req.Status == SigningStatusPending {
			req.Status = SigningStatusRefused
			req.ResolvedAt = time.Now().UTC().Format(time.RFC3339)
			_ = s.DataStore.SaveSigningRequest(*req)
		}
		log.Printf("[grants] the grant waiting for %s was withdrawn", holder)
	}
}

// errGrantSignature is a signature for a waiting grant that does not hold.
var errGrantSignature = errors.New("the signature does not hold for the identity's current key")

// fulfilLocks holds one lock per signing request, so two signatures for one
// request are not both acted on.
var fulfilLocks sync.Map

func lockFulfil(id string) func() {
	m, _ := fulfilLocks.LoadOrStore(id, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// completeWaiting acts on the signature the device that holds the key made
// over a waiting grant's, or registry's, interaction.
func (s *CoreServer) completeWaiting(req store.SigningRequest, signature string) error {
	unlock := lockFulfil(req.ID)
	defer unlock()
	body, ok, err := s.DataStore.GetPendingIssuance(req.ID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("nothing waits for this signature")
	}
	var pending pendingIssuance
	if err := json.Unmarshal([]byte(body), &pending); err != nil {
		return err
	}
	if pending.Spec.Request == nil && pending.Kind != signingKindRevocation {
		return errNeedsSignedRequest
	}
	// The signature is over the request's own payload, which is the
	// interaction kept: neither can have been swapped for the other's.
	payload, err := base64.StdEncoding.DecodeString(req.PayloadB64)
	if err != nil {
		return err
	}
	var kept []byte
	switch {
	case pending.Kind == signingKindGrant && pending.Prepared != nil:
		kept = pending.Prepared.IxnRaw
	case pending.Kind == signingKindRegistry && pending.Registry != nil:
		kept = pending.Registry.IxnRaw
	case pending.Kind == signingKindRevocation && pending.Revocation != nil:
		kept = pending.Revocation.IxnRaw
	default:
		return fmt.Errorf("what waits is of no kind this agent completes")
	}
	if req.Kind != pending.Kind || string(payload) != string(kept) {
		return fmt.Errorf("the request asks to sign something other than what waits")
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil || identity.AID != pending.Spec.Issuer {
		return fmt.Errorf("what waits is not this identity's")
	}
	pub, err := login.DecodeVerkey(identity.PublicKey)
	if err != nil {
		return err
	}
	if ok, err := login.VerifyString(string(payload), signature, pub); err != nil || !ok {
		return errGrantSignature
	}
	if pending.Kind == signingKindRegistry {
		return s.completeRegistry(req.ID, pending, signature)
	}
	if pending.Kind == signingKindRevocation {
		return s.completeRevocation(req.ID, pending, signature)
	}
	return s.completeGrant(req.ID, pending, signature)
}

// sameAsBuilt derives what the kept grant says from its own bytes and
// compares it with what it was built from.
func sameAsBuilt(pending pendingIssuance) (*authorisation.ToSign, error) {
	p := pending.Prepared
	shown, err := authorisation.WhatSigningGrants(p.IxnRaw, p.IssRaw, p.AcdcRaw)
	if err != nil {
		return nil, err
	}
	var acdc struct {
		S string                 `json:"s"`
		A map[string]interface{} `json:"a"`
	}
	if err := json.Unmarshal(p.AcdcRaw, &acdc); err != nil {
		return nil, err
	}
	if acdc.S != pending.Spec.Schema || shown.Holder != pending.Spec.Holder || shown.Issuer != pending.Spec.Issuer {
		return nil, fmt.Errorf("the grant kept is not the one built")
	}
	for k, want := range pending.Spec.Claims {
		if !sameJSONValue(acdc.A[k], want) {
			return nil, fmt.Errorf("the grant kept says other than it was built to (%s)", k)
		}
	}
	return shown, nil
}

func sameJSONValue(a, b interface{}) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// stillWhatItGrants checks that the machine or AI agent a waiting grant is
// for is still there, is still what the grant says, and has not been granted
// anything meanwhile.
func (s *CoreServer) stillWhatItGrants(kind *schemas.AssetGrant, shown *authorisation.ToSign) error {
	switch kind {
	case schemas.ControllerGrant:
		g, had, err := s.controllers().Get(shown.Holder)
		if err != nil || !had {
			return fmt.Errorf("the machine has been removed")
		}
		if live, why := g.Live(time.Now()); !live {
			return fmt.Errorf("the machine's authorisation no longer stands: %s", why)
		}
		if g.CredentialSAID != "" {
			return fmt.Errorf("the machine has been granted meanwhile")
		}
		if strings.TrimSpace(g.PublicKey) != shown.PublicKey || strings.TrimSpace(g.Label) != shown.Name ||
			string(g.Grade) != shown.Grade || g.Signer != shown.Signer || !sameMoment(shown.ValidUntil, g.ExpiresAt) {
			return fmt.Errorf("the machine is no longer what the grant says")
		}
	default:
		// Any other kind is an add-on's. Where no add-on here issues it, what
		// it is for is not here either, and it is refused as one whose holder
		// was removed is.
		g, ok := grantKind(kind)
		if !ok || g.StillWhatItGrants == nil {
			return fmt.Errorf("nothing here issues a grant of this kind, so what it is for is not here")
		}
		return g.StillWhatItGrants(s, shown)
	}
	return nil
}

func (s *CoreServer) completeGrant(requestID string, pending pendingIssuance, signature string) error {
	kind := grantKindNamed(pending.Spec.Schema)
	if kind == nil {
		return fmt.Errorf("the waiting grant is of no kind this agent issues")
	}
	// Signed by the device that holds the key, it is in that device's key log
	// already, so it is taken up here whatever has changed since it was
	// asked for: in force if it still stands, otherwise withdrawn.
	err := s.adoptGrant(waitingRow{ID: requestID, Pending: pending}, signature)
	if errors.Is(err, drivers.ErrStalePreparation) {
		// Built on a key log that has moved on: built again and asked afresh.
		preparer, _ := s.KeriDriver.(drivers.PreparedIssuer)
		_ = s.DataStore.DeletePendingIssuance(requestID)
		fresh, perr := preparer.PrepareCredentialInRegistry(pending.Spec.Issuer, pending.Spec.Claims, pending.Spec.Schema,
			pending.Spec.Holder, pending.Spec.Edges, pending.Prepared.Registry)
		if perr == nil {
			if _, perr = s.awaitSignature(kind, fresh, pending.Spec); perr == nil {
				return fmt.Errorf("%w; it has been built again and asked for afresh", err)
			}
		}
		return fmt.Errorf("%w, and it could not be built again: %v", err, perr)
	}
	if err != nil {
		if errors.Is(err, errSignedNotWanted) {
			s.witnessOwnLog()
		}
		return fmt.Errorf("the grant was not issued: %w", err)
	}
	s.witnessOwnLog()
	s.buildNextBehind()
	return nil
}

func (s *CoreServer) completeRegistry(requestID string, pending pendingIssuance, signature string) error {
	if _, err := authorisation.WhatSigningRegisters(pending.Registry.IxnRaw, pending.Registry.VcpRaw); err != nil {
		return err
	}
	preparer, can := s.KeriDriver.(drivers.PreparedIssuer)
	if !can {
		return fmt.Errorf("this engine cannot append a prepared registry")
	}
	s.engineKeepsCredentialLogs()
	ixnB64 := base64.StdEncoding.EncodeToString(pending.Registry.IxnRaw)
	s.signedElsewhere.Store(ixnB64, signature)
	defer s.signedElsewhere.Delete(ixnB64)
	if _, err := preparer.AppendPreparedRegistry(pending.Spec.Issuer, pending.Registry); err != nil {
		if errors.Is(err, drivers.ErrStalePreparation) {
			// Built on a key log that has moved on: built again and asked
			// afresh, as a grant is, unless a registry has been made since.
			_ = s.DataStore.DeletePendingIssuance(requestID)
			if reg, rerr := s.DataStore.GetRegistryByIssuer(pending.Spec.Issuer); rerr == nil && reg != nil && reg.VcpRawB64 != "" {
				return fmt.Errorf("%w; a registry has been made since", err)
			}
			fresh, perr := preparer.PrepareRegistryInception(pending.Spec.Issuer)
			if perr == nil {
				if _, perr = s.awaitRegistry(fresh, pending.Spec); perr == nil {
					return fmt.Errorf("%w; it has been built again and asked for afresh", err)
				}
			}
			return fmt.Errorf("%w, and it could not be built again: %v", err, perr)
		}
		return fmt.Errorf("the registry could not be appended: %w", err)
	}
	_ = s.DataStore.DeletePendingIssuance(requestID)
	s.witnessOwnLog()
	// The grant that waited behind it, built now on the registry and asked
	// for in its turn.
	kind := grantKindNamed(pending.Spec.Schema)
	if kind == nil {
		return nil
	}
	claims := map[string]interface{}{}
	for k, v := range pending.Spec.Claims {
		claims[k] = v
	}
	if _, err := s.issueAssetCredential(kind, pending.Spec.Holder, pending.Spec.Issuer, claims, pending.Spec.Expiry, pending.Spec.by()); err != nil && !errors.Is(err, errKeyElsewhere) {
		return fmt.Errorf("the registry was made, and the grant waiting behind it could not be built: %w", err)
	}
	s.buildNextBehind()
	return nil
}

// grantArrived stops a machine or AI agent waiting for its grant.
func (s *CoreServer) grantArrived(kind *schemas.AssetGrant, spec grantSpec, said string) {
	switch kind {
	case schemas.ControllerGrant:
		s.grantsMu.Lock()
		defer s.grantsMu.Unlock()
		g, had, err := s.controllers().Get(spec.Holder)
		if err != nil || !had {
			log.Printf("[grants] machine %s was granted %s and is no longer paired", spec.Holder, said)
			return
		}
		g.CredentialSAID, g.CredentialPending = said, false
		if err := s.controllers().Put(g); err != nil {
			log.Printf("[grants] machine %s was granted %s and could not be marked so: %v", spec.Holder, said, err)
		}
	default:
		if g, ok := grantKind(kind); ok && g.Arrived != nil {
			g.Arrived(s, spec.Holder, said)
		}
	}
}

// waitingStateOf says what has become of what waits for holder on the device
// that holds the key: waiting, refused or expired; "" when nothing does.
func (s *CoreServer) waitingStateOf(holder string) string {
	for _, row := range s.waitingRows() {
		if row.Pending.Spec.Holder != holder || row.Pending.Closed != "" {
			continue
		}
		req, err := s.DataStore.GetSigningRequest(row.ID)
		if err != nil || req == nil {
			continue
		}
		if req.Status == SigningStatusPending && req.ExpiresAt != "" {
			if exp, err := time.Parse(time.RFC3339, req.ExpiresAt); err == nil && exp.Before(time.Now()) {
				return SigningStatusExpired
			}
		}
		return req.Status
	}
	return ""
}

// queuedParts are the parts of a waiting grant the device that holds the key
// checks before it signs: the credential and its issuance event, or the
// registry's inception.
func (s *CoreServer) queuedParts(id string) map[string]string {
	body, ok, err := s.DataStore.GetPendingIssuance(id)
	if err != nil || !ok {
		return nil
	}
	var p pendingIssuance
	if json.Unmarshal([]byte(body), &p) != nil {
		return nil
	}
	switch {
	case p.Prepared != nil:
		return map[string]string{
			"credential_b64": base64.StdEncoding.EncodeToString(p.Prepared.AcdcRaw),
			"issuance_b64":   base64.StdEncoding.EncodeToString(p.Prepared.IssRaw),
		}
	case p.Registry != nil:
		return map[string]string{"registry_b64": base64.StdEncoding.EncodeToString(p.Registry.VcpRaw)}
	case p.Revocation != nil:
		return map[string]string{
			"credential_b64": base64.StdEncoding.EncodeToString(p.RevokedAcdc),
			"revocation_b64": base64.StdEncoding.EncodeToString(p.Revocation.RevRaw),
		}
	}
	return nil
}

// anInteractionWaits reports whether an interaction is waiting for the device
// that holds the key: one whose request is still open.
func (s *CoreServer) anInteractionWaits() bool {
	for _, row := range s.waitingRows() {
		if row.Pending.Kind == waitingBehind {
			continue
		}
		if req, err := s.DataStore.GetSigningRequest(row.ID); err == nil && req != nil && req.Status == SigningStatusPending {
			if req.ExpiresAt != "" {
				if exp, err := time.Parse(time.RFC3339, req.ExpiresAt); err == nil && exp.Before(time.Now()) {
					continue
				}
			}
			return true
		}
	}
	return false
}

// buildNextBehind builds the grant kept longest behind the interaction that
// was waiting, now that none is, and asks for it.
func (s *CoreServer) buildNextBehind() {
	if s.anInteractionWaits() {
		return
	}
	// A grant to be withdrawn goes first: until it is, the key log holds a
	// grant this Identity Agent does not stand behind.
	for _, row := range s.waitingRows() {
		if row.Pending.Kind != waitingBehind || row.Pending.Revokes == "" {
			continue
		}
		_ = s.DataStore.DeletePendingIssuance(row.ID)
		if err := s.queueRevocation(row.Pending.Revokes); err != nil {
			log.Printf("[grants] the withdrawal of %s could not be asked for: %v", row.Pending.Revokes, err)
			continue
		}
		return
	}
	for _, row := range s.waitingRows() { // in the order they were kept
		if row.Pending.Kind != waitingBehind || row.Pending.Revokes != "" {
			continue
		}
		_ = s.DataStore.DeletePendingIssuance(row.ID)
		kind := grantKindNamed(row.Pending.Spec.Schema)
		if kind == nil {
			continue
		}
		claims := map[string]interface{}{}
		for k, v := range row.Pending.Spec.Claims {
			claims[k] = v
		}
		if _, err := s.issueAssetCredential(kind, row.Pending.Spec.Holder, row.Pending.Spec.Issuer, claims,
			row.Pending.Spec.Expiry, row.Pending.Spec.by()); err != nil && !errors.Is(err, errKeyElsewhere) {
			log.Printf("[grants] the grant kept for %s could not be built: %v", row.Pending.Spec.Holder, err)
			continue
		}
		return
	}
}

// sameSubject reports whether two things kept for the device are about the
// same thing: the withdrawal of one credential, or a grant to one holder.
func sameSubject(a, b pendingIssuance) bool {
	if a.Kind == withdrawalRefusedKind || b.Kind == withdrawalRefusedKind {
		return false
	}
	if a.Revokes != "" || b.Revokes != "" {
		return a.Revokes == b.Revokes
	}
	return a.Spec.Holder != "" && a.Spec.Holder == b.Spec.Holder
}
