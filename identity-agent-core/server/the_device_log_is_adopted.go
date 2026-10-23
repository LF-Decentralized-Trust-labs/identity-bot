package server

// An Identity Agent where the identity's key is on another device takes up
// what that device signed.
//
// The device's key log is the identity's, since it holds the key. Whatever it
// has signed at the next place of the key log here is taken up here, whether
// the request for it is still waiting, was refused or expired here, or was
// withdrawn because its machine was removed: verified against the identity's
// current key and appended, so the two key logs never diverge. It is found in
// the device's reply, in what the device answers when asked to sign at a
// place it has already filled, or at the identity's witnesses; it is looked
// for before every grant is built here, and on every tick.
//
// A grant taken up that is no longer wanted here (its machine removed, its
// request withdrawn) is kept, so the registry's log is whole, is never in
// force, and is withdrawn at once by a revocation the device is asked to sign
// on the same queue, ahead of anything else.
//
// Signing is never split into a "prepare" and a "commit" on the device, which
// would reopen the window in which it signs two events at one place.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"identity-agent-core/authorisation"
	"identity-agent-core/drivers"
	"identity-agent-core/login"
	"identity-agent-core/schemas"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// adoptMu makes taking up what the device signed one pass at a time.
var adoptMu sync.Mutex

// adoptWhatTheDeviceSigned takes up, in order, every event the device that
// holds the key has signed beyond the key log here, offered first. It returns
// how many it took up.
func (s *CoreServer) adoptWhatTheDeviceSigned(offered *heldEvent) (int, error) {
	if s.DataStore == nil || !s.keyIsElsewhere() {
		return 0, nil
	}
	n, err := s.adoptInOrder(offered)
	if n > 0 {
		s.witnessOwnLog()
		s.buildNextBehind()
	}
	return n, err
}

func (s *CoreServer) adoptInOrder(offered *heldEvent) (int, error) {
	adoptMu.Lock()
	defer adoptMu.Unlock()
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return 0, fmt.Errorf("no identity")
	}
	pub, err := login.DecodeVerkey(identity.PublicKey)
	if err != nil {
		return 0, err
	}
	n := 0
	for n < 256 {
		tipSN, tipSAID, err := s.ownTip(identity.AID)
		if err != nil {
			return n, err
		}
		var candidates []heldEvent
		if offered != nil {
			candidates = append(candidates, *offered)
		}
		candidates = append(candidates, s.signedEventsAt(identity.AID, tipSN+1)...)
		raw, held := extensionOf(candidates, identity.AID, tipSN+1, tipSAID, pub)
		if raw == nil {
			break
		}
		if err := s.adoptOne(identity.AID, raw, held); err != nil && !errors.Is(err, errSignedNotWanted) {
			return n, fmt.Errorf("the event the device signed at place %d could not be taken up: %w", tipSN+1, err)
		}
		log.Printf("[grants] took up event %d of %s, signed on the device that holds the key", tipSN+1, identity.AID)
		n++
	}
	if n > 0 {
		s.settleAfterAdoption()
	}
	return n, nil
}

// ownTip is the place and identifier of the newest event of the key log here.
func (s *CoreServer) ownTip(aid string) (int, string, error) {
	events, err := s.DataStore.GetEvents(aid)
	if err != nil || len(events) == 0 {
		return 0, "", fmt.Errorf("no key log for %s", aid)
	}
	last := events[len(events)-1]
	var body struct {
		D string `json:"d"`
	}
	_ = json.Unmarshal([]byte(last.EventJSON), &body)
	return last.SequenceNumber, body.D, nil
}

// signedEventsAt asks where the device's signed events can be found for the
// one at sn: the identity's witnesses.
func (s *CoreServer) signedEventsAt(aid string, sn int) []heldEvent {
	if s.fetchSignedEvent != nil {
		return s.fetchSignedEvent(aid, sn)
	}
	keeper, ok := s.KeriDriver.(drivers.KELKeeper)
	if !ok || s.WitnessService == nil {
		return nil
	}
	witnesses, _, err := keeper.WitnessConfig(aid)
	if err != nil || len(witnesses) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var out []heldEvent
	for _, ev := range s.WitnessService.EventsHeldAt(ctx, aid, sn, witnesses) {
		out = append(out, heldEvent{RawB64: ev.RawBytesB64, Signature: ev.CesrSignature})
	}
	return out
}

// extensionOf picks, among candidates, the interaction that extends the key
// log here at sn after prior, signed by the identity's current key.
func extensionOf(candidates []heldEvent, aid string, sn int, prior string, pub ed25519.PublicKey) ([]byte, heldEvent) {
	for _, c := range candidates {
		raw, err := base64.StdEncoding.DecodeString(c.RawB64)
		if err != nil || len(raw) == 0 || keri.ValidateEvent(raw) != nil {
			continue
		}
		ev, err := keri.ParseEvent(raw)
		if err != nil || ev.Ilk != "ixn" || ev.Identifier != aid || int(ev.SN) != sn || ev.PriorSAID != prior {
			continue
		}
		if ok, err := login.VerifyString(string(raw), c.Signature, pub); err != nil || !ok {
			continue
		}
		return raw, c
	}
	return nil, heldEvent{}
}

// rowAsking finds what waits, or waited, here for the device to sign raw.
func (s *CoreServer) rowAsking(raw []byte) (waitingRow, bool) {
	for _, row := range s.waitingRows() {
		if ixn := row.Pending.interaction(); ixn != nil && bytes.Equal(ixn, raw) {
			return row, true
		}
	}
	return waitingRow{}, false
}

// stillAsked reports whether the request for a row is still open here.
func (s *CoreServer) stillAsked(row waitingRow) bool {
	if row.Pending.Closed != "" {
		return false
	}
	req, err := s.DataStore.GetSigningRequest(row.ID)
	if err != nil || req == nil || req.Status != SigningStatusPending {
		return false
	}
	if req.ExpiresAt != "" {
		if exp, err := time.Parse(time.RFC3339, req.ExpiresAt); err == nil && exp.Before(time.Now()) {
			return false
		}
	}
	return true
}

// closeExpired marks a request still open in the store, and past its time,
// expired: what it asked for has been taken up without it.
func (s *CoreServer) closeExpired(id string) {
	if req, err := s.DataStore.GetSigningRequest(id); err == nil && req != nil && req.Status == SigningStatusPending {
		req.Status = SigningStatusExpired
		req.ResolvedAt = time.Now().UTC().Format(time.RFC3339)
		_ = s.DataStore.SaveSigningRequest(*req)
	}
}

func (s *CoreServer) markSigned(id string) {
	if req, err := s.DataStore.GetSigningRequest(id); err == nil && req != nil {
		req.Status = SigningStatusSigned
		req.ResolvedAt = time.Now().UTC().Format(time.RFC3339)
		_ = s.DataStore.SaveSigningRequest(*req)
	}
}

func (s *CoreServer) adoptOne(aid string, raw []byte, held heldEvent) error {
	if row, ok := s.rowAsking(raw); ok {
		switch {
		case row.Pending.Prepared != nil:
			return s.adoptGrant(row, held.Signature)
		case row.Pending.Registry != nil:
			return s.adoptRegistry(row, held.Signature)
		case row.Pending.Revocation != nil:
			return s.adoptRevocation(row.ID, row.Pending.Revocation, held.Signature)
		}
	}
	return s.adoptFromParts(aid, raw, held)
}

// withSignature runs append with the device's signature over raw to hand.
func (s *CoreServer) withSignature(raw []byte, signature string, appendIt func() error) error {
	s.engineKeepsCredentialLogs()
	key := base64.StdEncoding.EncodeToString(raw)
	s.signedElsewhere.Store(key, signature)
	defer s.signedElsewhere.Delete(key)
	return appendIt()
}

// adoptGrant takes up a grant the device signed. Where it is still asked for
// here and still what it grants, it is in force as if the reply had come;
// otherwise it is kept, never in force, and withdrawn.
func (s *CoreServer) adoptGrant(row waitingRow, signature string) error {
	p := row.Pending
	preparer, ok := s.KeriDriver.(drivers.PreparedIssuer)
	if !ok {
		return fmt.Errorf("this engine cannot append a prepared grant")
	}
	var result *drivers.DriverIssueCredentialResponse
	if err := s.withSignature(p.Prepared.IxnRaw, signature, func() (err error) {
		result, err = preparer.AppendPreparedIssuance(p.Spec.Issuer, p.Prepared)
		return err
	}); err != nil {
		return err
	}
	asked := s.stillAsked(row)
	_ = s.DataStore.DeletePendingIssuance(row.ID)
	if asked {
		// Answered: signed, whether or not it is in force here.
		s.markSigned(row.ID)
	} else {
		s.closeExpired(row.ID)
	}
	kind := grantKindNamed(p.Spec.Schema)
	why := fmt.Errorf("it was no longer asked for here")
	if asked && kind != nil {
		shown, err := sameAsBuilt(p)
		if err == nil {
			err = s.stillWhatItGrants(kind, shown)
		}
		if err == nil {
			err = s.checkAuthorisationOf(p.Prepared.AcdcRaw, p.Spec.Issuer, "", "", p.Spec.by())
		}
		if err == nil {
			said, ferr := s.finishIssuance(kind, result, p.Spec.Holder, p.Spec.Issuer, p.Spec.Expiry,
				p.Prepared.Registry, p.Spec.RequestDigest, p.Spec.by())
			if ferr == nil {
				s.grantArrived(kind, p.Spec, said)
				return nil
			}
			err = ferr
		}
		why = err
		log.Printf("[grants] the grant the device signed for %s is not in force here, and is withdrawn: %v", p.Spec.Holder, err)
	}
	if err := s.keepAndWithdraw(p.Spec.Schema, p.Spec.Holder, p.Spec.Issuer, p.Prepared.Registry, result); err != nil {
		return err
	}
	return fmt.Errorf("%w: %v", errSignedNotWanted, why)
}

// errSignedNotWanted is a grant the device signed that is taken up here, never
// in force, and withdrawn.
var errSignedNotWanted = errors.New("the grant was signed, is not in force here, and its withdrawal has been asked for")

// keepAndWithdraw keeps a grant the device signed that is not wanted here,
// marked so it is never in force, and asks the device to withdraw it.
func (s *CoreServer) keepAndWithdraw(schema, holder, issuer, registry string, result *drivers.DriverIssueCredentialResponse) error {
	name := schema
	if kind := grantKindNamed(schema); kind != nil {
		name = kind.Schema.Name
	}
	if err := s.DataStore.SaveCredential(store.CredentialRecord{
		SAID:           result.AcdcSaid,
		IssuerAID:      issuer,
		HolderAID:      holder,
		SchemaSAID:     schema,
		AcdcJson:       result.AcdcJsonB64,
		IxnSAID:        result.IxnSaid,
		IssuedAt:       time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
		Status:         credentialStatusWithdrawing,
		Format:         "acdc",
		CredentialType: name,
		RegistrySAID:   registry,
		IssSAID:        result.IssSaid,
	}); err != nil {
		return err
	}
	return s.queueRevocation(result.AcdcSaid)
}

// credentialStatusWithdrawing is a grant in the key log that is not wanted
// here and waits for the device to sign its revocation: never in force.
const credentialStatusWithdrawing = "withdrawing"

// adoptRegistry takes up a registry inception the device signed, and builds
// the grant that waited behind it if that is still asked for.
func (s *CoreServer) adoptRegistry(row waitingRow, signature string) error {
	p := row.Pending
	preparer, ok := s.KeriDriver.(drivers.PreparedIssuer)
	if !ok {
		return fmt.Errorf("this engine cannot append a prepared registry")
	}
	if err := s.withSignature(p.Registry.IxnRaw, signature, func() error {
		_, err := preparer.AppendPreparedRegistry(p.Spec.Issuer, p.Registry)
		return err
	}); err != nil {
		return err
	}
	asked := s.stillAsked(row)
	_ = s.DataStore.DeletePendingIssuance(row.ID)
	if !asked {
		s.closeExpired(row.ID)
	}
	if asked {
		s.markSigned(row.ID)
		if grantKindNamed(p.Spec.Schema) != nil {
			return s.keepBehind(pendingIssuance{Kind: waitingBehind, Spec: p.Spec})
		}
	}
	return nil
}

// adoptRevocation takes up a revocation the device signed.
func (s *CoreServer) adoptRevocation(id string, p *drivers.PreparedRevocation, signature string) error {
	revoker, ok := s.KeriDriver.(drivers.PreparedRevoker)
	if !ok {
		return fmt.Errorf("this engine cannot append a prepared revocation")
	}
	if err := s.withSignature(p.IxnRaw, signature, func() error {
		_, err := revoker.AppendPreparedRevocation(p.Issuer, p)
		return err
	}); err != nil {
		return err
	}
	_ = s.DataStore.UpdateCredentialStatus(p.AcdcSAID, "revoked")
	if id != "" {
		_ = s.DataStore.DeletePendingIssuance(id)
		s.markSigned(id)
	}
	return nil
}

// adoptFromParts takes up an event this Identity Agent no longer holds the
// parts of, from the parts the device kept with it; failing those, the
// interaction alone, reported as anchoring what is not held here.
func (s *CoreServer) adoptFromParts(aid string, raw []byte, held heldEvent) error {
	dec := func(k string) []byte { b, _ := base64.StdEncoding.DecodeString(held.Parts[k]); return b }
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return err
	}
	switch {
	case held.Parts["revocation_b64"] != "":
		shown, err := authorisation.WhatSigningRevokes(raw, dec("revocation_b64"), dec("credential_b64"))
		if err != nil {
			return err
		}
		rev, err := keri.VerifyTELEvent(dec("revocation_b64"))
		if err != nil {
			return err
		}
		return s.adoptRevocation("", &drivers.PreparedRevocation{Issuer: aid, Registry: shown.Registry, AcdcSAID: shown.Credential,
			IssSAID: rev.Prior, RevRaw: dec("revocation_b64"), RevSAID: rev.SAID, IxnRaw: raw, IxnSAID: ev.SAID, SN: int(ev.SN), Prior: ev.PriorSAID}, held.Signature)
	case held.Parts["registry_b64"] != "":
		shown, err := authorisation.WhatSigningRegisters(raw, dec("registry_b64"))
		if err != nil {
			return err
		}
		vcp, err := keri.VerifyTELEvent(dec("registry_b64"))
		if err != nil {
			return err
		}
		preparer, ok := s.KeriDriver.(drivers.PreparedIssuer)
		if !ok {
			return fmt.Errorf("this engine cannot append a prepared registry")
		}
		p := &drivers.PreparedRegistry{Issuer: aid, Registry: shown.Registry, VcpRaw: dec("registry_b64"), VcpSAID: vcp.SAID,
			IxnRaw: raw, IxnSAID: ev.SAID, SN: int(ev.SN), Prior: ev.PriorSAID}
		return s.withSignature(raw, held.Signature, func() error {
			_, err := preparer.AppendPreparedRegistry(aid, p)
			return err
		})
	case held.Parts["credential_b64"] != "" && held.Parts["issuance_b64"] != "":
		shown, err := authorisation.WhatSigningGrants(raw, dec("issuance_b64"), dec("credential_b64"))
		if err != nil {
			return err
		}
		iss, err := keri.VerifyTELEvent(dec("issuance_b64"))
		if err != nil {
			return err
		}
		preparer, ok := s.KeriDriver.(drivers.PreparedIssuer)
		if !ok {
			return fmt.Errorf("this engine cannot append a prepared grant")
		}
		p := &drivers.PreparedIssuance{Issuer: aid, Registry: shown.Registry, AcdcRaw: dec("credential_b64"), AcdcSAID: shown.Credential,
			IssRaw: dec("issuance_b64"), IssSAID: iss.SAID, IxnRaw: raw, IxnSAID: ev.SAID, SN: int(ev.SN), Prior: ev.PriorSAID}
		var result *drivers.DriverIssueCredentialResponse
		if err := s.withSignature(raw, held.Signature, func() (err error) {
			result, err = preparer.AppendPreparedIssuance(aid, p)
			return err
		}); err != nil {
			return err
		}
		schema := schemas.ControllerGrant.Schema.SAID
		if shown.Kind == "ai_agent" {
			schema = schemas.AIAgentGrant.Schema.SAID
		}
		return s.keepAndWithdraw(schema, shown.Holder, aid, shown.Registry, result)
	}
	return s.adoptBare(aid, raw, held.Signature)
}

// adoptBare takes up an interaction alone, when what it anchors is not to be
// had: the key log stays the device's, and what it anchors is reported.
func (s *CoreServer) adoptBare(aid string, raw []byte, signature string) error {
	keeper, ok := s.KeriDriver.(drivers.KELKeeper)
	if !ok {
		return fmt.Errorf("this engine cannot keep its key log")
	}
	var body struct {
		D string            `json:"d"`
		A []json.RawMessage `json:"a"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return err
	}
	data := make([]interface{}, 0, len(body.A))
	for _, a := range body.A {
		data = append(data, a)
	}
	keep := func(k drivers.KELKeep) error {
		if !bytes.Equal(k.Raw, raw) {
			return fmt.Errorf("the interaction built here is not the one the device signed")
		}
		var parsed map[string]interface{}
		if err := json.Unmarshal(k.Raw, &parsed); err != nil {
			return err
		}
		rec, err := s.ownInteractionRecord(aid, parsed, base64.StdEncoding.EncodeToString(k.Raw), k.SN, signature)
		if err != nil {
			return err
		}
		return s.DataStore.SaveEvent(rec)
	}
	if _, err := keeper.InteractKept(aid, data, keep); err != nil {
		return err
	}
	s.noteAnchoredNotHeld(body.D)
	return nil
}

const anchoredNotHeldFile = "anchored_not_held.json"

// noteAnchoredNotHeld records an interaction taken up whose anchored event
// this Identity Agent could not obtain.
func (s *CoreServer) noteAnchoredNotHeld(said string) {
	list := s.anchoredNotHeld()
	list = append(list, said)
	if b, err := json.Marshal(list); err == nil {
		_ = os.WriteFile(filepath.Join(s.DataDir, anchoredNotHeldFile), b, 0o600)
	}
	log.Printf("[grants] took up %s, signed on the device that holds the key; what it anchors is not held here", said)
}

func (s *CoreServer) anchoredNotHeld() []string {
	var list []string
	if b, err := os.ReadFile(filepath.Join(s.DataDir, anchoredNotHeldFile)); err == nil {
		_ = json.Unmarshal(b, &list)
	}
	return list
}

// settleAfterAdoption deals with every interaction that waited at a place the
// key log has now moved past: one still asked for is built again behind what
// waits; one no longer asked for is dropped.
func (s *CoreServer) settleAfterAdoption() {
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return
	}
	tip, _, err := s.ownTip(identity.AID)
	if err != nil {
		return
	}
	for _, row := range s.waitingRows() {
		place := placeOf(row.Pending)
		if place < 0 || place > tip {
			continue
		}
		asked := s.stillAsked(row)
		_ = s.DataStore.DeletePendingIssuance(row.ID)
		if !asked {
			s.closeExpired(row.ID)
			continue
		}
		if req, err := s.DataStore.GetSigningRequest(row.ID); err == nil && req != nil {
			req.Status = SigningStatusRefused
			req.ResolvedAt = time.Now().UTC().Format(time.RFC3339)
			_ = s.DataStore.SaveSigningRequest(*req)
		}
		behind := pendingIssuance{Kind: waitingBehind, Spec: row.Pending.Spec, Revokes: row.Pending.Revokes}
		if err := s.keepBehind(behind); err != nil {
			log.Printf("[grants] %s could not be kept to build again: %v", row.ID, err)
		}
	}
}

func placeOf(p pendingIssuance) int {
	switch {
	case p.Prepared != nil:
		return p.Prepared.SN
	case p.Registry != nil:
		return p.Registry.SN
	case p.Revocation != nil:
		return p.Revocation.SN
	}
	return -1
}

// keepBehind keeps something to build once nothing waits for the device.
func (s *CoreServer) keepBehind(p pendingIssuance) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return s.DataStore.SavePendingIssuance(fmt.Sprintf("%s-%020d", waitingBehind, time.Now().UnixNano()), string(body))
}

// queueRevocation asks the device that holds the key to withdraw a grant, or
// keeps it to ask once nothing else waits.
func (s *CoreServer) queueRevocation(said string) error {
	rec, err := s.DataStore.GetCredential(said)
	if err != nil || rec == nil {
		return fmt.Errorf("no credential %s to withdraw", said)
	}
	if s.anInteractionWaits() {
		return s.keepBehind(pendingIssuance{Kind: waitingBehind, Spec: grantSpec{Issuer: rec.IssuerAID}, Revokes: said})
	}
	revoker, ok := s.KeriDriver.(drivers.PreparedRevoker)
	if !ok {
		return fmt.Errorf("this engine cannot prepare a revocation")
	}
	p, err := revoker.PrepareRevocation(rec.IssuerAID, said, rec.RegistrySAID)
	if err != nil {
		return err
	}
	acdc, err := base64.StdEncoding.DecodeString(rec.AcdcJson)
	if err != nil {
		return err
	}
	shown, err := authorisation.WhatSigningRevokes(p.IxnRaw, p.RevRaw, acdc)
	if err != nil {
		return err
	}
	_, err = s.queueForTheKey(signingKindRevocation, pendingIssuance{Kind: signingKindRevocation, Spec: grantSpec{Issuer: rec.IssuerAID},
		Revocation: p, Revokes: said, RevokedAcdc: acdc}, p.IxnRaw, summaryOf(shown))
	return err
}

// completeRevocation acts on the signature the device made over a grant's
// revocation.
func (s *CoreServer) completeRevocation(requestID string, pending pendingIssuance, signature string) error {
	err := s.adoptRevocation(requestID, pending.Revocation, signature)
	if errors.Is(err, drivers.ErrStalePreparation) {
		_ = s.DataStore.DeletePendingIssuance(requestID)
		if qerr := s.queueRevocation(pending.Revokes); qerr != nil {
			return fmt.Errorf("%w, and it could not be built again: %v", err, qerr)
		}
		return fmt.Errorf("%w; it has been built again and asked for afresh", err)
	}
	if err != nil {
		return err
	}
	s.witnessOwnLog()
	s.buildNextBehind()
	return nil
}

// unsignedOwnEvents are the places of events in the key log here that carry
// no signature: written by an earlier version where the key is now on
// another device, which never held them, so it cannot extend this key log.
func (s *CoreServer) unsignedOwnEvents() []int {
	if s.DataStore == nil {
		return nil
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return nil
	}
	events, err := s.DataStore.GetEvents(identity.AID)
	if err != nil {
		return nil
	}
	var out []int
	for _, ev := range events {
		if ev.CesrSignature == "" && ev.SequenceNumber > 0 {
			out = append(out, ev.SequenceNumber)
		}
	}
	return out
}

// errUnsignedKeyLog is a key log here holding events the device that holds
// the key never signed: nothing can be asked of that device until they are
// discarded or signed.
var errUnsignedKeyLog = errors.New("this Identity Agent's key log holds events written by an earlier version without the identity's key, which the device that holds the key never had; nothing can be signed there until they are discarded or signed")

// handleAdoptSigned takes up an event the device that holds the key signed,
// as it answered when asked to sign at a place it had already filled.
func (s *CoreServer) handleAdoptSigned(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		writeError(w, http.StatusForbidden, "owner only", "only this agent's owner hands it what its key signed")
		return
	}
	var held heldEvent
	if err := json.NewDecoder(r.Body).Decode(&held); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body", err.Error())
		return
	}
	n, err := s.adoptWhatTheDeviceSigned(&held)
	if err != nil {
		writeError(w, http.StatusConflict, "not taken up", err.Error())
		return
	}
	if n == 0 {
		writeError(w, http.StatusUnprocessableEntity, "not taken up",
			"it does not extend this key log, or is not signed by the identity's current key")
		return
	}
	writeJSON(w, map[string]int{"adopted": n})
}

// keyLogReport says, where the key is on another device, what stands in the
// way of that device extending the key log here, or what the key log here
// anchors that is not held here.
func (s *CoreServer) keyLogReport() map[string]any {
	out := map[string]any{}
	if !s.keyIsElsewhere() {
		return out
	}
	if unsigned := s.unsignedOwnEvents(); len(unsigned) > 0 {
		out["key_log_unsigned_events"] = unsigned
		out["key_log_detail"] = fmt.Sprintf("%d event(s) of this identity's key log here (places %v) were written by an earlier "+
			"version without the identity's key, and the device that holds the key never had them. Nothing can be signed "+
			"there until they are discarded or signed.", len(unsigned), unsigned)
	}
	if notHeld := s.anchoredNotHeld(); len(notHeld) > 0 {
		out["key_log_anchors_not_held"] = notHeld
	}
	return out
}
