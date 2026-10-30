package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/authorisation"
	"identity-agent-core/schemas"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// Whoever authorised a credential is named in it.
//
// An AI agent's grant and the credential that makes a machine its body carry
// the request that authorised them, exactly as it was signed, with its body,
// and what it named as the thing it acts on. A request a machine made for a
// signer also carries an edge to that machine's Controller Grant, which names
// the signer and is anchored in the identity's key log. authorisation.Check is
// the rule anybody applies to them later; this Identity Agent applies it to
// each one it issues, and withdraws one that fails.
//
// What this shows, and what it does not. The Controller Grant is issued by
// this Identity Agent, on the word of the device that paired the machine; an
// Identity Agent run by someone who controls it could issue one to a key of
// its own. What cannot be made up afterwards is the machine's own signature
// over the request: it shows that the holder of that machine key asked for
// exactly this, at that time, under a grant the identity's key log shows was
// issued and not yet revoked.
//
// A request made with the identity's own key carries that signature instead.
// One made on the device that holds the key, with no signature, carries none:
// the issuer is the authority, and authorisation.Check says so rather than
// reporting it checked.

// authority is who authorised a credential.
type authority struct {
	// ControllerGrant is the Controller Grant of the machine the request came
	// from. Empty for an owner-signed request, and for a machine whose grant
	// is waiting for the device that holds the identity's key.
	ControllerGrant string
	// Request is the request as it was signed. Nil when the identity's own
	// device asked without signing.
	Request *signedRequest
	// About is what the request named as the thing it acts on.
	About string
}

// signedRequest is a request exactly as it was signed, with its body.
type signedRequest struct {
	Kind      string `json:"kind"`
	Signer    string `json:"signer"`
	Signed    string `json:"signed"`
	Signature string `json:"signature"`
	Body      string `json:"body"`
}

// authorityOf is who authorised r, read before the handler reads the body.
// For a machine's request it also holds the machine's grant against being
// revoked, re-issued or replaced until release is called, so a credential is
// never issued on a grant withdrawn while it was being issued.
func (s *CoreServer) authorityOf(r *http.Request) (authority, func(), error) {
	release := func() {}
	body, err := readSignedBody(r)
	if err != nil {
		return authority{}, release, err
	}
	if grant, ok := TheControllerThatAsked(r); ok {
		s.grantsMu.RLock()
		release = s.grantsMu.RUnlock
		current, had, err := s.controllers().Get(grant.ControllerAID)
		switch {
		case err != nil:
			release()
			return authority{}, func() {}, err
		case !had:
			release()
			return authority{}, func() {}, fmt.Errorf("this machine's grant has been removed")
		}
		// A mark that the grant waits for another device is believed only
		// where the key really is elsewhere.
		if current.CredentialSAID == "" && (!current.CredentialPending || !s.keyIsElsewhere()) {
			release()
			return authority{}, func() {}, fmt.Errorf("this machine was paired before machines were given grants, and needs the owner's approval before what it asks for can rest on it")
		}
		if current.CredentialSAID != "" {
			if err := s.grantStillStands(current.CredentialSAID); err != nil {
				release()
				return authority{}, func() {}, err
			}
			if err := s.rowIsItsGrant(current); err != nil {
				release()
				return authority{}, func() {}, err
			}
		}
		signed, sig, err := s.theRequestAsSigned(r, grant)
		if err != nil {
			release()
			return authority{}, func() {}, err
		}
		return authority{
			ControllerGrant: current.CredentialSAID,
			Request:         &signedRequest{Kind: "controller", Signer: grant.ControllerAID, Signed: signed, Signature: sig, Body: string(body)},
		}, release, nil
	}
	// Admitted by the identity's own key, the request kept as it was signed.
	if sig := strings.TrimSpace(r.Header.Get(headerOwnerSig)); sig != "" {
		owner := ""
		if oa, err := s.ownerAuthority(); err == nil && oa != nil {
			owner = oa.AID
		}
		stamp := strings.TrimSpace(r.Header.Get(headerOwnerTimestamp))
		return authority{Request: &signedRequest{
			Kind: "owner", Signer: owner, Signature: sig, Body: string(body),
			Signed: canonicalOwnerRequest(strings.TrimSpace(r.Header.Get(headerOwnerFor)),
				r.Method, r.URL.Path, stamp, body),
		}}, release, nil
	}
	return authority{}, release, nil
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

// grantStillStands refuses a Controller Grant that has been revoked.
func (s *CoreServer) grantStillStands(said string) error {
	rec, err := s.DataStore.GetCredential(said)
	if err != nil || rec == nil {
		return fmt.Errorf("this machine's grant is not on record")
	}
	if rec.Status != "issued" {
		return fmt.Errorf("this machine's grant has been withdrawn")
	}
	_, status, err := s.credentialLog(rec.RegistrySAID, said)
	if err != nil || status != keri.StatusIssued {
		return fmt.Errorf("this machine's grant is not in force in the registry")
	}
	return nil
}

// name writes the authority into a credential about to be issued: an edge to
// the Controller Grant, and the signed request and what it named among its
// attributes. A schema that admits neither is left as it is.
func (a authority) name(kind *schemas.AssetGrant, claims map[string]interface{}) map[string]interface{} {
	if !kind.HasEdges() {
		return nil
	}
	if a.About != "" {
		claims["about"] = a.About
	}
	if a.Request != nil {
		// What was asked for, not the body: the credential is public, and a
		// body can carry a system prompt, a model's address or a stored key's
		// name. The body is kept with this Identity Agent's record.
		asked, err := authorisation.Asked(a.Request.Body)
		if err != nil {
			asked = map[string]json.RawMessage{}
		}
		claims["request"] = map[string]interface{}{
			"kind": a.Request.Kind, "signer": a.Request.Signer, "signed": a.Request.Signed,
			"signature": a.Request.Signature, "asked": asked,
		}
	}
	if a.ControllerGrant == "" {
		return nil
	}
	return map[string]interface{}{
		"authorised_by": map[string]interface{}{"n": a.ControllerGrant, "s": schemas.ControllerGrant.Schema.SAID},
	}
}

// checkAuthorisation applies authorisation.Check to a credential just issued.
func (s *CoreServer) checkAuthorisation(said string, by authority) error {
	if by.Request == nil {
		return nil
	}
	rec, err := s.DataStore.GetCredential(said)
	if err != nil || rec == nil {
		return fmt.Errorf("the credential is not on record")
	}
	acdc, err := base64.StdEncoding.DecodeString(rec.AcdcJson)
	if err != nil {
		return err
	}
	return s.checkAuthorisationOf(acdc, rec.IssuerAID, rec.RegistrySAID, said, by)
}

// checkAuthorisationOf checks a credential against the request it carries.
// Given where it was issued (registry and said), the order of issue and
// revocation is read from where each is anchored in the issuer's key log;
// without them, for a credential built and not yet appended, from the times
// the grant's log states.
func (s *CoreServer) checkAuthorisationOf(acdc []byte, issuer, registry, said string, by authority) error {
	if by.Request == nil {
		return nil
	}
	in := authorisation.Input{Credential: acdc, Body: by.Request.Body, HaveBody: true}
	if said != "" {
		// The issuer's key log and this credential's own log, so the order of
		// issue and revocation is read from where each is anchored.
		if events, err := s.DataStore.GetEvents(issuer); err == nil {
			for _, ev := range events {
				if raw, err := base64.StdEncoding.DecodeString(ev.RawBytesB64); err == nil && len(raw) > 0 {
					in.IssuerKEL = append(in.IssuerKEL, raw)
				}
			}
		}
		if own, _, err := s.credentialLog(registry, said); err == nil {
			for _, ev := range own {
				raw, _ := base64.StdEncoding.DecodeString(ev)
				in.CredentialLog = append(in.CredentialLog, raw)
			}
		}
	}
	switch by.Request.Kind {
	case "controller":
		if by.ControllerGrant == "" {
			return nil // waiting for the device that holds the key; nothing to name
		}
		grant, err := s.DataStore.GetCredential(by.ControllerGrant)
		if err != nil || grant == nil {
			return fmt.Errorf("the machine's grant is not on record")
		}
		if in.Grant, err = base64.StdEncoding.DecodeString(grant.AcdcJson); err != nil {
			return err
		}
		events, _, err := s.credentialLog(grant.RegistrySAID, grant.SAID)
		if err != nil {
			return err
		}
		for _, ev := range events {
			raw, _ := base64.StdEncoding.DecodeString(ev)
			in.GrantLog = append(in.GrantLog, raw)
		}
	case "owner":
		oa, err := s.ownerAuthority()
		if err != nil || oa == nil {
			return fmt.Errorf("the identity's owner is not known")
		}
		in.OwnerKey = oa.PublicKey
	}
	// Asked for by a signed request, the credential must carry it: one that
	// carries none rests on nothing that asked for it.
	if err := authorisation.Check(in); err != nil {
		if errors.Is(err, authorisation.ErrNoRequest) {
			return fmt.Errorf("the credential does not carry the request that asked for it")
		}
		return err
	}
	return nil
}

// issuedUnderFirstVersionTooLate reports whether rec is an AI agent grant or
// body credential issued under the first version of the template after this
// Identity Agent began issuing the version that names who authorised it. Such a
// credential could only have been issued to avoid naming anybody, and is not
// honoured. One issued before is.
func (s *CoreServer) issuedUnderFirstVersionTooLate(rec *store.CredentialRecord) bool {
	if rec == nil || (rec.SchemaSAID != schemas.AIAgentGrantV1.Schema.SAID && rec.SchemaSAID != schemas.AIAgentBodyV1.Schema.SAID) {
		return false
	}
	since, ok := s.firstEdgedIssuance()
	if !ok {
		return false
	}
	return issuedAt(*rec).After(since)
}

// firstEdgedIssuance is when this Identity Agent first issued an AI agent
// grant or body credential under the version that names who authorised it.
// Found once and remembered: it never moves.
func (s *CoreServer) firstEdgedIssuance() (time.Time, bool) {
	if t, ok := s.edgesSince.Load().(time.Time); ok {
		return t, true
	}
	creds, err := s.DataStore.GetCredentials()
	if err != nil {
		return time.Time{}, false
	}
	var first time.Time
	for _, c := range creds {
		if c.SchemaSAID != schemas.AIAgentGrant.Schema.SAID && c.SchemaSAID != schemas.AIAgentBody.Schema.SAID {
			continue
		}
		if t := issuedAt(c); !t.IsZero() && (first.IsZero() || t.Before(first)) {
			first = t
		}
	}
	if first.IsZero() {
		return time.Time{}, false
	}
	s.edgesSince.Store(first)
	return first, true
}

// errKeyElsewhere is an identity whose key this Identity Agent does not hold.
var errKeyElsewhere = errors.New("the identity's key is held on another device")

// grantController records that a machine may act for this identity, with its
// Controller Grant anchored in the identity's key log. The grant becomes
// visible only once its credential is issued, so nothing the machine asks for
// meanwhile can be issued without an edge. A grant it replaces has its
// credential withdrawn; if that cannot be done the new credential is withdrawn
// instead and nothing changes, so a machine never has two grants in force.
//
// Where the identity's key is held on another device, the grant is recorded
// with its credential pending on that device, and nothing is written into the
// key log here.
func (s *CoreServer) grantController(g ControllerGrant, now time.Time, by authority) (ControllerGrant, error) {
	s.grantsMu.Lock()
	defer s.grantsMu.Unlock()
	checked, err := s.controllers().Check(g, now)
	if err != nil {
		return ControllerGrant{}, err
	}
	// The signer a machine speaks as is one of this identity's active
	// signers, whether the owner named it or it was settled for them.
	if checked.Signer != "" && !s.isActiveSigner(checked.Signer) {
		return ControllerGrant{}, fmt.Errorf("%s is not an active signer of this identity", checked.Signer)
	}
	before, had, err := s.controllers().Get(checked.ControllerAID)
	if err != nil {
		return ControllerGrant{}, err
	}
	// A machine already granted, re-granted where the key is on another
	// device: its current grant stops being in force here now, and its
	// withdrawal is asked of that device ahead of the new grant, which waits
	// behind it.
	if had && before.CredentialSAID != "" {
		switch err := s.keyCanSign(); {
		case errors.Is(err, errKeyElsewhere):
			rec, gerr := s.DataStore.GetCredential(before.CredentialSAID)
			if gerr != nil || rec == nil {
				return ControllerGrant{}, fmt.Errorf("this machine's current grant %s is not on record", before.CredentialSAID)
			}
			if _, _, werr := s.withdrawCredential(rec); werr != nil {
				return ControllerGrant{}, fmt.Errorf("this machine's current grant could not be withdrawn: %w", werr)
			}
			before.CredentialSAID = ""
		case err != nil:
			return ControllerGrant{}, err
		}
	}
	by.About = checked.ControllerAID
	said, err := s.issueControllerGrant(checked, by)
	if errors.Is(err, errKeyElsewhere) {
		checked.CredentialPending = true
		if err := s.controllers().Put(checked); err != nil {
			return ControllerGrant{}, err
		}
		return checked, nil
	}
	if err != nil {
		return ControllerGrant{}, fmt.Errorf("the machine's grant could not be anchored, so it was not granted: %w", err)
	}
	if had && before.CredentialSAID != "" && before.CredentialSAID != said {
		if err := s.withdrawControllerGrant(before.CredentialSAID); err != nil {
			s.withdrawOrSay(said)
			return ControllerGrant{}, fmt.Errorf("the machine's earlier grant could not be withdrawn, so it was not re-granted: %w", err)
		}
	}
	checked.CredentialSAID = said
	if err := s.controllers().Put(checked); err != nil {
		s.withdrawOrSay(said)
		return ControllerGrant{}, err
	}
	return checked, nil
}

// issueControllerGrant issues the credential for a grant.
func (s *CoreServer) issueControllerGrant(g ControllerGrant, by authority) (string, error) {
	if s.DataStore == nil || s.KeriDriver == nil {
		return "", fmt.Errorf("this Identity Agent has no key log to anchor the grant in")
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return "", fmt.Errorf("this Identity Agent has no identity to grant for")
	}
	// Issuing writes an interaction into the identity's key log, which only
	// the holder of its key may sign: where that is another device, the grant
	// is built here and waits for it (issueAssetCredential).
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
	return s.issueAssetCredential(schemas.ControllerGrant, g.ControllerAID, identity.AID, claims, expiry, by)
}

// revokeController takes a machine's authorisation away, and withdraws its
// Controller Grant. The machine stops at once whatever happens to the
// withdrawal: someone removing a stolen laptop must never be told to wait for
// a key log.
func (s *CoreServer) revokeController(aid string) error {
	// A grant waiting for the device that holds the key is withdrawn with
	// the machine, so signing it later grants nothing.
	defer s.withdrawWaitingFor(aid)
	s.grantsMu.Lock()
	defer s.grantsMu.Unlock()
	g, had, err := s.controllers().Get(aid)
	if err != nil {
		return err
	}
	if err := s.controllers().Revoke(aid); err != nil {
		return err
	}
	if had && g.CredentialSAID != "" {
		s.withdrawOrSay(g.CredentialSAID)
	}
	return nil
}

// bindSigner records which signer a machine acts as, re-issuing its Controller
// Grant to say so. The new credential is issued and the old one withdrawn
// before anything is recorded; if either fails nothing changes and the next
// attempt starts again.
func (s *CoreServer) bindSigner(aid, signer string) (ControllerGrant, error) {
	s.grantsMu.Lock()
	defer s.grantsMu.Unlock()
	g, had, err := s.controllers().Get(aid)
	if err != nil {
		return ControllerGrant{}, err
	}
	if !had {
		return ControllerGrant{}, fmt.Errorf("no such machine")
	}
	if g.Signer != "" {
		return g, nil
	}
	bound := g
	bound.Signer = signer
	if g.CredentialSAID != "" {
		if err := s.keyCanSign(); err != nil {
			return g, fmt.Errorf("%w, and this machine's grant could not be re-issued to name its signer", err)
		}
	}
	if g.CredentialSAID != "" {
		// Re-issued from what the grant says, never from a row changed since.
		if err := s.rowIsItsGrant(g); err != nil {
			return g, err
		}
		said, err := s.issueControllerGrant(bound, authority{About: bound.ControllerAID})
		if err != nil {
			return g, fmt.Errorf("the machine's grant could not be re-issued to name its signer: %w", err)
		}
		if err := s.withdrawControllerGrant(g.CredentialSAID); err != nil {
			s.withdrawOrSay(said)
			return g, fmt.Errorf("the machine's grant could not be withdrawn to name its signer: %w", err)
		}
		bound.CredentialSAID = said
	}
	if err := s.controllers().Put(bound); err != nil {
		if bound.CredentialSAID != g.CredentialSAID {
			s.withdrawOrSay(bound.CredentialSAID)
		}
		return g, err
	}
	return bound, nil
}

// withdrawControllerGrant revokes a Controller Grant credential in the
// registry and marks it revoked.
func (s *CoreServer) withdrawControllerGrant(said string) error {
	rec, err := s.DataStore.GetCredential(said)
	if err != nil || rec == nil {
		return fmt.Errorf("grant credential %s is not on record", said)
	}
	_, _, err = s.withdrawCredential(rec)
	return err
}

// withdrawOrSay withdraws a Controller Grant credential, saying so when it
// cannot, and marks it unusable here whatever the registry says.
func (s *CoreServer) withdrawOrSay(said string) {
	if err := s.withdrawControllerGrant(said); err != nil {
		log.Printf("[controller] grant credential %s: its revocation was not recorded in the registry: %v", said, err)
		// Not in force here either way; where the key is on another device it
		// stays withdrawing, which says so, rather than reading as revoked.
		if rec, _ := s.DataStore.GetCredential(said); rec == nil || rec.Status != credentialStatusWithdrawing {
			_ = s.DataStore.UpdateCredentialStatus(said, "revoked")
		}
	}
}

// rowIsItsGrant checks a machine's row against the grant credential it holds:
// the same machine, key, label and grade. The row is a file; the grant is what
// the identity signed, and a row that no longer says what was granted is not
// acted on or re-issued from.
func (s *CoreServer) rowIsItsGrant(g ControllerGrant) error {
	rec, err := s.DataStore.GetCredential(g.CredentialSAID)
	if err != nil || rec == nil {
		return fmt.Errorf("this machine's grant is not on record")
	}
	raw, err := base64.StdEncoding.DecodeString(rec.AcdcJson)
	if err != nil {
		return fmt.Errorf("this machine's grant is unreadable")
	}
	var acdc struct {
		A map[string]interface{} `json:"a"`
	}
	if json.Unmarshal(raw, &acdc) != nil || acdc.A == nil {
		return fmt.Errorf("this machine's grant is unreadable")
	}
	str := func(k string) string { v, _ := acdc.A[k].(string); return strings.TrimSpace(v) }
	if str("i") != g.ControllerAID || str("public_key") != strings.TrimSpace(g.PublicKey) ||
		str("grade") != string(g.Grade) || str("label") != strings.TrimSpace(g.Label) || str("signer") != g.Signer {
		return fmt.Errorf("this machine's record no longer says what its grant does")
	}
	if !sameMoment(str("valid_until"), g.ExpiresAt) {
		return fmt.Errorf("this machine's record no longer says when its grant ends")
	}
	return nil
}

// Machines paired, and AI agents provisioned, before every one of them was
// given a grant have none, and are never given one from what a file says:
// each waits for the owner's approval, given the ordinary way. A machine is
// approved by granting it again (POST /api/controllers), an AI agent by
// setting its capabilities (PUT /api/mcp/agents/{id}/capabilities); each
// carries the owner's request into the grant, and the grant is checked
// against it like any other.
//
// handleGrantsAwaitingApproval lists them, so an app can ask the owner.
func (s *CoreServer) handleGrantsAwaitingApproval(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	keyHere := !s.keyIsElsewhere()
	machines := []map[string]any{}
	if all, err := s.controllers().All(); err == nil {
		for _, g := range all {
			if g.CredentialSAID != "" {
				continue
			}
			if live, _ := g.Live(now); !live {
				continue
			}
			m := onTheWire(g, now)
			// A mark that the grant waits for another device is believed only
			// where the key really is elsewhere.
			m["awaiting"] = s.awaitingFor(g.ControllerAID, g.CredentialPending && !keyHere)
			machines = append(machines, m)
		}
	}
	// What waits for a grant an add-on issues, under its key. AI agents are
	// always listed, as none where no add-on here makes them.
	out := map[string]any{"machines": machines, "agents": []map[string]any{}}
	for _, a := range registeredAddons() {
		for _, g := range a.GrantKinds {
			if g.Awaiting != nil && g.AwaitingKey != "" {
				out[g.AwaitingKey] = g.Awaiting(s)
			}
		}
	}
	for k, v := range s.keyLogReport() {
		out[k] = v
	}
	writeJSON(w, out)
}

// awaitingWhat says what a grant is waiting for: the owner's approval, or,
// once approved where the key is elsewhere, the device that holds it.
func awaitingWhat(pending bool) string {
	if pending {
		return "the device that holds the identity's key"
	}
	return "the owner's approval"
}

// awaitingFor is what holder's grant waits for, saying so when the device
// that holds the key refused it, or it waited too long, so the owner asks
// again.
func (s *CoreServer) awaitingFor(holder string, pending bool) string {
	if !pending {
		return awaitingWhat(false)
	}
	switch s.waitingStateOf(holder) {
	case SigningStatusRefused:
		return "the device that holds the identity's key refused it: ask again"
	case SigningStatusExpired:
		return "the device that holds the identity's key did not sign it in time and it expired: ask again"
	}
	return awaitingWhat(true)
}

// awaitingPhrase is the same, as it is said of an AI agent.
func awaitingPhrase(pending bool) string {
	if pending {
		return "waiting for its grant to be signed on the device that holds the identity's key"
	}
	return "awaiting the owner's approval"
}

// sameMoment reports whether a grant's stated end and a record's are the same
// time, both absent counting as the same.
func sameMoment(stated string, at time.Time) bool {
	if stated == "" || at.IsZero() {
		return stated == "" && at.IsZero()
	}
	t, err := time.Parse(time.RFC3339, stated)
	return err == nil && t.Equal(at)
}

// isActiveSigner reports whether aid is one of this identity's active signers.
func (s *CoreServer) isActiveSigner(aid string) bool {
	for _, p := range s.signers() {
		if p.AID == aid {
			return true
		}
	}
	return false
}

func nonNilConstraints(c map[string]interface{}) map[string]interface{} {
	if c == nil {
		return map[string]interface{}{}
	}
	return c
}

// signers are the people who sign for the organisation: every active signer
// on its roster, and its owner. The owner counts whether or not founding put
// them on the roster, because the organisation's own key log names them, which
// is the strongest proof of a person it has. Their standing says which, so the
// record shows what the proof is.
func (s *CoreServer) signers() []signerRef {
	var out []signerRef
	seen := map[string]bool{}
	if s.assetHandler != nil {
		for _, e := range s.assetHandler.Store.ListEmployees() {
			if e.IsSigner && e.Status == "active" {
				out = append(out, signerRef{AID: e.PairwiseAID, Standing: "signer", Credential: e.VouchSig, Name: e.Name})
				seen[e.PairwiseAID] = true
			}
		}
	}
	if owner, ok := s.theOwner(); ok && !seen[owner] {
		out = append(out, signerRef{AID: owner, Standing: "owner", Name: "The owner"})
	}
	return out
}

// onlyActiveSigner is the organisation's signer when it has exactly one, and
// empty otherwise.
func (s *CoreServer) onlyActiveSigner() string {
	if signers := s.signers(); len(signers) == 1 {
		return signers[0].AID
	}
	return ""
}

// signerRef is one of the people who sign for this identity, and how it knows
// them: "owner" (named in its own key log) or "signer". Credential is the
// signature with which they founded the organisation.
type signerRef struct {
	AID        string
	Standing   string
	Credential string
	Name       string
}

// theOwner is the person this organisation answers to: the owner its own
// inception event names, or, with no such anchor, the one sealed when it was
// provisioned. Never the organisation itself, which is what ownerAuthority
// falls back to when nobody was named.
func (s *CoreServer) theOwner() (string, bool) {
	oa, err := s.ownerAuthority()
	if err != nil || oa == nil || oa.AID == "" {
		return "", false
	}
	if s.DataStore != nil {
		if id, _ := s.DataStore.GetIdentity(); id != nil && id.AID == oa.AID {
			return "", false
		}
	}
	return oa.AID, true
}
