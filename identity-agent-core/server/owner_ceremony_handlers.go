package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/iacrypto"

	"github.com/go-chi/chi/v5"
)

func (s *CoreServer) mountOwnerCeremonyRoutes(r chi.Router) {
	if s.assetHandler == nil {
		return
	}
	r.Route("/owners", func(r chi.Router) {
		r.Get("/", s.handleListOwners)
		r.Get("/ceremony", s.handleGetCeremony)
		r.Post("/ceremony", s.handleStartCeremony)
		r.Delete("/ceremony", s.handleAbandonCeremony)
	})
}

// handleListOwners reports who owns this organisation, read from its own log.
func (s *CoreServer) handleListOwners(w http.ResponseWriter, r *http.Request) {
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		writeError(w, http.StatusConflict, "No identity", "this agent has no identity yet")
		return
	}
	owners, err := s.ownersOfOwnIdentity(identity.AID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not read the owners", err.Error())
		return
	}
	writeJSONResponse(w, map[string]interface{}{
		"aid":    identity.AID,
		"owners": owners,
	})
}

func (s *CoreServer) handleGetCeremony(w http.ResponseWriter, r *http.Request) {
	ceremonyMu.Lock()
	c, err := s.loadCeremony()
	ceremonyMu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not read the ceremony", err.Error())
		return
	}
	if c == nil {
		writeJSONResponse(w, map[string]interface{}{"ceremony": nil})
		return
	}
	writeJSONResponse(w, map[string]interface{}{
		"ceremony":    c,
		"outstanding": c.Outstanding(),
	})
}

// handleStartCeremony begins bringing new owners in.
//
// It mints one invite per person, each carrying the same signed offer the
// founding-signer flow already uses — so what the organisation renders is the
// QR code that machinery already produces, and an incoming owner's agent
// follows a path it already knows how to walk.
func (s *CoreServer) handleStartCeremony(w http.ResponseWriter, r *http.Request) {
	var req struct {
		// Invite names the people being brought in. Names are for the person
		// running the ceremony to tell one QR code from another; nothing
		// cryptographic depends on them.
		Invite []string `json:"invite"`
		// Threshold is how many owners must sign afterwards. Omitted means
		// everybody, which is the safe reading of an unstated intention.
		Threshold int `json:"threshold"`
		// The organisation's own rotation keys, from the device that holds its
		// seed. Required, because a rotation must carry a key the previous event
		// committed to — the organisation cannot be rotated by anybody who
		// cannot produce it.
		OrgPublicKey     string `json:"org_public_key"`
		OrgNextPublicKey string `json:"org_next_public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Bad request", err.Error())
		return
	}

	var names []string
	for _, n := range req.Invite {
		if strings.TrimSpace(n) != "" {
			names = append(names, strings.TrimSpace(n))
		}
	}
	if len(names) == 0 {
		writeError(w, http.StatusBadRequest, "Nobody to invite",
			"name at least one person to bring in as an owner")
		return
	}

	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		writeError(w, http.StatusConflict, "No identity",
			"an organisation must exist before its ownership can change")
		return
	}
	existing, err := s.ownersOfOwnIdentity(identity.AID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not read the current owners", err.Error())
		return
	}
	if len(existing) == 0 {
		// An identity with no owner anchored at inception can never acquire
		// one — that is the rule the whole ownership design rests on, and a
		// ceremony that appeared to work here would be promising the
		// impossible.
		writeError(w, http.StatusConflict, "This identity has no owners",
			"only an organisation founded with an owner can change who owns it")
		return
	}

	total := len(existing) + len(names)
	threshold := req.Threshold
	if threshold <= 0 {
		threshold = total
	}
	if threshold > total {
		writeError(w, http.StatusBadRequest, "Impossible threshold",
			fmt.Sprintf("%d signatures cannot be required of %d owners", threshold, total))
		return
	}

	ceremonyMu.Lock()
	defer ceremonyMu.Unlock()

	if current, lerr := s.loadCeremony(); lerr == nil && current != nil && current.Status == ceremonyCollecting {
		// One at a time. Two overlapping ceremonies would each rotate from a key
		// set the other had already replaced, and the second would fail at the
		// end — after everybody had signed.
		writeError(w, http.StatusConflict, "A ceremony is already under way",
			fmt.Sprintf("still waiting on: %s. Abandon it first if it is stale.",
				strings.Join(current.Outstanding(), ", ")))
		return
	}

	// The organisation's own rotation keys. Supplied by the caller when the seed
	// lives on their device; derived here when it lives on this one, which is
	// the case for an organisation running on hardware it does not own.
	//
	// Derived rather than remembered: only the DIGEST of the committed key is in
	// the log, so the key itself has to be produced again from the index the
	// identity recorded. Verified against that digest before anybody is invited,
	// because discovering the derivation is wrong after collecting everybody's
	// signatures would waste the one thing a ceremony spends — people's time and
	// their willingness to do it again.
	orgPublic, orgNext := req.OrgPublicKey, req.OrgNextPublicKey
	if orgPublic == "" || orgNext == "" {
		keys, kerr := s.ownRotationKeys()
		if kerr != nil {
			writeError(w, http.StatusConflict, "This organisation cannot rotate its own key", kerr.Error())
			return
		}
		orgPublic, orgNext = keys.Current, keys.Next
	}

	c := &OwnerCeremony{
		ID:               genInviteToken(),
		Threshold:        threshold,
		OrgPublicKey:     orgPublic,
		OrgNextPublicKey: orgNext,
		Status:           ceremonyCollecting,
		StartedAt:        time.Now().UTC(),
	}
	for _, name := range names {
		token, url, ierr := s.mintOwnerInvite(r, name)
		if ierr != nil {
			writeError(w, http.StatusInternalServerError, "Could not mint an invite", ierr.Error())
			return
		}
		c.Invited = append(c.Invited, CeremonyInvitee{Name: name, Token: token, InviteURL: url})
	}
	if err := s.saveCeremony(c); err != nil {
		writeError(w, http.StatusInternalServerError, "Could not record the ceremony", err.Error())
		return
	}

	writeJSONResponse(w, map[string]interface{}{
		"ceremony": c,
		"note": "each invited owner scans their own code. Nothing changes until " +
			"every one of them has, and no key material leaves their device.",
	})
}

// handleAbandonCeremony throws away a ceremony that is not going to complete.
//
// Kept rather than deleted, so somebody who accepted an invitation into a
// ceremony that was later dropped can be shown what happened rather than left
// wondering why nothing changed.
func (s *CoreServer) handleAbandonCeremony(w http.ResponseWriter, r *http.Request) {
	ceremonyMu.Lock()
	defer ceremonyMu.Unlock()

	c, err := s.loadCeremony()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not read the ceremony", err.Error())
		return
	}
	if c == nil || c.Status != ceremonyCollecting {
		writeError(w, http.StatusConflict, "Nothing to abandon", "no ceremony is under way")
		return
	}
	c.Status = ceremonyAbandoned
	c.Detail = "abandoned by the organisation before it completed"
	if err := s.saveCeremony(c); err != nil {
		writeError(w, http.StatusInternalServerError, "Could not record it", err.Error())
		return
	}
	writeJSONResponse(w, map[string]interface{}{"status": ceremonyAbandoned})
}

// mintOwnerInvite produces one invite and the URL that becomes its QR code.
//
// Deliberately the same machinery the founding-signer invite uses: the same
// invite record, the same signed offer, the same /i/{token} resolution. An
// incoming owner's agent already knows how to walk that path, and a second
// parallel invite format would be one more thing to keep in step.
func (s *CoreServer) mintOwnerInvite(r *http.Request, name string) (token, url string, err error) {
	publicURL := s.EndpointService.CurrentURL()
	if publicURL == "" {
		publicURL = s.getPublicURL(r)
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return "", "", fmt.Errorf("this agent has no identity")
	}
	orgAID := identity.AID
	orgOOBI := fmt.Sprintf("%s/public/oobi/%s", publicURL, orgAID)

	orgName := ""
	if prof, _ := s.DataStore.GetProfile(); prof != nil {
		orgName = prof.OrgName
		if orgName == "" {
			orgName = prof.FullName
		}
	}

	inv := asset.EmployeeInvite{
		Token: genInviteToken(), Role: "Owner", IsSigner: true,
		MaxUses: 1, SiteAID: orgAID, SiteOOBI: orgOOBI,
	}
	if err := s.assetHandler.Store.CreateEmployeeInvite(inv); err != nil {
		return "", "", err
	}

	askToken, err := s.mintSignerAsk(orgName, orgAID, orgOOBI, inv.Token)
	if err != nil {
		return "", "", err
	}
	return inv.Token, fmt.Sprintf("%s/i/%s", publicURL, askToken), nil
}

// completeCeremonyIfReady rotates the organisation once everybody has accepted.
//
// Called from the redemption path, so the last person to scan their code is the
// one whose acceptance completes it. Nobody has to remember to come back and
// press a button, and there is no window in which every owner has agreed and
// the organisation has not changed.
func (s *CoreServer) completeCeremonyIfReady(c *OwnerCeremony) {
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		_ = s.finishCeremony(ceremonyFailed, "this agent has no identity to rotate", "")
		return
	}
	if s.KeriDriver == nil {
		_ = s.finishCeremony(ceremonyFailed, "no KERI engine to rotate with", "")
		return
	}

	existing, err := s.ownersOfOwnIdentity(identity.AID)
	if err != nil {
		_ = s.finishCeremony(ceremonyFailed, "could not read the current owners: "+err.Error(), "")
		return
	}

	// The owner seals: everyone who owned it before, plus everyone who just
	// accepted. Written in the same event as the keys, which is the only way the
	// two cannot disagree about who owns this.
	seals := make([]interface{}, 0, len(existing)+len(c.Invited))
	for _, aid := range existing {
		seals = append(seals, ownerAnchorSeal(aid))
	}
	// The keys the identity will be controlled by afterwards.
	//
	// The organisation's own PRE-ROTATED key leads, because a rotation has to
	// carry a key the previous event committed to — without it no verifier would
	// accept the event, whatever else it said. The incoming owners' keys join
	// it, which is what a verifier does accept: the prior commitment is
	// satisfied and new keys ride along. Checked against a real Kevery rather
	// than assumed.
	keys := []string{c.OrgPublicKey}
	nextKeys := []string{c.OrgNextPublicKey}
	for _, invitee := range c.Invited {
		seals = append(seals, ownerAnchorSeal(invitee.PairwiseAID))
		keys = append(keys, invitee.PublicKey)
		nextKeys = append(nextKeys, invitee.NextPublicKey)
	}

	// Committed as digests of the SUCCESSOR keys, each supplied by the owner it
	// belongs to. Committing digests of the current set instead would pre-commit
	// to keys already in use, which defeats the point of pre-rotation entirely.
	nextDigests, err := digestsOf(nextKeys)
	if err != nil {
		_ = s.finishCeremony(ceremonyFailed, "could not commit next keys: "+err.Error(), "")
		return
	}

	resp, err := s.KeriDriver.RotateToMultisig(identity.AID, keys, nextDigests,
		fmt.Sprintf("%d", c.Threshold), fmt.Sprintf("%d", c.Threshold), seals)
	if err != nil {
		_ = s.finishCeremony(ceremonyFailed, "the rotation failed: "+err.Error(), "")
		return
	}
	// Recorded only now that the rotation was accepted. Advancing first and
	// failing would leave the identity believing it had moved on while its log
	// said otherwise, and every later rotation would derive a key its own events
	// do not commit to.
	if aerr := s.advanceKeyGeneration(resp.NewPublicKey, resp.NewNextKeyDigest); aerr != nil {
		_ = s.finishCeremony(ceremonyFailed,
			"the ownership changed but this agent could not record where its keys moved to, "+
				"so it will not be able to rotate again: "+aerr.Error(), resp.Said)
		return
	}
	_ = s.finishCeremony(ceremonyApplied, "", resp.Said)
}

// digestsOf turns a set of next public keys into the digests a rotation commits
// to.
//
// Blake3, which is what this system content-addresses with everywhere, and what
// keripy derives an identifier from. A different hash here would produce
// commitments no rotation could ever satisfy.
func digestsOf(publicKeys []string) ([]string, error) {
	digests := make([]string, 0, len(publicKeys))
	for _, key := range publicKeys {
		if strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("an owner committed no successor key")
		}
		digests = append(digests, iacrypto.Blake3QB64Must([]byte(key)))
	}
	return digests, nil
}
