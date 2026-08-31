package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"identity-agent-core/asset"
	"identity-agent-core/login"

	"github.com/go-chi/chi/v5"
)

func (s *CoreServer) mountSignerRoutes(r chi.Router) {
	if s.assetHandler == nil {
		return
	}
	// Under the parent "/api" router — relative paths.
	r.Route("/signer", func(r chi.Router) {
		r.Post("/invites", s.handleCreateSignerInvite)
		// Public: the signing individual's agent looks up + redeems here (t=4).
		r.Get("/invites/{token}", s.assetHandler.HandleGetEmployeeInviteInfo)
		r.Post("/invites/{token}/redeem", s.handleRedeemSignerInvite)
	})
}

// handleCreateSignerInvite mints the founding-signer invite and its signed t=4
// Ask. The signer relates to the organisation's ROOT identity — no portal exists
// yet during onboarding. The organisation's app renders the returned URL as the
// QR or link a founding signer scans.
// HandleCreateSignerInvite is the founding-signer invite, exposed so an
// extension that owns the roster can mount this route without rebuilding it.
//
// Only the REDEEM half differs for such an extension, because only that half
// writes a roster. Minting the invite derives a pairwise key and signs an Ask
// with it, and a second implementation of that is how a ceremony ends up
// recording a signature with no cryptographic force behind it.
func (s *CoreServer) HandleCreateSignerInvite(w http.ResponseWriter, r *http.Request) {
	s.handleCreateSignerInvite(w, r)
}

func (s *CoreServer) handleCreateSignerInvite(w http.ResponseWriter, r *http.Request) {
	publicURL := s.EndpointService.CurrentURL()
	if publicURL == "" {
		publicURL = s.getPublicURL(r)
	}
	// Mintable BEFORE the identity exists, which is the point.
	//
	// This used to refuse until the identity had been created, so the founding
	// signer could only ever be collected AFTERWARDS — and an owner can only be
	// anchored AT inception. The result was an organisation incepted owning
	// itself, with its real owner recorded in a file beside the database: the
	// precise arrangement the anchor was introduced to replace.
	//
	// So the invitation now names what the organisation WILL be rather than what
	// it is. Whoever scans it is agreeing to become the owner of an organisation
	// about to be created, which is a clearer and stronger commitment than
	// vouching for one that already exists without them.
	orgAID, orgOOBI, orgName := "", "", ""
	if id, _ := s.DataStore.GetIdentity(); id != nil {
		orgAID = id.AID
		orgOOBI = fmt.Sprintf("%s/public/oobi/%s", publicURL, id.AID)
	}
	if prof, _ := s.DataStore.GetProfile(); prof != nil {
		orgName = prof.OrgName
		if orgName == "" {
			orgName = prof.FullName
		}
	}

	inv := asset.EmployeeInvite{
		Token:    genInviteToken(),
		Role:     "Super Admin",
		IsSigner: true,
		MaxUses:  1, // a single founding signer
		SiteAID:  orgAID,
		SiteOOBI: orgOOBI,
	}
	if err := s.assetHandler.Store.CreateEmployeeInvite(inv); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// A name is required even when the identity is not, because the person
	// scanning has to be told what they are agreeing to own. An invitation
	// carrying neither an identifier nor a name says nothing at all.
	if orgAID == "" && strings.TrimSpace(orgName) == "" {
		http.Error(w,
			"name the organisation before inviting its owner — an invitation with no identifier and no name tells the person scanning nothing about what they would be taking on",
			http.StatusBadRequest)
		return
	}

	askToken, aerr := s.mintSignerAsk(orgName, orgAID, orgOOBI, inv.Token)
	if aerr != nil {
		http.Error(w, aerr.Error(), http.StatusInternalServerError)
		return
	}

	scanWriteJSON(w, map[string]interface{}{
		"invite": inv,
		"token":  askToken,
		"url":    fmt.Sprintf("%s/i/%s", publicURL, askToken),
	})
}

// mintSignerAsk builds the signed offer a person scans, and returns the token
// that resolves to it.
//
// Extracted so the founding-signer invite and the owner ceremony mint the same
// thing. A second, parallel offer format would be one more thing to keep in
// step, and the agent on the other side already knows how to read this one.
func (s *CoreServer) mintSignerAsk(orgName, orgAID, orgOOBI, inviteToken string) (string, error) {
	_, pwOOBI, seed, err := s.mintPairwise("signer")
	if err != nil {
		return "", fmt.Errorf("mint signer: %w", err)
	}
	ask, _ := json.Marshal(map[string]interface{}{
		"v":            "ASK1",
		"t":            4,
		"org_name":     orgName,
		"org_aid":      orgAID,
		"org_oobi":     orgOOBI,
		"site_aid":     orgAID,
		"site_oobi":    orgOOBI,
		"invite_token": inviteToken,
		"signer_oobi":  pwOOBI,
	})
	sig, serr := login.SignAsk(ask, seed)
	if serr != nil {
		return "", fmt.Errorf("sign ask: %w", serr)
	}
	if signed, ierr := injectSig(ask, sig); ierr == nil {
		ask = signed
	}

	tb := make([]byte, 16)
	if _, rerr := rand.Read(tb); rerr != nil {
		return "", rerr
	}
	askToken := hex.EncodeToString(tb)
	mintedAsks.Lock()
	mintedAsks.m[askToken] = ask
	mintedAsks.Unlock()
	return askToken, nil
}

// handleRedeemSignerInvite is called by the signing individual's agent (t=4).
//
// It seals them as the organisation's owner authority, and records them on the
// roster as an active administrator.
//
// The sealing is the part that matters, and its absence was the bug. Redeeming
// used to write an employee row saying "Super Admin" and file a signature
// beside it as evidence — a string in a table with no cryptographic force.
// Nothing consulted it before acting, so ownerAuthority() fell through to its
// default of "this agent's own identity is the authority" and the organisation
// owned itself. On rented hardware that meant the box held the only key that
// mattered and nobody outside it could prove otherwise.
//
// Sealing here closes that by making the signer's key the one this agent
// answers to, which is what most operations already check.
func (s *CoreServer) handleRedeemSignerInvite(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	var body struct {
		PairwiseAID   string `json:"pairwise_aid"`
		Name          string `json:"name"`
		OOBI          string `json:"oobi"`
		PublicKey     string `json:"public_key"`
		NextPublicKey string `json:"next_public_key"`
		VouchSig      string `json:"vouch_sig"`
		VouchPayload  string `json:"vouch_payload"`
		// BackupSealPublicKeyB64 is the X25519 key this organisation will seal
		// its archives to, so it can write backups it cannot itself read.
		//
		// Collected here because this is the moment the owner is present and
		// nowhere else is. An organisation holds its own signing seed and the
		// founder never sees it — there is no phrase to write down — so a
		// sealed archive only the owner can open is the ONLY way an
		// organisation survives losing the machine it runs on. Asking for it
		// later means a window where the answer is "it does not survive".
		BackupSealPublicKeyB64 string `json:"backup_seal_public_key_b64,omitempty"`
		// MachineOwnerAID is the identity this owner will claim a rented
		// machine with, minted while they were here rather than at the moment
		// of claiming.
		//
		// A machine is told who may claim it before it starts, so the identity
		// has to exist before anybody asks for a machine -- and this is the
		// only moment the owner's device is in the conversation beforehand.
		// Optional: agreeing to own an organisation and never renting anything
		// is ordinary.
		MachineOwnerAID string `json:"machine_owner_aid,omitempty"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.PairwiseAID == "" || body.VouchSig == "" {
		http.Error(w, "pairwise_aid and vouch_sig required", http.StatusBadRequest)
		return
	}
	// A signer without a public key cannot be sealed, and an organisation whose
	// owner cannot be verified is the condition this ceremony exists to prevent.
	// Checked here with the other required fields, before anything reaches into
	// the roster — a request that cannot succeed should not touch subsystems on
	// its way to being refused.
	if body.PublicKey == "" {
		http.Error(w,
			"public_key is required: without it this organisation could not verify its own owner, "+
				"which is the condition this ceremony exists to prevent",
			http.StatusBadRequest)
		return
	}
	inv, ok := s.assetHandler.Store.GetEmployeeInvite(token)
	if !ok || inv.Revoked || !inv.IsSigner {
		http.Error(w, "invalid signer invite", http.StatusBadRequest)
		return
	}
	if inv.MaxUses > 0 && inv.UseCount >= inv.MaxUses {
		http.Error(w, "signer invite already used", http.StatusBadRequest)
		return
	}
	emp := asset.Employee{
		PairwiseAID:     body.PairwiseAID,
		MachineOwnerAID: body.MachineOwnerAID,
		Name:            body.Name,
		Role:            "Super Admin",
		Status:          "active", // founding signer is active immediately
		InviteToken:     token,
		OOBI:            body.OOBI,
		IsSigner:        true,
		VouchSig:        body.VouchSig,
		VouchPayload:    body.VouchPayload,
	}

	acc, err := s.AcceptFoundingSigner(SignerAcceptance{
		InviteToken:            token,
		PairwiseAID:            body.PairwiseAID,
		PublicKey:              body.PublicKey,
		NextPublicKey:          body.NextPublicKey,
		BackupSealPublicKeyB64: body.BackupSealPublicKeyB64,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.assetHandler.Store.UpsertEmployee(emp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.assetHandler.Store.IncrementEmployeeInviteUse(token)

	if acc.Ceremony {
		scanWriteJSON(w, map[string]interface{}{
			"status":      "accepted",
			"owner":       body.PairwiseAID,
			"outstanding": acc.Outstanding,
		})
		return
	}
	scanWriteJSON(w, map[string]string{
		"status": "active",
		"role":   "Super Admin",
		"owner":  body.PairwiseAID,
	})
}

// SignerAcceptance is what somebody presented when they agreed to own an
// organisation.
type SignerAcceptance struct {
	InviteToken            string
	PairwiseAID            string
	PublicKey              string
	NextPublicKey          string
	BackupSealPublicKeyB64 string
}

// SignerAccepted says what agreeing turned out to mean: one more acceptance in
// a ceremony still collecting them, or the founding of an organisation.
type SignerAccepted struct {
	Ceremony bool
	// Who has not accepted yet, when a ceremony is still collecting.
	Outstanding []string
}

// AcceptFoundingSigner performs the OWNER half of a signer redemption, and
// writes no roster.
//
// The roster is deliberately not written here, because an organisation does not
// necessarily keep it where this core does. An extension may own the roster,
// and a founding signer written anywhere other than the roster in use is a
// signer nobody can see — which leaves founding unable to complete while every
// individual step reports success.
//
// What stays here is the ordering, which is the part that must not be
// reimplemented anywhere: the owner is sealed BEFORE the caller writes anybody
// down. If the roster were written first and sealing then failed, the
// organisation would look founded — an active Super Admin on the list — while
// answering to nobody but itself. Sealing first means a failure leaves an
// unfounded organisation that can be founded again, which is recoverable
// rather than misleading.
func (s *CoreServer) AcceptFoundingSigner(a SignerAcceptance) (SignerAccepted, error) {
	// An invite that belongs to an ownership ceremony is collecting keys from
	// several people; the founding path below is for the FIRST owner, where
	// there is nothing yet to rotate from.
	ceremony, complete, cerr := s.recordAcceptance(
		a.InviteToken, a.PairwiseAID, a.PublicKey, a.NextPublicKey)
	if cerr != nil {
		return SignerAccepted{}, fmt.Errorf("could not record your acceptance: %w", cerr)
	}
	if ceremony != nil {
		if complete {
			// The last acceptance is what applies it. Nobody has to remember to
			// come back and press a button, and there is no window in which
			// every owner has agreed and nothing has changed.
			s.completeCeremonyIfReady(ceremony)
		}
		return SignerAccepted{Ceremony: true, Outstanding: ceremony.Outstanding()}, nil
	}

	if err := s.SealOwnerAuthority(OwnerAuthority{
		AID:       a.PairwiseAID,
		PublicKey: a.PublicKey,
	}); err != nil {
		return SignerAccepted{}, fmt.Errorf("could not seal the owner: %w", err)
	}

	// Where this organisation's archives get sealed to, recorded in the same
	// act. Not fatal, and deliberately so: the owner is sealed by this point and
	// refusing now would leave an organisation with no owner at all, which is
	// worse than one that cannot back up yet. Logged loudly instead, because an
	// organisation that cannot back up is a real problem — its signing seed
	// exists in exactly one place and the founder has no copy of it.
	if a.BackupSealPublicKeyB64 != "" {
		if err := s.recordBackupSealKeys([]string{a.BackupSealPublicKeyB64}); err != nil {
			log.Printf("[signer] WARNING: the owner was sealed but their recovery key was refused (%v) — this organisation cannot write a backup anybody can open", err)
		}
	} else {
		log.Printf("[signer] WARNING: the owner gave no recovery key — this organisation's seed exists in one place only, and losing this machine would end it")
	}
	return SignerAccepted{}, nil
}
