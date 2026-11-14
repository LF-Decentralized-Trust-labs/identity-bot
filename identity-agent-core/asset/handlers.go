package asset

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"identity-agent-core/enrolsecret"
	"net/http"
	"regexp"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/jsonreply"
)

type Handler struct {
	Store      *Store
	KeriDriver drivers.KeriEngine
	dataDir    string

	// RootAID returns the AID of the agent's root identity (the delegator for per-asset
	// delegated inception), or "" if no root identity exists yet. Injected by the server so
	// this package stays free of the identity store. Nil is treated as "".
	RootAID func() string

	// OnFrontEndsSwitchedOff is told, after the owner's setting is saved, which
	// front ends it has just switched off for the asset, so what was granted
	// through them is ended and not merely paused (ADR-072 section 3). Nil is
	// told nothing.
	OnFrontEndsSwitchedOff func(assetID string, kinds []string)
	// OnMemberRemoved is told after a person is removed from the asset, so a
	// grant that does not lapse cannot wake when they are added again.
	OnMemberRemoved func(assetID, memberAID string)

	// VaultHas reports whether the credential vault holds an entry of a name,
	// so a brain's reference to one is shown and a key in its place is not.
	// Injected by the server; nil knows of none.
	VaultHas func(string) bool

	// DefaultDelegationModel returns the agent's configured default delegation model for new
	// assets when the request doesn't specify one: "delegated" | "standalone" | "" (unset).
	// This is the flexibility seam: an org deployment configures "delegated" (per-asset AIDs
	// anchor to the org root — provable ownership); an individual leaves it standalone (no
	// forced root<->asset correlation). An explicit request field always overrides this, and
	// the resolver can later read a stored per-agent setting instead of an env var without
	// touching this handler. Nil / "" falls through to the neutral built-in default.
	DefaultDelegationModel func() string

	// PersistDelegationAnchor persists the delegator's (owner root's) anchoring interaction
	// event to the root KEL after a delegated inception. Injected by the server so this
	// package stays free of the identity/event store. It is MANDATORY for delegated assets:
	// without it, the anchor is lost on the next KEL reload and delegation verification
	// breaks (the root KEL develops a sequence gap). Nil is only acceptable where no
	// delegated inception occurs (standalone assets / tests).
	//
	// It is handed the whole response, not only the parsed event, because the
	// stored event must carry the bytes it was serialised as: those are what the
	// delegator signs, and an approval nobody signed approves nothing.
	PersistDelegationAnchor func(rootAID string, approval *drivers.DriverDelegatedInceptionResponse) error
	// KeyHeldHere reports whether this Identity Agent holds the identity's
	// key. A delegated identity is approved by an interaction in the
	// identity's key log, which only that key may sign; where it is on
	// another device nothing is delegated here, rather than an approval
	// written unsigned.
	KeyCheck func() error
	// AskApproval, where the key is on another device, asks that device to
	// sign the approval of a delegated identity built but not yet held, once
	// the asset it is for is stored with its approval pending. An error is
	// returned if it could not be asked, and the asset is then removed.
	AskApproval func(a Asset, p *drivers.PreparedDelegation) error
}

func NewHandler(dataDir string, keri drivers.KeriEngine) (*Handler, error) {
	st, err := NewStore(dataDir)
	if err != nil {
		return nil, err
	}
	return &Handler{Store: st, KeriDriver: keri, dataDir: dataDir}, nil
}

// persistDelegationAnchor saves the root's anchoring interaction event for a
// delegated inception. A missing DelegatorIxn or an unwired callback is a hard
// error for a delegated asset — silently skipping it is precisely what produced
// the root-KEL sequence gap that broke delegation verification.
// ErrKeyElsewhere is a delegation asked for where the identity's key is held
// on another device.
var ErrKeyElsewhere = errors.New("the identity's key is held on another device, which alone can approve an identity delegated from it; do this there")

// ErrKeyUnavailable is a delegation asked for where the identity's key is
// held here and cannot be read right now.
var ErrKeyUnavailable = errors.New("this machine holds the identity's key and cannot read it right now")

// mayDelegate reports why a delegated identity cannot be made here, if it
// cannot: ErrKeyElsewhere or ErrKeyUnavailable.
func (h *Handler) mayDelegate() error {
	if h.KeyCheck == nil {
		return nil
	}
	return h.KeyCheck()
}

// delegationRefusalStatus answers a refused delegation.
func delegationRefusalStatus(err error) int {
	if errors.Is(err, ErrKeyUnavailable) {
		return http.StatusServiceUnavailable
	}
	return http.StatusConflict
}

func (h *Handler) persistDelegationAnchor(rootAID string, approval *drivers.DriverDelegatedInceptionResponse) error {
	if approval == nil || approval.DelegatorIxn == nil {
		return fmt.Errorf("driver returned no delegator anchoring event")
	}
	if h.PersistDelegationAnchor == nil {
		return fmt.Errorf("no delegation-anchor persistence configured")
	}
	return h.PersistDelegationAnchor(rootAID, approval)
}

func (h *Handler) writeJSON(w http.ResponseWriter, v interface{}, status int) {
	jsonreply.Write(w, status, v)
}

func (h *Handler) HandleListAssets(w http.ResponseWriter, r *http.Request) {
	assets, err := h.Store.ListAssets()
	if err != nil {
		h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusInternalServerError)
		return
	}
	type item struct {
		Asset        Asset `json:"asset"`
		MemberCount  int   `json:"member_count"`
		PendingCount int   `json:"pending_count"`
	}
	var out []item
	for _, a := range assets {
		mems := h.Store.ListMembers(a.ID)
		reqs := h.Store.ListRequests(a.ID)
		pending := 0
		for _, rq := range reqs {
			if rq.Status == "pending" {
				pending++
			}
		}
		out = append(out, item{Asset: a.ForDisplay(h.VaultHas), MemberCount: len(mems), PendingCount: pending})
	}
	h.writeJSON(w, map[string]interface{}{"assets": out}, http.StatusOK)
}

func (h *Handler) HandleCreateAsset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DisplayName     string           `json:"display_name"`
		Origin          string           `json:"origin"`
		AssetType       string           `json:"asset_type"`
		DelegationModel string           `json:"delegation_model"`
		Policy          EnrollmentPolicy `json:"policy"`
		// DeviceFrontEnds: for an app, the front ends its manifest offers.
		DeviceFrontEnds []string `json:"device_front_ends"`
		// InstalledApp: who the app's installed front end is (ADR-072 section 4).
		InstalledApp InstalledAppIdentity `json:"installed_app_identity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.writeJSON(w, map[string]string{"error": "bad request"}, http.StatusBadRequest)
		return
	}
	if err := CheckOfferedFrontEnds(body.AssetType, body.DeviceFrontEnds); err != nil {
		h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusBadRequest)
		return
	}
	if err := CheckInstalledAppIdentity(body.AssetType, body.DeviceFrontEnds, body.InstalledApp); err != nil {
		h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusBadRequest)
		return
	}
	if body.DisplayName == "" || body.Origin == "" || body.AssetType == "" {
		h.writeJSON(w, map[string]string{"error": "missing fields"}, http.StatusBadRequest)
		return
	}
	if g := body.Policy.UnsupportedGate(); g != "" {
		h.writeJSON(w, map[string]string{"error": g}, http.StatusBadRequest)
		return
	}

	// Derive the asset's signing keypair from the controller root seed (HD), keyed by a
	// stable per-asset index. The private seed is never stored — re-derived on demand
	// (root + SigningIndex) so the agent can sign challenges on behalf of this asset.
	// (Previously the keypair was random and the private half discarded, so the asset
	// could never sign at all.)
	id := genID()
	signingIndex := signingIndexForID(id)
	pub, nextPub, derr := deriveAssetKeypair(h.dataDir, signingIndex)
	if derr != nil {
		h.writeJSON(w, map[string]string{"error": "derive asset key: " + derr.Error()}, http.StatusInternalServerError)
		return
	}
	pubB64 := iacrypto.VerkeyQB64(pub)
	nextB64 := iacrypto.VerkeyQB64(nextPub)

	// Resolve the delegation model with an explicit precedence, so the org-vs-individual choice
	// is a policy — not baked into the code:
	//   1. an explicit request field always wins ("delegated" | "standalone");
	//   2. otherwise the agent's configured default (org deployments set "delegated");
	//   3. otherwise a neutral built-in default of "standalone" (an individual gets an
	//      unlinked per-asset AID unless something opts into delegation).
	// A delegated AID anchors back to the root AID (the driver keys identities by AID, so the
	// root AID IS the delegator name), which is what an org wants for provable ownership.
	rootAID := ""
	if h.RootAID != nil {
		rootAID = h.RootAID()
	}
	requested := body.DelegationModel
	model := requested
	if model == "" && h.DefaultDelegationModel != nil {
		model = h.DefaultDelegationModel()
	}
	if model == "" {
		model = "standalone"
	}
	// Delegation needs a root identity to delegate from. If the caller explicitly asked for it
	// without one, that's an error; if it was only the default, degrade gracefully to standalone
	// rather than failing asset creation.
	if model == "delegated" && rootAID == "" {
		if requested == "delegated" {
			h.writeJSON(w, map[string]string{"error": "delegated inception requires a root identity"}, http.StatusBadRequest)
			return
		}
		model = "standalone"
	}

	var pairwise string
	var delegator string
	var approvalPending bool
	var awaiting *drivers.PreparedDelegation

	if model == "delegated" {
		elsewhere, err := h.mustAskTheKeyDevice()
		if err != nil {
			h.writeJSON(w, map[string]string{"error": err.Error()}, delegationRefusalStatus(err))
			return
		}
		if elsewhere {
			// The key that approves it is on another device: the asset is
			// stored, unable to act, and that device is asked.
			prepared, err := h.prepareApproval(rootAID, pubB64, nextB64)
			if err != nil {
				h.writeJSON(w, map[string]string{"error": err.Error()}, delegationRefusalStatus(err))
				return
			}
			pairwise, delegator, approvalPending = prepared.AID, rootAID, true
			awaiting = prepared
		} else {
			resp, err := h.KeriDriver.CreateDelegatedInception(pubB64, nextB64, body.DisplayName, rootAID,
				FoundingSigner(h.dataDir, signingIndex))
			if err != nil {
				h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusInternalServerError)
				return
			}
			// Persist the root's anchoring event, or the delegation won't survive a KEL
			// reload. Fail creation rather than mint a delegated asset that can't verify.
			if err := h.persistDelegationAnchor(rootAID, resp); err != nil {
				h.writeJSON(w, map[string]string{"error": "persist delegation anchor: " + err.Error()}, http.StatusInternalServerError)
				return
			}
			pairwise = resp.AID
			delegator = resp.DelegatorAID
		}
	} else {
		resp, err := h.KeriDriver.CreateInceptionNamed(pubB64, nextB64, body.DisplayName,
			FoundingSigner(h.dataDir, signingIndex))
		if err != nil {
			h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusInternalServerError)
			return
		}
		pairwise = resp.AID
	}

	asset := Asset{
		ID:                id,
		DisplayName:       body.DisplayName,
		AssetType:         body.AssetType,
		Origin:            body.Origin,
		PairwiseAID:       pairwise,
		DelegationModel:   model,
		DelegatorAID:      delegator,
		ApprovalPending:   approvalPending,
		Policy:            body.Policy,
		DeviceFrontEnds:   body.DeviceFrontEnds,
		InstalledApp:      body.InstalledApp,
		FrontEndsDeclared: DeclaresFrontEnds(body.AssetType, body.DeviceFrontEnds),
		SigningIndex:      signingIndex,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}

	if awaiting != nil {
		if err := h.storeAwaitingApproval(asset, awaiting); err != nil {
			h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusInternalServerError)
			return
		}
	} else {
		h.Store.UpsertAsset(asset)
	}

	h.writeJSON(w, map[string]interface{}{"asset": asset, "sdk_config": SDKConfigOf(asset)}, http.StatusCreated)
}

// SDKConfigOf is what an app on this asset is configured with. An asset still
// waiting for the device that holds the identity's key to approve it is in no
// key log yet and cannot be resolved by anyone, so its identifier and OOBI are
// left out and it says it is pending, rather than being handed out as usable.
func SDKConfigOf(a Asset) map[string]string {
	sdk := map[string]string{
		"ASSET_ID":        a.ID,
		"ENROLLMENT_MODE": string(a.Policy.Mode),
	}
	if a.ApprovalPending {
		sdk["APPROVAL_PENDING"] = "true"
		return sdk
	}
	sdk["SITE_PAIRWISE_AID"] = a.PairwiseAID
	sdk["SITE_OOBI"] = fmt.Sprintf("http://127.0.0.1:5050/public/oobi/%s", a.PairwiseAID)
	return sdk
}

func (h *Handler) HandleGetAsset(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	a, ok, err := h.Store.GetAsset(id)
	if err != nil {
		h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusInternalServerError)
		return
	}
	if !ok {
		h.writeJSON(w, map[string]string{"error": "not found"}, http.StatusNotFound)
		return
	}
	h.writeJSON(w, map[string]interface{}{"asset": a.ForDisplay(h.VaultHas), "sdk_config": SDKConfigOf(a)}, http.StatusOK)
}

func (h *Handler) HandleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var pol EnrollmentPolicy
	json.NewDecoder(r.Body).Decode(&pol)
	if g := pol.UnsupportedGate(); g != "" {
		h.writeJSON(w, map[string]string{"error": g}, http.StatusBadRequest)
		return
	}
	a, ok, err := h.Store.GetAsset(id)
	if err != nil {
		h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusInternalServerError)
		return
	}
	if !ok {
		h.writeJSON(w, map[string]string{"error": "not found"}, http.StatusNotFound)
		return
	}
	a.Policy = pol
	a.UpdatedAt = time.Now().UTC()
	h.Store.UpsertAsset(a)
	h.writeJSON(w, a.ForDisplay(h.VaultHas), http.StatusOK)
}

// HandleGetFrontEnds answers which front ends an app offers and which of them
// its owner has switched off. GET /api/assets/{id}/front-ends. Owner only.
func (h *Handler) HandleGetFrontEnds(w http.ResponseWriter, r *http.Request) {
	a, ok, status, msg := h.appForFrontEnds(chi.URLParam(r, "id"))
	if !ok {
		h.writeJSON(w, map[string]string{"error": msg}, status)
		return
	}
	h.writeJSON(w, frontEndsOf(a), http.StatusOK)
}

// HandlePutFrontEnds sets which offered front ends are switched off.
// PUT /api/assets/{id}/front-ends {"switched_off": ["browser"]}. Owner only.
// The list replaces the last one; a kind the app does not offer is refused,
// because the owner can switch off what an app offers and cannot switch on
// what it does not (ADR-072 §3).
func (h *Handler) HandlePutFrontEnds(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SwitchedOff *[]string `json:"switched_off"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.SwitchedOff == nil {
		h.writeJSON(w, map[string]string{"error": "bad request: switched_off is required (an empty list switches everything on)"}, http.StatusBadRequest)
		return
	}
	frontEndsMu.Lock()
	defer frontEndsMu.Unlock()
	a, ok, status, msg := h.appForFrontEnds(chi.URLParam(r, "id"))
	if !ok {
		h.writeJSON(w, map[string]string{"error": msg}, status)
		return
	}
	if !a.FrontEndsAreDeclared() {
		h.writeJSON(w, map[string]string{"error": "this utility app was made before it could say how it is used, so there is nothing to switch off until its front ends are declared"}, http.StatusConflict)
		return
	}
	off, err := SwitchOff(a.DeviceFrontEnds, *body.SwitchedOff)
	if err != nil {
		h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusBadRequest)
		return
	}
	var newlyOff []string
	for _, k := range off {
		if !containsKind(a.FrontEndsOff, k) {
			newlyOff = append(newlyOff, k)
		}
	}
	a.FrontEndsOff = off
	a.UpdatedAt = time.Now().UTC()
	if err := h.Store.UpsertAsset(a); err != nil {
		h.writeJSON(w, map[string]string{"error": "the setting could not be saved"}, http.StatusInternalServerError)
		return
	}
	if h.OnFrontEndsSwitchedOff != nil && len(newlyOff) > 0 {
		h.OnFrontEndsSwitchedOff(a.ID, newlyOff)
	}
	h.writeJSON(w, frontEndsOf(a), http.StatusOK)
}

// HandleSetOfferedFrontEnds declares the front ends of an app that has none
// declared: an app made before it could say. PUT /api/assets/{id}/front-ends/offered
// {"device_front_ends": ["browser"]}, taken from the app's manifest. Owner only,
// and once only: an app that has declared is refused, because what an app
// offers is not for the owner's switches to grow (ADR-072 section 3).
func (h *Handler) HandleSetOfferedFrontEnds(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DeviceFrontEnds *[]string            `json:"device_front_ends"`
		InstalledApp    InstalledAppIdentity `json:"installed_app_identity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.DeviceFrontEnds == nil {
		h.writeJSON(w, map[string]string{"error": "bad request: device_front_ends is required (the app's manifest list, which may be empty)"}, http.StatusBadRequest)
		return
	}
	offered := *body.DeviceFrontEnds
	if offered == nil {
		offered = []string{}
	}
	if err := CheckOfferedFrontEnds("app", offered); err != nil {
		h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusBadRequest)
		return
	}
	if err := CheckInstalledAppIdentity("app", offered, body.InstalledApp); err != nil {
		h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusBadRequest)
		return
	}
	// Held from the read to the write so two requests cannot both pass the
	// "once only" check.
	frontEndsMu.Lock()
	defer frontEndsMu.Unlock()
	a, ok, status, msg := h.appForFrontEnds(chi.URLParam(r, "id"))
	if !ok {
		h.writeJSON(w, map[string]string{"error": msg}, status)
		return
	}
	if a.FrontEndsAreDeclared() {
		h.writeJSON(w, map[string]string{"error": ErrFrontEndsAlreadyDeclared.Error()}, http.StatusConflict)
		return
	}
	a.DeviceFrontEnds = offered
	a.FrontEndsDeclared = true
	a.InstalledApp = body.InstalledApp
	a.UpdatedAt = time.Now().UTC()
	if err := h.Store.UpsertAsset(a); err != nil {
		h.writeJSON(w, map[string]string{"error": "the setting could not be saved"}, http.StatusInternalServerError)
		return
	}
	h.writeJSON(w, frontEndsOf(a), http.StatusOK)
}

// HandleSetRelayID records a utility app's relay identifier, which its sign-in
// challenges then carry, signed (ADR-072 Amendment 7). PUT /api/assets/{id}/relay-id
// {"relay_id": "E…"}. Owner only. The record itself is SetRelayID, which an add-on
// that learns the identifier calls directly.
func (h *Handler) HandleSetRelayID(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RelayID string `json:"relay_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.writeJSON(w, map[string]string{"error": "bad request: relay_id is required, an identifier of 44 characters"}, http.StatusBadRequest)
		return
	}
	a, err := h.SetRelayID(chi.URLParam(r, "id"), body.RelayID)
	switch {
	case errors.Is(err, ErrRelayIDShape):
		h.writeJSON(w, map[string]string{"error": "bad request: relay_id is required, an identifier of 44 characters"}, http.StatusBadRequest)
	case errors.Is(err, ErrNotFound):
		h.writeJSON(w, map[string]string{"error": "not found"}, http.StatusNotFound)
	case errors.Is(err, ErrNotAnApp):
		h.writeJSON(w, map[string]string{"error": "only a utility app has a relay identifier"}, http.StatusBadRequest)
	case err != nil:
		h.writeJSON(w, map[string]string{"error": "the relay identifier could not be saved"}, http.StatusInternalServerError)
	default:
		h.writeJSON(w, map[string]string{"relay_id": a.RelayID}, http.StatusOK)
	}
}

var (
	// ErrRelayIDShape is a relay identifier that is not 44 characters of the identifier alphabet.
	ErrRelayIDShape = errors.New("a relay identifier is 44 characters")
	// ErrNotFound is an asset that is not held.
	ErrNotFound = errors.New("not found")
	// ErrNotAnApp is an asset that is not a utility app.
	ErrNotAnApp = errors.New("only a utility app has a relay identifier")
)

// SetRelayID records the relay identifier of the utility app assetID. It may be set
// again, as a utility app that is replaced is given a new identifier; challenges
// already issued keep the old one. The route and an add-on both come here, so the
// shape check and the write are in one place.
func (h *Handler) SetRelayID(assetID, relayID string) (*Asset, error) {
	if !relayIDShape.MatchString(relayID) {
		return nil, ErrRelayIDShape
	}
	frontEndsMu.Lock()
	defer frontEndsMu.Unlock()
	a, found, err := h.Store.GetAsset(assetID)
	switch {
	case err != nil:
		return nil, err
	case !found:
		return nil, ErrNotFound
	case a.AssetType != "app":
		return nil, ErrNotAnApp
	}
	a.RelayID = relayID
	a.UpdatedAt = time.Now().UTC()
	if err := h.Store.UpsertAsset(a); err != nil {
		return nil, err
	}
	return &a, nil
}

// relayIDShape is a self-addressing identifier as written in this system: 44
// characters of the URL-safe alphabet, the first a derivation code.
var relayIDShape = regexp.MustCompile(`^[A-Z][A-Za-z0-9_-]{43}$`)

func (h *Handler) appForFrontEnds(id string) (a Asset, ok bool, status int, msg string) {
	a, found, err := h.Store.GetAsset(id)
	switch {
	case err != nil:
		return a, false, http.StatusInternalServerError, err.Error()
	case !found:
		return a, false, http.StatusNotFound, "not found"
	case a.AssetType != "app":
		return a, false, http.StatusBadRequest, "only a utility app has front ends"
	}
	return a, true, 0, ""
}

func (h *Handler) HandleCreateInvite(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body struct {
		Label   string `json:"label"`
		MaxUses int    `json:"max_uses"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.MaxUses == 0 {
		body.MaxUses = 0 // unlimited
	}
	token := genToken()
	inv := AssetInvite{
		Token:     token,
		AssetID:   id,
		Label:     body.Label,
		MaxUses:   body.MaxUses,
		UseCount:  0,
		CreatedAt: time.Now().UTC(),
	}
	if err := h.Store.CreateInvite(inv); err != nil {
		h.writeJSON(w, map[string]string{"error": "the invite could not be saved"}, http.StatusInternalServerError)
		return
	}
	inv.ID = enrolsecret.Digest(token)
	h.writeJSON(w, inv, http.StatusCreated)
}

func (h *Handler) HandleListInvites(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	h.writeJSON(w, h.Store.ListInvites(id), http.StatusOK)
}

func (h *Handler) HandleRevokeInvite(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	inviteID := chi.URLParam(r, "invite")
	h.writeRevokeResult(w, h.Store.RevokeInvite(id, inviteID), func() { h.writeJSON(w, map[string]bool{"revoked": true}, http.StatusOK) })
}

// writeRevokeResult turns the outcome of a revoke into the status a client can
// trust: 404 for a code nobody holds, 409 for one already revoked or used up,
// 500 when the withdrawal could not be saved. ok runs only on a real revoke.
func (h *Handler) writeRevokeResult(w http.ResponseWriter, err error, ok func()) {
	switch {
	case err == nil:
		ok()
	case errors.Is(err, ErrInviteNotFound):
		h.writeJSON(w, map[string]string{"error": "no such invite"}, http.StatusNotFound)
	case errors.Is(err, ErrInviteClosed):
		h.writeJSON(w, map[string]string{"error": "invite is already revoked or used up"}, http.StatusConflict)
	default:
		h.writeJSON(w, map[string]string{"error": "the invite could not be revoked"}, http.StatusInternalServerError)
	}
}

func (h *Handler) HandleGetInviteInfo(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	inv, ok := h.Store.GetInvite(token)
	if !ok || inv.Revoked || inv.usedUp() {
		h.writeJSON(w, map[string]string{"error": "invalid"}, http.StatusNotFound)
		return
	}
	h.writeJSON(w, inv, http.StatusOK)
}

func (h *Handler) HandleRedeemInvite(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	// TODO: enforce policy.RequiredAAL >= asset.Policy.RequiredAAL before granting membership.
	// Check and spend in one locked step.
	switch _, err := h.Store.RedeemInvite(token); {
	case err == nil:
	case errors.Is(err, ErrInviteNotFound):
		h.writeJSON(w, map[string]string{"error": "invalid"}, http.StatusBadRequest)
		return
	case errors.Is(err, ErrInviteExhausted):
		h.writeJSON(w, map[string]string{"error": "exhausted"}, http.StatusBadRequest)
		return
	default:
		h.writeJSON(w, map[string]string{"error": "the invite could not be redeemed"}, http.StatusInternalServerError)
		return
	}
	// create member stub (pairwise from login context later)
	h.writeJSON(w, map[string]string{"status": "redeemed"}, http.StatusOK)
}

func (h *Handler) HandleListRequests(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	h.writeJSON(w, h.Store.ListRequests(id), http.StatusOK)
}

func (h *Handler) HandleSubmitRequest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body struct {
		RequesterInfo map[string]string `json:"requester_info"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	req := AssetAccessRequest{
		ID:            genID(),
		AssetID:       id,
		RequesterInfo: body.RequesterInfo,
		Status:        "pending",
		CreatedAt:     time.Now().UTC(),
	}
	h.Store.CreateRequest(req)
	h.writeJSON(w, req, http.StatusCreated)
}

func (h *Handler) HandleApproveRequest(w http.ResponseWriter, r *http.Request) {
	reqID := chi.URLParam(r, "reqID")
	// TODO: enforce policy.RequiredAAL
	h.Store.UpdateRequestStatus(reqID, "approved")
	h.writeJSON(w, map[string]string{"status": "approved"}, http.StatusOK)
}

func (h *Handler) HandleDenyRequest(w http.ResponseWriter, r *http.Request) {
	reqID := chi.URLParam(r, "reqID")
	h.Store.UpdateRequestStatus(reqID, "denied")
	h.writeJSON(w, map[string]string{"status": "denied"}, http.StatusOK)
}

func (h *Handler) HandleListMembers(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	h.writeJSON(w, h.Store.ListMembers(id), http.StatusOK)
}

func (h *Handler) HandleRemoveMember(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	aid := chi.URLParam(r, "aid")
	h.Store.RemoveMember(id, aid)
	if h.OnMemberRemoved != nil {
		h.OnMemberRemoved(id, aid)
	}
	h.writeJSON(w, map[string]bool{"removed": true}, http.StatusOK)
}

func genID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func genToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
