package asset

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"identity-agent-core/iacrypto"
)

// ProvisionAgentAsset provisions an AI agent as a delegated asset: it mints a
// delegated AID (dip anchored to the owner's root AID — the KERI driver keys
// identities by AID, so the root AID IS the delegator name) and stores the agent
// with a capability ceiling. The agent's signing key is HD-derived from the root
// seed at a stable index, so the Identity Agent can sign on the agent's behalf
// (the IA-mediated model — the agent never holds standalone signing authority).
//
// The agent gets its OWN verifiable AID chained to the owner's root, so every
// action it takes through the endpoint is provably "owner -> this agent" in the
// signed invocation log.
func (h *Handler) ProvisionAgentAsset(displayName string, capabilities []string, cfg *AgentConfig, validUntil *time.Time, constraints map[string]interface{}) (*Asset, error) {
	return h.provisionDelegated(delegatedAsset{
		assetType: "ai_agent", noun: "agent", originScheme: "agent", errTaken: ErrAgentNameTaken,
		displayName: displayName, capabilities: capabilities, cfg: cfg, validUntil: validUntil, constraints: constraints,
	})
}

// ProvisionAppAsset provisions an app as a delegated asset, the same way an AI
// agent is (ProvisionAgentAsset): it mints a delegated AID anchored to the
// owner's root AID, derives the signing key from the root seed at a stable
// index, and stores the app with its capability ceiling and the argument limits
// of its grant. The grant itself is issued by the caller, from the owner's
// registry, as an App Grant (ADR-045, Amendment 1).
//
// An app has no brain, so unlike an agent it takes no AgentConfig: its grant
// carries only capabilities and resource constraints.
func (h *Handler) ProvisionAppAsset(displayName string, capabilities []string, validUntil *time.Time, constraints map[string]interface{}) (*Asset, error) {
	return h.provisionDelegated(delegatedAsset{
		assetType: "app", noun: "app", originScheme: "app", errTaken: ErrAppNameTaken,
		displayName: displayName, capabilities: capabilities, validUntil: validUntil, constraints: constraints,
	})
}

// delegatedAsset is what differs between the kinds of asset that are minted as
// a delegated identifier with a capability ceiling. Everything else about
// provisioning one is the same, and is written once in provisionDelegated.
type delegatedAsset struct {
	assetType    string // "ai_agent" or "app"
	noun         string // how an error names it
	originScheme string
	errTaken     error
	displayName  string
	capabilities []string
	cfg          *AgentConfig
	validUntil   *time.Time
	constraints  map[string]interface{}
}

func (h *Handler) provisionDelegated(d delegatedAsset) (*Asset, error) {
	displayName := strings.TrimSpace(d.displayName)
	if displayName == "" {
		return nil, fmt.Errorf("%s display name is required", d.noun)
	}
	// Held from the name check to the stored asset, so two requests for the same
	// name cannot both pass the check before either is stored.
	provisionMu.Lock()
	defer provisionMu.Unlock()
	taken, err := h.delegatedNameTaken(displayName)
	if err != nil {
		return nil, err
	}
	if taken {
		return nil, fmt.Errorf("%w: %q", d.errTaken, displayName)
	}
	// What the grant would say is checked before anything is minted or issued,
	// for an app and an AI agent alike: a grant that could never be in force, or
	// that records a limit nothing enforces, is refused here, not issued.
	if err := checkGrantAsked(d.noun, d.capabilities, d.validUntil, d.constraints); err != nil {
		return nil, err
	}
	rootAID := ""
	if h.RootAID != nil {
		rootAID = h.RootAID()
	}
	if rootAID == "" {
		return nil, fmt.Errorf("delegated %s identity requires a root identity — complete identity setup first", d.noun)
	}
	if h.KeriDriver == nil {
		return nil, fmt.Errorf("keri driver required to mint the delegated %s AID", d.noun)
	}

	if err := h.mayDelegate(); err != nil {
		return nil, err
	}
	id := genID()
	signingIndex := signingIndexForID(id)
	pub, nextPub, err := deriveAssetKeypair(h.dataDir, signingIndex)
	if err != nil {
		return nil, fmt.Errorf("derive %s key: %w", d.noun, err)
	}
	resp, err := h.KeriDriver.CreateDelegatedInception(
		iacrypto.VerkeyQB64(pub), iacrypto.VerkeyQB64(nextPub), displayName, rootAID)
	if err != nil {
		return nil, fmt.Errorf("mint delegated %s AID: %w", d.noun, err)
	}
	// Persist the owner-root anchoring event, or the asset's delegation won't
	// survive a KEL reload and its capability grant will never verify.
	if err := h.persistDelegationAnchor(rootAID, resp); err != nil {
		return nil, fmt.Errorf("persist delegation anchor: %w", err)
	}

	now := time.Now().UTC()
	asset := Asset{
		ID:               id,
		DisplayName:      displayName,
		AssetType:        d.assetType,
		Origin:           d.originScheme + "://" + id,
		PairwiseAID:      resp.AID,
		DelegationModel:  "delegated",
		DelegatorAID:     resp.DelegatorAID,
		SigningIndex:     signingIndex,
		Capabilities:     d.capabilities,
		AgentConfig:      d.cfg,
		GrantValidUntil:  d.validUntil,
		GrantConstraints: d.constraints,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	h.Store.UpsertAsset(asset)
	return &asset, nil
}

// ErrAgentNameTaken refuses a second AI agent with a name already in use,
// whether by an AI agent or by an app (see delegatedNameTaken).
//
// The name is not only a label. The KERI engine keys the identities it holds
// by it, and an agent's token is filed under it, so two agents sharing a name
// would share the engine's record of one identity and revoking either token
// by name would revoke both. Names are compared trimmed and without case,
// because two agents a person cannot tell apart on screen are the same mistake.
var ErrAgentNameTaken = errors.New("an AI agent with that name already exists")

// ErrAppNameTaken refuses a second app, or an app named as an AI agent already
// is, for the reason ErrAgentNameTaken gives: the engine keys the identities it
// holds by name, whatever kind of asset they are.
var ErrAppNameTaken = errors.New("an app or AI agent with that name already exists")

var provisionMu sync.Mutex

// delegatedNameTaken reports whether any AI agent or app already has the name.
// They share the engine's namespace, so a name is taken across both.
// An unreadable store is an error, never "not taken": answering false would let
// a duplicate name through.
func (h *Handler) delegatedNameTaken(name string) (bool, error) {
	assets, err := h.Store.ListAssets()
	if err != nil {
		return false, err
	}
	for _, a := range assets {
		if (a.AssetType == "ai_agent" || a.AssetType == "app") && SameAgentName(a.DisplayName, name) {
			return true, nil
		}
	}
	return false, nil
}

// SameAgentName is how two AI agent names are compared everywhere: trimmed,
// and without case, because two names a person cannot tell apart on screen
// must not name two agents.
func SameAgentName(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// UpdateAgentConfig replaces the operational config of an existing ai_agent asset
// (role, prompt, brain, exposure) without touching its identity or grant. Returns
// the updated asset, or an error if it isn't an ai_agent.
func (h *Handler) UpdateAgentConfig(assetID string, cfg *AgentConfig) (*Asset, error) {
	a, ok, err := h.Store.GetAsset(assetID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("agent not found")
	}
	if a.AssetType != "ai_agent" {
		return nil, fmt.Errorf("asset %s is not an ai_agent", assetID)
	}
	a.AgentConfig = cfg
	a.UpdatedAt = time.Now().UTC()
	h.Store.UpsertAsset(a)
	return &a, nil
}

// SetAgentCapabilities replaces an agent's capability ceiling.
//
// A ceiling could only be set at provisioning, which meant granting an existing
// agent one more capability required minting a whole new identity — a new AID, a
// new token, and an audit trail that no longer connects to what that agent did
// yesterday. Re-provisioning to widen a grant loses the very continuity the
// delegated identity exists to provide.
//
// Replacing rather than merging is deliberate. A ceiling is the full statement of
// what an agent may do, so an owner editing one should see the whole list and say
// what it becomes. An add-only call reads as harmless and is how ceilings quietly
// grow: every caller adds, nobody subtracts, and after a while nobody can say why
// an agent holds what it holds.
func (h *Handler) SetAgentCapabilities(assetID string, caps []string) (*Asset, error) {
	a, ok, err := h.Store.GetAsset(assetID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("agent not found")
	}
	if a.AssetType != "ai_agent" {
		return nil, fmt.Errorf("asset %s is not an ai_agent", assetID)
	}
	a.Capabilities = NormaliseCapabilities(caps)
	a.UpdatedAt = time.Now().UTC()
	if err := h.Store.UpsertAsset(a); err != nil {
		return nil, fmt.Errorf("persisting ceiling: %w", err)
	}
	return &a, nil
}

// NormaliseCapabilities trims, de-duplicates and sorts a ceiling, so it cannot
// silently contain duplicates or blanks, either of which make a later diff of
// "what changed" harder to read than it should be.
func NormaliseCapabilities(caps []string) []string {
	seen := map[string]bool{}
	clean := make([]string, 0, len(caps))
	for _, c := range caps {
		c = strings.TrimSpace(c)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		clean = append(clean, c)
	}
	sort.Strings(clean)
	return clean
}

// SetAgentGrantConstraints replaces the argument limits recorded for an AI
// agent's grant. The grant itself is re-issued by the caller.
func (h *Handler) SetAgentGrantConstraints(assetID string, constraints map[string]interface{}) (*Asset, error) {
	a, ok, err := h.Store.GetAsset(assetID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("agent not found")
	}
	if a.AssetType != "ai_agent" {
		return nil, fmt.Errorf("asset %s is not an ai_agent", assetID)
	}
	a.GrantConstraints = constraints
	a.UpdatedAt = time.Now().UTC()
	if err := h.Store.UpsertAsset(a); err != nil {
		return nil, fmt.Errorf("persisting constraints: %w", err)
	}
	return &a, nil
}

// ListAgents returns all ai_agent assets (owner-only surface; contains no secrets).
func (h *Handler) ListAgents() ([]Asset, error) {
	assets, err := h.Store.ListAssets()
	if err != nil {
		return nil, err
	}
	out := make([]Asset, 0)
	for _, a := range assets {
		if a.AssetType == "ai_agent" {
			out = append(out, a)
		}
	}
	return out, nil
}
