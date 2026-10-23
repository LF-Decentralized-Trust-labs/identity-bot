package server

// Machines paired, and AI agents provisioned, before every one of them was
// given a grant are given one afterwards. What they are given must not come
// from a file anybody who can write the data directory can edit: that would
// turn a write to a file into a grant the identity signed.
//
// So the first time this version runs where the identity's key is held, it
// writes one interaction into the identity's own key log that seals what
// existed then: every machine without a grant and every AI agent without one,
// exactly as each stood. The list itself is kept beside the database; its
// digest is in the key log, which nobody without the key can extend or
// rewrite. From then on a grant is given afterwards only to a machine or an
// AI agent that matches that list exactly. Anything added or widened since
// waits for the identity's own signature, given the ordinary way.
//
// The interaction is recognised by a marker seal anybody can recompute, so a
// snapshot is never taken twice, even after the list kept beside the database
// is removed: the identity's key log says one was taken, and without the list
// that matches it nothing is given at all.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
)

const earlierGrantsFile = "earlier_grants_snapshot.json"

// earlierGrants is what existed, without grants, when the snapshot was taken.
type earlierGrants struct {
	Identity    string           `json:"identity"`
	Controllers []earlierMachine `json:"controllers"`
	Agents      []earlierAIAgent `json:"agents"`
	TakenAt     string           `json:"taken_at"`
}

type earlierMachine struct {
	AID       string `json:"aid"`
	PublicKey string `json:"public_key"`
	Label     string `json:"label"`
	Grade     string `json:"grade"`
	Signer    string `json:"signer,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type earlierAIAgent struct {
	AssetID      string                 `json:"asset_id"`
	AgentAID     string                 `json:"agent_aid"`
	DelegatorAID string                 `json:"delegator_aid"`
	Name         string                 `json:"name"`
	Capabilities []string               `json:"capabilities"`
	Constraints  map[string]interface{} `json:"constraints,omitempty"`
	ValidUntil   string                 `json:"valid_until,omitempty"`
}

func machineAsItStands(g ControllerGrant) earlierMachine {
	m := earlierMachine{AID: g.ControllerAID, PublicKey: g.PublicKey, Label: g.Label, Grade: string(g.Grade), Signer: g.Signer}
	if !g.ExpiresAt.IsZero() {
		m.ExpiresAt = g.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return m
}

func agentAsItStands(a asset.Asset) earlierAIAgent {
	caps := append([]string{}, a.Capabilities...)
	sort.Strings(caps)
	e := earlierAIAgent{AssetID: a.ID, AgentAID: a.PairwiseAID, DelegatorAID: a.DelegatorAID, Name: a.DisplayName,
		Capabilities: caps, Constraints: a.GrantConstraints}
	if a.GrantValidUntil != nil {
		e.ValidUntil = a.GrantValidUntil.UTC().Format(time.RFC3339)
	}
	return e
}

func sameJSONValue(a, b interface{}) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// earlierGrantsMarker is the seal that says a snapshot was taken for this
// identity: anybody can compute it, so it is found without the list.
func earlierGrantsMarker(identity string) string {
	return iacrypto.Blake3QB64Must([]byte("identity-agent/earlier-grants-snapshot/v1\n" + identity))
}

// anchoredEarlierGrants finds the snapshot in the identity's key log: whether
// one was taken, and the digest of the list it sealed.
func (s *CoreServer) anchoredEarlierGrants(identity string) (taken bool, digest string, err error) {
	events, err := s.DataStore.GetEvents(identity)
	if err != nil {
		return false, "", err
	}
	marker := earlierGrantsMarker(identity)
	for _, ev := range events {
		raw, _ := base64.StdEncoding.DecodeString(ev.RawBytesB64)
		var parsed map[string]interface{}
		if json.Unmarshal(raw, &parsed) != nil || parsed["t"] != "ixn" {
			continue
		}
		seals, _ := parsed["a"].([]interface{})
		if len(seals) != 2 {
			continue
		}
		first, _ := seals[0].(map[string]interface{})
		second, _ := seals[1].(map[string]interface{})
		if first == nil || second == nil || first["d"] != marker {
			continue
		}
		d, _ := second["d"].(string)
		return true, d, nil
	}
	return false, "", nil
}

// earlierGrantsSnapshot is the snapshot that grants given afterwards rest on,
// taking it if it has never been taken and the identity's key is held here.
// It returns false where there is none to rest on: never taken, or the list
// kept here no longer matches the digest the key log sealed.
func (s *CoreServer) earlierGrantsSnapshot() (earlierGrants, bool) {
	s.earlierGrantsMu.Lock()
	defer s.earlierGrantsMu.Unlock()
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return earlierGrants{}, false
	}
	taken, digest, err := s.anchoredEarlierGrants(identity.AID)
	if err != nil {
		return earlierGrants{}, false
	}
	if !taken {
		snap, err := s.takeEarlierGrantsSnapshot(identity.AID)
		if err != nil {
			if err != errKeyElsewhere {
				log.Printf("[grants] what existed before grants could not be sealed, so nothing is given a grant afterwards: %v", err)
			}
			return earlierGrants{}, false
		}
		return snap, true
	}
	raw, err := os.ReadFile(filepath.Join(s.DataDir, earlierGrantsFile))
	if err != nil || iacrypto.Blake3QB64Must(raw) != digest {
		log.Printf("[grants] the list of what existed before grants does not match what the key log sealed; nothing is given a grant afterwards")
		return earlierGrants{}, false
	}
	var snap earlierGrants
	if json.Unmarshal(raw, &snap) != nil || snap.Identity != identity.AID {
		return earlierGrants{}, false
	}
	return snap, true
}

// takeEarlierGrantsSnapshot seals what exists now without grants. The list is
// written before the interaction, so the interaction never seals a list that
// is not kept; a list kept whose interaction was never written matches
// nothing, and the next attempt replaces it.
func (s *CoreServer) takeEarlierGrantsSnapshot(identity string) (earlierGrants, error) {
	if _, err := s.identitySigningSeed(); err != nil {
		return earlierGrants{}, errKeyElsewhere
	}
	snap := earlierGrants{Identity: identity, Controllers: []earlierMachine{}, Agents: []earlierAIAgent{}, TakenAt: time.Now().UTC().Format(time.RFC3339)}
	// Started without an identity: everything it holds was made by this
	// version, which grants at pairing and provisioning, so nothing is owed a
	// grant afterwards, whatever the files say by now.
	if s.startedWithoutIdentity {
		return s.sealEarlierGrants(identity, snap)
	}
	if all, err := s.controllers().All(); err == nil {
		for _, g := range all {
			if g.CredentialSAID == "" && !g.CredentialPending {
				snap.Controllers = append(snap.Controllers, machineAsItStands(g))
			}
		}
	} else {
		return earlierGrants{}, err
	}
	if s.assetHandler != nil && s.assetHandler.Store != nil {
		mcpTokensMu.Lock()
		toks := s.loadMCPTokens()
		mcpTokensMu.Unlock()
		seen := map[string]bool{}
		for _, t := range toks {
			if t.AgentAID == "" || t.GrantSAID != "" || t.AssetID == "" || seen[t.AssetID] {
				continue
			}
			if a, ok := s.assetHandler.Store.GetAsset(t.AssetID); ok {
				seen[t.AssetID] = true
				snap.Agents = append(snap.Agents, agentAsItStands(a))
			}
		}
	}
	return s.sealEarlierGrants(identity, snap)
}

func (s *CoreServer) sealEarlierGrants(identity string, snap earlierGrants) (earlierGrants, error) {
	keeper, ok := s.KeriDriver.(drivers.KELKeeper)
	if !ok {
		return earlierGrants{}, fmt.Errorf("this Identity Agent cannot keep a key log")
	}
	sort.Slice(snap.Controllers, func(i, j int) bool { return snap.Controllers[i].AID < snap.Controllers[j].AID })
	sort.Slice(snap.Agents, func(i, j int) bool { return snap.Agents[i].AssetID < snap.Agents[j].AssetID })
	raw, err := json.Marshal(snap)
	if err != nil {
		return earlierGrants{}, err
	}
	path := filepath.Join(s.DataDir, earlierGrantsFile)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return earlierGrants{}, err
	}
	seals := []interface{}{
		map[string]interface{}{"d": earlierGrantsMarker(identity)},
		map[string]interface{}{"d": iacrypto.Blake3QB64Must(raw)},
	}
	keep := func(k drivers.KELKeep) error {
		var ixn map[string]interface{}
		if err := json.Unmarshal(k.Raw, &ixn); err != nil {
			return err
		}
		rec, err := s.ownInteractionRecord(identity, ixn, base64.StdEncoding.EncodeToString(k.Raw), k.SN, "")
		if err != nil {
			return err
		}
		return s.DataStore.SaveEvent(rec)
	}
	if _, err := keeper.InteractKept(identity, seals, keep); err != nil {
		return earlierGrants{}, fmt.Errorf("the snapshot could not be sealed in the key log: %w", err)
	}
	log.Printf("[grants] sealed %d machine(s) and %d AI agent(s) that existed before grants", len(snap.Controllers), len(snap.Agents))
	return snap, nil
}

// machineIsInSnapshot reports whether g is, exactly, a machine the snapshot
// sealed. A signer bound since, where the snapshot named none, is the one
// change allowed: it is set from the identity's own signers, never from the
// row.
func (snap earlierGrants) machineIsInSnapshot(g ControllerGrant) bool {
	now := machineAsItStands(g)
	for _, m := range snap.Controllers {
		if m.AID != now.AID {
			continue
		}
		if m.Signer == "" {
			now.Signer = ""
		}
		return m == now
	}
	return false
}

// agentInSnapshot is the AI agent, as the snapshot sealed it, when a stands
// exactly as it did then.
func (snap earlierGrants) agentInSnapshot(a asset.Asset) bool {
	now := agentAsItStands(a)
	for _, e := range snap.Agents {
		if e.AssetID == now.AssetID {
			return sameJSONValue(e, now)
		}
	}
	return false
}
