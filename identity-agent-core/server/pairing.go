package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/store"
)

// Adopting an agent that is not yours yet.
//
// A freshly provisioned instance has no identity and no owner. Somebody has to
// adopt it, and the way they do it decides everything about what renting
// hardware means.
//
// The wrong way is the obvious one: hand the box your root seed and let it act
// as you. It works, it is one HTTP call, and it means your root key now lives
// on hardware somebody else owns. There is no recovering from that — not by
// unpairing, not by deleting the instance.
//
// So the box never receives a key. It generates its own, hands out only the
// public half, and the controller issues a KERI delegated inception (`dip`)
// naming that key, anchored in the controller's own KEL. The box ends up able
// to sign for itself and independently revocable; the root never moves.
//
// Two calls, both reachable before an owner exists because that is the only
// moment they are for, and both refused the instant one succeeds.

type pairingBeginResponse struct {
	// PairwiseAID is the identity the box published for discovery, echoed so a
	// controller can confirm it is adopting the box it resolved.
	PairwiseAID string `json:"pairwise_aid"`
	// PublicKey and NextPublicKey are the box's own delegated key material.
	// Public halves only — the private keys never leave the instance, which is
	// the entire point of the ceremony.
	PublicKey     string `json:"public_key"`
	NextPublicKey string `json:"next_public_key"`
}

type pairingCompleteRequest struct {
	// DipEvent is the delegated inception the controller issued over the key
	// material from begin.
	DipEvent map[string]interface{} `json:"dip_event"`
	// DelegatorIxn is the controller's interaction event anchoring the
	// delegation in its own KEL — what makes the delegation verifiable by a
	// third party rather than merely asserted here.
	DelegatorIxn map[string]interface{} `json:"delegator_ixn,omitempty"`
	// DelegatorAID is the controller's root AID.
	DelegatorAID string `json:"delegator_aid"`
	// AdoptionCode is the one-time code this instance issued with its pairing
	// offer. Without it, whoever reaches an unadopted box first takes it.
	AdoptionCode string `json:"adoption_code"`
	// OwnerAID and OwnerPublicKey become the owner authority: whose signature
	// this instance will accept as its owner's from now on.
	OwnerAID       string `json:"owner_aid"`
	OwnerPublicKey string `json:"owner_public_key"`
	// BackupSealPublicKeyB64 is the X25519 public key this instance seals its
	// backup keys to, so it can write archives it cannot itself read.
	//
	// It arrives here rather than being configured afterwards because the gap
	// between the two is the one window where an instance is running, holding
	// real data, and unable to back any of it up safely. There is no reason to
	// have that window: the owner is already talking to it, and already has the
	// key. For an identity with several owners this carries one key per owner,
	// any of whom can then restore alone.
	BackupSealPublicKeysB64 []string `json:"backup_seal_public_keys_b64,omitempty"`
}

// pairingState holds the key material offered by begin, so complete can check
// the delegation was issued over it. Process-wide: an instance is adopted once.
var pairingState struct {
	sync.Mutex
	offered *pairingBeginResponse
	// seed is the private half, kept only in memory between the two calls.
	seed []byte
}

// handlePairingBegin generates this instance's delegated key material and hands
// out the public halves.
func (s *CoreServer) handlePairingBegin(w http.ResponseWriter, r *http.Request) {
	if err := s.refuseIfAlreadyPaired(w); err != nil {
		return
	}

	pairingState.Lock()
	defer pairingState.Unlock()

	// Offer the same material twice rather than generating fresh keys on a
	// retry: a controller that retried would otherwise issue a delegation over
	// a key the box had already replaced, and the box would refuse its own
	// adoption.
	if pairingState.offered != nil {
		writeJSONResponse(w, pairingState.offered)
		return
	}

	rootSeed, err := ensureRootSeed(s.DataDir)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "No key material", err.Error())
		return
	}
	// Derived, not random: the delegated key is recoverable from this
	// instance's own backup, so adoption survives the instance being restored.
	idx, err := s.DataStore.AllocateNextRelationshipIndex("delegated-identity")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not allocate a key index", err.Error())
		return
	}
	seed, err := backup.DerivePairwiseSeed(rootSeed, idx, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not derive a key", err.Error())
		return
	}
	nextSeed, err := backup.DerivePairwiseSeed(rootSeed, idx, 1)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not derive a rotation key", err.Error())
		return
	}

	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	nextPub := ed25519.NewKeyFromSeed(nextSeed).Public().(ed25519.PublicKey)

	offer := &pairingBeginResponse{
		PublicKey:     iacrypto.VerkeyQB64(pub),
		NextPublicKey: iacrypto.VerkeyQB64(nextPub),
	}
	pairingOnce.Lock()
	if pairingOnce.offer != nil {
		offer.PairwiseAID = pairingOnce.offer.AID
	}
	pairingOnce.Unlock()

	pairingState.offered = offer
	pairingState.seed = seed
	writeJSONResponse(w, offer)
}

// handlePairingComplete accepts the delegation and seals the owner.
//
// This is the moment an instance stops being nobody's, so every check here is
// about one question: is this delegation actually over the key this box just
// generated, from the party claiming to have issued it?
func (s *CoreServer) handlePairingComplete(w http.ResponseWriter, r *http.Request) {
	if err := s.refuseIfAlreadyPaired(w); err != nil {
		return
	}

	var req pairingCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	pairingState.Lock()
	defer pairingState.Unlock()
	if pairingState.offered == nil {
		writeError(w, http.StatusConflict, "Nothing to complete",
			"call /api/pairing/begin first — there is no key material to delegate over")
		return
	}

	// Check the code before anything else is considered. An instance that
	// validated a delegation first would leak whether the delegation was
	// well-formed to somebody with no standing to ask.
	expected := expectedAdoptionCode()
	if expected == "" {
		writeError(w, http.StatusConflict, "Not offered for pairing",
			"this instance has not published a pairing offer, so there is no adoption to complete")
		return
	}
	if subtle.ConstantTimeCompare([]byte(expected), []byte(req.AdoptionCode)) != 1 {
		writeError(w, http.StatusForbidden, "Wrong adoption code",
			"this instance was provisioned for somebody, and adopting it needs the code issued with that provisioning")
		return
	}

	if err := validateDelegation(req, pairingState.offered.PublicKey); err != nil {
		writeError(w, http.StatusBadRequest, "Delegation refused", err.Error())
		return
	}

	delegatedAID, _ := req.DipEvent["i"].(string)
	eventJSON, _ := json.Marshal(req.DipEvent)
	now := time.Now().UTC().Format(time.RFC3339)

	if err := s.DataStore.SaveEvent(store.EventRecord{
		AID:            delegatedAID,
		SequenceNumber: 0,
		EventType:      "dip",
		EventJSON:      string(eventJSON),
		PublicKey:      pairingState.offered.PublicKey,
		Timestamp:      now,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Could not persist the delegation", err.Error())
		return
	}
	if err := s.DataStore.SaveIdentity(store.IdentityState{
		AID:        delegatedAID,
		PublicKey:  pairingState.offered.PublicKey,
		Created:    now,
		EventCount: 1,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Could not persist the identity", err.Error())
		return
	}

	// Seal the owner in the same act. An instance that held a delegation but no
	// owner would be adopted and unadministrable — and a later, separate call
	// to name the owner is a window somebody else could step into.
	if err := s.SealOwnerAuthority(OwnerAuthority{
		AID:       req.OwnerAID,
		PublicKey: req.OwnerPublicKey,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Could not seal the owner", err.Error())
		return
	}

	// Record who this instance seals its backups to, in the same act for the
	// same reason as the owner above.
	//
	// A failure here does not undo the adoption. The instance is legitimately
	// adopted at this point and refusing it now would leave it delegated but
	// ownerless, which is worse than adopted but not yet backing up. It is
	// logged loudly instead, because an agent that cannot back up is a real
	// problem — just not one worth throwing away a valid adoption for.
	if len(req.BackupSealPublicKeysB64) > 0 {
		if err := s.recordBackupSealKeys(req.BackupSealPublicKeysB64); err != nil {
			log.Printf("[pairing] WARNING: adopted, but the recovery keys were refused (%v) — this instance cannot back up until they are set", err)
		}
	} else {
		log.Printf("[pairing] WARNING: adopted with no recovery key — this instance can only back up by being handed a seed phrase, which is what having a recovery key avoids")
	}

	// The private half has done its work; the identity is persisted and the key
	// is re-derivable from this instance's own seed.
	pairingState.seed = nil

	log.Printf("[pairing] adopted: delegated AID %s under delegator %s, owner %s",
		delegatedAID, req.DelegatorAID, req.OwnerAID)

	writeJSONResponse(w, map[string]interface{}{
		"ok":            true,
		"delegated_aid": delegatedAID,
		"delegator_aid": req.DelegatorAID,
		"owner_aid":     req.OwnerAID,
	})
}

// validateDelegation checks the delegation is over this instance's key and
// names a real delegator other than itself.
func validateDelegation(req pairingCompleteRequest, offeredPublicKey string) error {
	if req.DipEvent == nil {
		return fmt.Errorf("dip_event is required")
	}
	if t, _ := req.DipEvent["t"].(string); t != "dip" {
		return fmt.Errorf("expected a delegated inception (dip), got %q", t)
	}
	delegatedAID, _ := req.DipEvent["i"].(string)
	if delegatedAID == "" {
		return fmt.Errorf("dip_event has no delegated AID")
	}
	di, _ := req.DipEvent["di"].(string)
	if di == "" {
		return fmt.Errorf("dip_event names no delegator")
	}
	if req.DelegatorAID != "" && di != req.DelegatorAID {
		return fmt.Errorf("dip_event delegates from %s but the request claims %s", di, req.DelegatorAID)
	}
	if di == delegatedAID {
		return fmt.Errorf("an AID cannot delegate to itself")
	}

	// The check that matters: the delegation must be over the key this instance
	// generated. Without it a controller could delegate to a key it holds and
	// hand the box a delegation the box cannot sign with — or worse, one
	// somebody else can.
	keys, _ := req.DipEvent["k"].([]interface{})
	if len(keys) == 0 {
		return fmt.Errorf("dip_event carries no key")
	}
	if first, _ := keys[0].(string); first != offeredPublicKey {
		return fmt.Errorf("the delegation is over a different key than this instance generated")
	}

	if req.OwnerAID == "" || req.OwnerPublicKey == "" {
		return fmt.Errorf("owner_aid and owner_public_key are required: an adopted instance must know whose signature counts as its owner's")
	}
	// One decoder for key material, shared with the owner-signature path, so a
	// key this accepts is exactly a key that path can later verify against.
	if _, err := login.DecodeVerkey(req.OwnerPublicKey); err != nil {
		return fmt.Errorf("owner_public_key: %w", err)
	}
	return nil
}

// refuseIfAlreadyPaired stops a second adoption. First pairing wins, and the
// window closes the moment it does — an instance that could be re-adopted is an
// instance somebody else can take.
func (s *CoreServer) refuseIfAlreadyPaired(w http.ResponseWriter) error {
	if s.DataStore == nil {
		writeError(w, http.StatusServiceUnavailable, "No store", "this instance has no data store")
		return fmt.Errorf("no store")
	}
	identity, err := s.DataStore.GetIdentity()
	if err == nil && identity != nil {
		writeError(w, http.StatusConflict, "Already paired",
			"this instance has an identity; pairing is offered only once, before one exists")
		return fmt.Errorf("already paired")
	}
	return nil
}

func writeJSONResponse(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// resetPairingStateForTest clears the in-memory offer between tests.
func resetPairingStateForTest() {
	pairingState.Lock()
	defer pairingState.Unlock()
	pairingState.offered = nil
	pairingState.seed = nil
}

// --- the controller side: adopting a box ---

// handlePairingAdopt runs the whole ceremony from the owner's agent.
//
// One call from the owner's side, because every step in between is a place a
// user could be asked to do something they cannot check. The controller fetches
// the box's key material, issues the delegation over it, anchors it in its own
// KEL, and hands the box back the result. The box's private key never leaves
// the box; the root key never leaves here.
//
// Owner-only: adopting hardware on somebody's behalf is exactly the authority
// the owner check exists to protect.
func (s *CoreServer) handlePairingAdopt(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BoxURL string `json:"box_url"`
		// AdoptionCode comes from whoever provisioned the box — through the
		// deep link or QR the provisioning page produced. The box will not be
		// adopted without it.
		AdoptionCode string `json:"adoption_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BoxURL == "" {
		writeError(w, http.StatusBadRequest, "Missing box_url",
			"send {\"box_url\": \"http://…\", \"adoption_code\": \"…\"}")
		return
	}
	if s.KeriDriver == nil {
		writeError(w, http.StatusServiceUnavailable, "No KERI engine",
			"issuing a delegation needs the local KERI engine — the root key never leaves this device, so this cannot be done remotely")
		return
	}
	root, err := s.DataStore.GetIdentity()
	if err != nil || root == nil {
		writeError(w, http.StatusConflict, "No identity",
			"this agent has no root identity yet; there is nothing to delegate from")
		return
	}

	base := strings.TrimRight(req.BoxURL, "/")
	client := &http.Client{Timeout: 30 * time.Second}

	// 1. Ask the box for the key it generated for itself.
	offer, err := boxPairingBegin(client, base)
	if err != nil {
		writeError(w, http.StatusBadGateway, "The box did not offer key material", err.Error())
		return
	}

	// 2. Issue the delegation over exactly that key, anchored in our own KEL.
	name := "box-" + shortAID(offer.PairwiseAID)
	// The driver knows an identity by the name it was incepted under, and
	// CreateInception sends none — so the root is registered under its own AID.
	dip, err := s.KeriDriver.CreateDelegatedInception(
		offer.PublicKey, offer.NextPublicKey, name, root.AID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not issue the delegation", err.Error())
		return
	}

	// 3. Hand it back, along with who owns the box from now on: us, and the
	// public key it should seal its backups to.
	//
	// Derived here rather than by the app, because the seed this comes from is
	// already on this device and sending only the public half means the box can
	// write archives forever and open none of them. An app that computed it
	// would need the seed in a second place to do so.
	sealKeys, err := s.ownerBackupSealPublicKeys()
	if err != nil {
		// Adopting a box that cannot back up would be handing somebody a
		// machine that quietly accumulates data it can never restore.
		writeError(w, http.StatusInternalServerError, "Could not derive the recovery key",
			"the box would have been adopted with no way to back up: "+err.Error())
		return
	}

	result, err := boxPairingComplete(client, base, pairingCompleteRequest{
		AdoptionCode:            req.AdoptionCode,
		DipEvent:                dip.DipEvent,
		DelegatorIxn:            dip.DelegatorIxn,
		DelegatorAID:            root.AID,
		OwnerAID:                root.AID,
		OwnerPublicKey:          root.PublicKey,
		BackupSealPublicKeysB64: sealKeys,
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "The box refused the delegation", err.Error())
		return
	}

	log.Printf("[pairing] adopted box at %s: delegated AID %s under root %s", base, dip.AID, root.AID)
	writeJSONResponse(w, map[string]interface{}{
		"ok": true, "box_url": base,
		"delegated_aid": dip.AID, "delegator_aid": root.AID,
		"box_pairwise_aid": offer.PairwiseAID, "box_response": result,
	})
}

func boxPairingBegin(client *http.Client, base string) (*pairingBeginResponse, error) {
	resp, err := client.Post(base+"/api/pairing/begin", "application/json", strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var offer pairingBeginResponse
	if err := json.NewDecoder(resp.Body).Decode(&offer); err != nil {
		return nil, err
	}
	if offer.PublicKey == "" {
		return nil, fmt.Errorf("the box offered no key")
	}
	return &offer, nil
}

func boxPairingComplete(client *http.Client, base string, body pairingCompleteRequest) (map[string]interface{}, error) {
	raw, _ := json.Marshal(body)
	resp, err := client.Post(base+"/api/pairing/complete", "application/json", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 400))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out, nil
}

func shortAID(aid string) string {
	if len(aid) > 8 {
		return aid[:8]
	}
	return aid
}
