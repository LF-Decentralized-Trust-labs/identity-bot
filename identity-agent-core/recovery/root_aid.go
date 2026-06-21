package recovery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"identity-agent-core/store"
)

const (
	rootAIDMapFileName      = "root_aid_map.json"
	continuityProofVersion  = "2"
	rootAIDRotationTaskType = "root_aid_rotation_notify"
)

// RootAIDRotationEnabled gates break-glass rotation until the signed old→new
// delegation anchor mechanism is reviewed and explicitly enabled.
var RootAIDRotationEnabled = false

// RootAIDRotationRequest is the break-glass root-AID rotation payload.
type RootAIDRotationRequest struct {
	RecoverySessionID    string   `json:"recovery_session_id"`
	NewRootPublicKey     string   `json:"new_root_public_key"`
	NewRootNextPublicKey string   `json:"new_root_next_public_key"`
	// PreRotationPublicKey reveals the old root's pre-committed next key in the
	// authorization rotation (signed by that pre-rotated key, not the compromised current key).
	PreRotationPublicKey     string `json:"pre_rotation_public_key"`
	PreRotationNextPublicKey string `json:"pre_rotation_next_public_key"`
	// AuthorizationCesrSignature is the CESR Cigar over the authorization rot event
	// raw bytes, produced by signing with the pre-rotated key then /cesr-encode.
	AuthorizationCesrSignature string `json:"authorization_cesr_signature"`
	// BackAnchorCesrSignature optionally signs the secondary new→old IXN back-reference.
	BackAnchorCesrSignature string `json:"back_anchor_cesr_signature,omitempty"`
	WitnessThreshold        int      `json:"witness_threshold,omitempty"`
	CarryForwardAIDs        []string `json:"carry_forward_aids,omitempty"`
	UseHybridInception      bool     `json:"use_hybrid_inception,omitempty"`
	HybridSynthetic         bool     `json:"hybrid_synthetic,omitempty"`
}

// ContinuityProof documents the old-root-signed delegation anchor authorizing the
// new root inception. The trust gate is the CESR signature on the authorization
// event verifiable against the old KEL — not a standalone content digest.
type ContinuityProof struct {
	V                          string                 `json:"v"`
	OldRootAID                 string                 `json:"old_root_aid"`
	NewRootAID                 string                 `json:"new_root_aid"`
	NewInceptionSAID           string                 `json:"new_inception_said"`
	AuthorizationEvent         map[string]interface{} `json:"authorization_event"`
	AuthorizationCesrSignature string                 `json:"authorization_cesr_signature"`
	AuthorizationEventSAID     string                 `json:"authorization_event_said"`
	BackAnchorEvent            map[string]interface{} `json:"back_anchor_event,omitempty"`
	BackAnchorCesrSignature    string                 `json:"back_anchor_cesr_signature,omitempty"`
	BackAnchorEventSAID        string                 `json:"back_anchor_event_said,omitempty"`
	PriorKelTailSAID           string                 `json:"prior_kel_tail_said,omitempty"`
	RotatedAt                  string                 `json:"rotated_at"`
	RecoverySessionID          string                 `json:"recovery_session_id,omitempty"`
	CarryForwardAIDs           []string               `json:"carry_forward_aids,omitempty"`
	WitnessThreshold           int                    `json:"witness_threshold,omitempty"`
}

// RootAIDMapEntry records one break-glass rotation in local history.
type RootAIDMapEntry struct {
	OldRootAID                 string `json:"old_root_aid"`
	NewRootAID                 string `json:"new_root_aid"`
	NewInceptionSAID           string `json:"new_inception_said"`
	AuthorizationEventSAID     string `json:"authorization_event_said"`
	AuthorizationCesrSignature string `json:"authorization_cesr_signature"`
	BackAnchorEventSAID        string `json:"back_anchor_event_said,omitempty"`
	PriorKelTailSAID           string `json:"prior_kel_tail_said,omitempty"`
	RotatedAt                  string `json:"rotated_at"`
	RecoverySessionID          string `json:"recovery_session_id,omitempty"`
}

// RootAIDMap is persisted at <dataDir>/root_aid_map.json.
type RootAIDMap struct {
	Version int               `json:"version"`
	Entries []RootAIDMapEntry `json:"entries"`
}

// RootAIDRotationResult contains the new root KEL state and notify outcomes.
type RootAIDRotationResult struct {
	Status             string          `json:"status"`
	Message            string          `json:"message"`
	OldRootAID         string          `json:"old_root_aid"`
	NewRootAID         string          `json:"new_root_aid"`
	ContinuityProof    ContinuityProof `json:"continuity_proof"`
	NotifySet          NotifySet       `json:"notify_set"`
	CarriedForwardAIDs []string        `json:"carried_forward_aids"`
	NotificationsSent  int             `json:"notifications_sent"`
}

// KeriInceptionResult is the subset of driver inception output used by rotation.
type KeriInceptionResult struct {
	AID            string
	PublicKey      string
	NextKeyDigest  string
	InceptionEvent map[string]interface{}
	InceptionSAID  string
	SequenceNumber int
}

// KeriRotationResult is the subset of driver rotation output used by rotation.
type KeriRotationResult struct {
	AID              string
	NewPublicKey     string
	NewNextKeyDigest string
	RotationEvent    map[string]interface{}
	RotationSAID     string
	RawBytesB64      string
	SequenceNumber   int
}

// KeriInteractResult is the subset of driver IXN output used by rotation.
type KeriInteractResult struct {
	AID            string
	IxnEvent       map[string]interface{}
	Said           string
	SequenceNumber int
}

// KeriDriverPort is the KERI surface required for break-glass root rotation.
type KeriDriverPort interface {
	CreateInception(publicKey, nextPublicKey string) (*KeriInceptionResult, error)
	CreateHybridInception(synthetic bool, name string) (*KeriInceptionResult, error)
	RotateWithAnchor(name, newPublicKey, newNextPublicKey string, anchorData []interface{}) (*KeriRotationResult, error)
	Interact(name string, data []interface{}) (*KeriInteractResult, error)
}

// RootRotationStore is the persistence surface required for break-glass root rotation.
type RootRotationStore interface {
	NotifySetSource
	GetEvents(aid string) ([]store.EventRecord, error)
	SaveEvent(record store.EventRecord) error
	SaveIdentity(state store.IdentityState) error
	SaveTask(task store.TaskRecord) error
}

// RootAIDRotationService performs break-glass root-AID rotation after recovery.
type RootAIDRotationService struct {
	DataDir string
	Now     func() time.Time
}

func NewRootAIDRotationService(dataDir string) *RootAIDRotationService {
	return &RootAIDRotationService{
		DataDir: dataDir,
		Now:     func() time.Time { return time.Now().UTC() },
	}
}

// RotateRootAID mints a new root AID and proves continuity via an old-root-signed
// delegation anchor.
//
// KERI anchoring mechanism (v2 — for Rob review):
//
//  1. Mint fresh root via driver CreateInception (new ICP, sn=0) → new_inception_said.
//  2. On the OLD root prefix, emit a rot event that reveals the pre-committed next
//     key (signed by that pre-rotated key) with seal data [{"d":"<new_inception_said>"}]
//     in the rot's `a` field (keripy eventing.rotate data=…). This is the mandatory
//     old→new authorization verifiable against the notify-set's copy of the old KEL.
//  3. Optional secondary: new-root IXN back-reference sealing prior_kel_tail_said
//     (bidirectional link only; never substitutes for step 2).
//
// Security boundary: if both the old current key AND its pre-rotation next key are
// compromised, root-level break-glass cannot help — guardians/social recovery take over.
func (s *RootAIDRotationService) RotateRootAID(
	req RootAIDRotationRequest,
	driver KeriDriverPort,
	st RootRotationStore,
	watcherHints []string,
) (*RootAIDRotationResult, error) {
	if !RootAIDRotationEnabled {
		return nil, fmt.Errorf("root-AID rotation is gated pending security review of the signed delegation anchor")
	}
	if err := validateRootAIDRotationRequest(req); err != nil {
		return nil, err
	}
	if driver == nil {
		return nil, fmt.Errorf("KERI driver is required for root-AID rotation")
	}
	if st == nil {
		return nil, fmt.Errorf("identity store is required for root-AID rotation")
	}

	identity, err := st.GetIdentity()
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}
	if identity == nil || identity.AID == "" {
		return nil, fmt.Errorf("no existing root identity to rotate")
	}
	oldRootAID := identity.AID

	priorTailSAID, err := kelTailSAID(st, oldRootAID)
	if err != nil {
		return nil, err
	}

	inception, err := s.mintNewRoot(driver, req)
	if err != nil {
		return nil, err
	}
	newRootAID := inception.AID
	newInceptionSAID := inception.InceptionSAID
	if newInceptionSAID == "" {
		return nil, fmt.Errorf("new root inception missing SAID")
	}

	authAnchor := BuildDelegationAnchorSeal(newInceptionSAID)
	rot, err := driver.RotateWithAnchor(
		oldRootAID,
		req.PreRotationPublicKey,
		req.PreRotationNextPublicKey,
		authAnchor,
	)
	if err != nil {
		return nil, fmt.Errorf("old-root authorization rotation: %w", err)
	}
	if err := ValidateAuthorizationEvent(oldRootAID, newInceptionSAID, rot.RotationEvent); err != nil {
		return nil, err
	}
	if req.AuthorizationCesrSignature == "" {
		return nil, fmt.Errorf("authorization_cesr_signature is required")
	}

	var backIxn *KeriInteractResult
	if priorTailSAID != "" {
		backSeal := BuildContinuityBackReferenceSeal(priorTailSAID)
		ixn, err := driver.Interact(newRootAID, backSeal)
		if err != nil {
			return nil, fmt.Errorf("optional back-reference IXN: %w", err)
		}
		backIxn = ixn
	}

	rotatedAt := s.Now().Format(time.RFC3339)
	proof := BuildContinuityProof(ContinuityProofInput{
		OldRootAID:                 oldRootAID,
		NewRootAID:                 newRootAID,
		NewInceptionSAID:           newInceptionSAID,
		AuthorizationEvent:         rot.RotationEvent,
		AuthorizationCesrSignature: req.AuthorizationCesrSignature,
		AuthorizationEventSAID:     rot.RotationSAID,
		BackAnchorEvent:            eventOrNil(backIxn),
		BackAnchorCesrSignature:    req.BackAnchorCesrSignature,
		BackAnchorEventSAID:        saidOrEmpty(backIxn),
		PriorKelTailSAID:           priorTailSAID,
		RotatedAt:                  rotatedAt,
		RecoverySessionID:          req.RecoverySessionID,
		CarryForwardAIDs:           req.CarryForwardAIDs,
		WitnessThreshold:           req.WitnessThreshold,
	})

	notifySet, err := BuildNotifySet(st, oldRootAID, watcherHints)
	if err != nil {
		return nil, err
	}

	contacts, err := st.GetContacts()
	if err != nil {
		return nil, fmt.Errorf("load contacts for carry-forward: %w", err)
	}
	carried := FilterCarryForwardContacts(contacts, req.CarryForwardAIDs)
	carriedAIDs := make([]string, 0, len(carried))
	for _, c := range carried {
		carriedAIDs = append(carriedAIDs, c.AID)
	}
	sort.Strings(carriedAIDs)

	sent, err := s.dispatchNotifications(st, notifySet, proof)
	if err != nil {
		return nil, err
	}

	if err := s.persistKelAndIdentity(st, inception, rot, backIxn, req); err != nil {
		return nil, err
	}

	entry := RootAIDMapEntry{
		OldRootAID:                   oldRootAID,
		NewRootAID:                   newRootAID,
		NewInceptionSAID:             newInceptionSAID,
		AuthorizationEventSAID:       rot.RotationSAID,
		AuthorizationCesrSignature:   req.AuthorizationCesrSignature,
		BackAnchorEventSAID:          saidOrEmpty(backIxn),
		PriorKelTailSAID:             priorTailSAID,
		RotatedAt:                    rotatedAt,
		RecoverySessionID:            req.RecoverySessionID,
	}
	if err := appendRootAIDMapEntry(s.DataDir, entry); err != nil {
		return nil, err
	}

	return &RootAIDRotationResult{
		Status:             "completed",
		Message:            "root-AID break-glass rotation completed; old root authorized new inception via signed rot anchor",
		OldRootAID:         oldRootAID,
		NewRootAID:         newRootAID,
		ContinuityProof:    proof,
		NotifySet:          *notifySet,
		CarriedForwardAIDs: carriedAIDs,
		NotificationsSent:  sent,
	}, nil
}

// RotateRootAID is the package-level entry used by HTTP handlers.
func RotateRootAID(
	req RootAIDRotationRequest,
	driver KeriDriverPort,
	st RootRotationStore,
	dataDir string,
	watcherHints []string,
) (*RootAIDRotationResult, error) {
	return NewRootAIDRotationService(dataDir).RotateRootAID(req, driver, st, watcherHints)
}

// RootAIDRotationAvailable reports whether break-glass root rotation is exposed.
func RootAIDRotationAvailable() bool {
	return RootAIDRotationEnabled
}

// ContinuityProofInput is the continuity payload before assembly.
type ContinuityProofInput struct {
	OldRootAID                 string
	NewRootAID                 string
	NewInceptionSAID           string
	AuthorizationEvent         map[string]interface{}
	AuthorizationCesrSignature string
	AuthorizationEventSAID     string
	BackAnchorEvent            map[string]interface{}
	BackAnchorCesrSignature    string
	BackAnchorEventSAID        string
	PriorKelTailSAID           string
	RotatedAt                  string
	RecoverySessionID          string
	CarryForwardAIDs           []string
	WitnessThreshold           int
}

// BuildDelegationAnchorSeal returns the rot/ixn seal authorizing a new root inception.
// Format: [{"d":"<new_inception_said>"}] per keripy eventing.rotate/interact data=….
func BuildDelegationAnchorSeal(newInceptionSAID string) []interface{} {
	return []interface{}{
		map[string]interface{}{"d": newInceptionSAID},
	}
}

// BuildContinuityBackReferenceSeal returns the optional new→old back-reference seal.
func BuildContinuityBackReferenceSeal(priorKelTailSAID string) []interface{} {
	return BuildDelegationAnchorSeal(priorKelTailSAID)
}

// ValidateAuthorizationEvent ensures the old root rot seals the new inception SAID.
func ValidateAuthorizationEvent(oldRootAID, newInceptionSAID string, event map[string]interface{}) error {
	if event == nil {
		return fmt.Errorf("authorization event is required")
	}
	if t, _ := event["t"].(string); t != "rot" {
		return fmt.Errorf("authorization event must be rot, got %q", t)
	}
	if i, _ := event["i"].(string); i != oldRootAID {
		return fmt.Errorf("authorization event prefix %q does not match old root %q", i, oldRootAID)
	}
	seals, ok := event["a"].([]interface{})
	if !ok || len(seals) == 0 {
		return fmt.Errorf("authorization rot missing anchor seals in field a")
	}
	found := false
	for _, seal := range seals {
		m, ok := seal.(map[string]interface{})
		if !ok {
			continue
		}
		if d, _ := m["d"].(string); d == newInceptionSAID {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("authorization rot does not seal new inception SAID %s", newInceptionSAID)
	}
	return nil
}

// BuildContinuityProof assembles the continuity document for outbound notification.
func BuildContinuityProof(in ContinuityProofInput) ContinuityProof {
	return ContinuityProof{
		V:                          continuityProofVersion,
		OldRootAID:                 in.OldRootAID,
		NewRootAID:                 in.NewRootAID,
		NewInceptionSAID:           in.NewInceptionSAID,
		AuthorizationEvent:         in.AuthorizationEvent,
		AuthorizationCesrSignature: in.AuthorizationCesrSignature,
		AuthorizationEventSAID:     in.AuthorizationEventSAID,
		BackAnchorEvent:            in.BackAnchorEvent,
		BackAnchorCesrSignature:    in.BackAnchorCesrSignature,
		BackAnchorEventSAID:        in.BackAnchorEventSAID,
		PriorKelTailSAID:           in.PriorKelTailSAID,
		RotatedAt:                  in.RotatedAt,
		RecoverySessionID:          in.RecoverySessionID,
		CarryForwardAIDs:           append([]string(nil), in.CarryForwardAIDs...),
		WitnessThreshold:           in.WitnessThreshold,
	}
}

func validateRootAIDRotationRequest(req RootAIDRotationRequest) error {
	if req.RecoverySessionID == "" {
		return fmt.Errorf("recovery_session_id is required")
	}
	if req.UseHybridInception {
		if req.PreRotationPublicKey == "" || req.PreRotationNextPublicKey == "" {
			return fmt.Errorf("pre_rotation_public_key and pre_rotation_next_public_key are required")
		}
		if req.AuthorizationCesrSignature == "" {
			return fmt.Errorf("authorization_cesr_signature is required")
		}
		return nil
	}
	if req.NewRootPublicKey == "" || req.NewRootNextPublicKey == "" {
		return fmt.Errorf("new_root_public_key and new_root_next_public_key are required")
	}
	if req.PreRotationPublicKey == "" || req.PreRotationNextPublicKey == "" {
		return fmt.Errorf("pre_rotation_public_key and pre_rotation_next_public_key are required")
	}
	if req.AuthorizationCesrSignature == "" {
		return fmt.Errorf("authorization_cesr_signature is required")
	}
	return nil
}

func (s *RootAIDRotationService) mintNewRoot(driver KeriDriverPort, req RootAIDRotationRequest) (*KeriInceptionResult, error) {
	if req.UseHybridInception {
		name := fmt.Sprintf("root-successor-%s", req.RecoverySessionID)
		return driver.CreateHybridInception(req.HybridSynthetic, name)
	}
	return driver.CreateInception(req.NewRootPublicKey, req.NewRootNextPublicKey)
}

func kelTailSAID(st RootRotationStore, aid string) (string, error) {
	events, err := st.GetEvents(aid)
	if err != nil {
		return "", fmt.Errorf("load KEL events: %w", err)
	}
	if len(events) == 0 {
		return "", fmt.Errorf("no KEL events for root AID %s", aid)
	}
	tail := events[len(events)-1]
	var ked map[string]interface{}
	if err := json.Unmarshal([]byte(tail.EventJSON), &ked); err != nil {
		return "", fmt.Errorf("parse tail event: %w", err)
	}
	said, _ := ked["d"].(string)
	if said == "" {
		return "", fmt.Errorf("tail KEL event missing SAID (d)")
	}
	return said, nil
}

func (s *RootAIDRotationService) persistKelAndIdentity(
	st RootRotationStore,
	icp *KeriInceptionResult,
	rot *KeriRotationResult,
	backIxn *KeriInteractResult,
	req RootAIDRotationRequest,
) error {
	now := s.Now().Format(time.RFC3339)

	rotJSON, err := json.Marshal(rot.RotationEvent)
	if err != nil {
		return fmt.Errorf("marshal authorization rot: %w", err)
	}
	if err := st.SaveEvent(store.EventRecord{
		AID:            rot.AID,
		SequenceNumber: rot.SequenceNumber,
		EventType:      "rot",
		EventJSON:      string(rotJSON),
		PublicKey:      rot.NewPublicKey,
		NextKeyDigest:  rot.NewNextKeyDigest,
		Timestamp:      now,
		CesrSignature:  req.AuthorizationCesrSignature,
	}); err != nil {
		return fmt.Errorf("save authorization rot: %w", err)
	}

	icpJSON, err := json.Marshal(icp.InceptionEvent)
	if err != nil {
		return fmt.Errorf("marshal inception: %w", err)
	}
	if err := st.SaveEvent(store.EventRecord{
		AID:            icp.AID,
		SequenceNumber: icp.SequenceNumber,
		EventType:      "icp",
		EventJSON:      string(icpJSON),
		PublicKey:      icp.PublicKey,
		NextKeyDigest:  icp.NextKeyDigest,
		Timestamp:      now,
	}); err != nil {
		return fmt.Errorf("save inception event: %w", err)
	}

	eventCount := icp.SequenceNumber + 1
	if backIxn != nil {
		ixnJSON, err := json.Marshal(backIxn.IxnEvent)
		if err != nil {
			return fmt.Errorf("marshal back ixn: %w", err)
		}
		if err := st.SaveEvent(store.EventRecord{
			AID:            backIxn.AID,
			SequenceNumber: backIxn.SequenceNumber,
			EventType:      "ixn",
			EventJSON:      string(ixnJSON),
			Timestamp:      now,
			CesrSignature:  req.BackAnchorCesrSignature,
		}); err != nil {
			return fmt.Errorf("save back ixn: %w", err)
		}
		eventCount = backIxn.SequenceNumber + 1
	}

	return st.SaveIdentity(store.IdentityState{
		AID:           icp.AID,
		PublicKey:     icp.PublicKey,
		NextKeyDigest: icp.NextKeyDigest,
		Created:       now,
		EventCount:    eventCount,
	})
}

func (s *RootAIDRotationService) dispatchNotifications(st RootRotationStore, set *NotifySet, proof ContinuityProof) (int, error) {
	if set == nil {
		return 0, nil
	}
	proofJSON, err := json.Marshal(proof)
	if err != nil {
		return 0, fmt.Errorf("marshal continuity proof: %w", err)
	}

	now := s.Now().Format(time.RFC3339)
	sent := 0
	for _, party := range set.All() {
		target := party.AID
		if target == "" {
			target = party.URL
		}
		task := store.TaskRecord{
			ID:         fmt.Sprintf("root-aid-notify-%s-%d", target, s.Now().UnixNano()),
			Type:       rootAIDRotationTaskType,
			Status:     "pending",
			ContactAID: party.AID,
			Detail:     fmt.Sprintf("notify %s (%s) of new root %s with signed delegation anchor", party.Kind, target, proof.NewRootAID),
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		_ = proofJSON
		if err := st.SaveTask(task); err != nil {
			return sent, fmt.Errorf("queue notify task for %s: %w", target, err)
		}
		sent++
	}
	return sent, nil
}

func appendRootAIDMapEntry(dataDir string, entry RootAIDMapEntry) error {
	if dataDir == "" {
		return fmt.Errorf("data directory is required")
	}
	path := filepath.Join(dataDir, rootAIDMapFileName)

	var existing RootAIDMap
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &existing)
	}
	if existing.Version == 0 {
		existing.Version = 1
	}
	existing.Entries = append(existing.Entries, entry)

	out, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal root aid map: %w", err)
	}
	if err := os.WriteFile(path, out, 0600); err != nil {
		return fmt.Errorf("write root aid map: %w", err)
	}
	return nil
}

// LoadRootAIDMap reads root_aid_map.json from the data directory.
func LoadRootAIDMap(dataDir string) (*RootAIDMap, error) {
	path := filepath.Join(dataDir, rootAIDMapFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &RootAIDMap{Version: 1, Entries: []RootAIDMapEntry{}}, nil
		}
		return nil, err
	}
	var m RootAIDMap
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func eventOrNil(ixn *KeriInteractResult) map[string]interface{} {
	if ixn == nil {
		return nil
	}
	return ixn.IxnEvent
}

func saidOrEmpty(ixn *KeriInteractResult) string {
	if ixn == nil {
		return ""
	}
	return ixn.Said
}

func eventSAID(ev map[string]interface{}) string {
	if ev == nil {
		return ""
	}
	said, _ := ev["d"].(string)
	return said
}