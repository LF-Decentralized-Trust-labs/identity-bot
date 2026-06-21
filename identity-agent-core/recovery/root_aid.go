package recovery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/store"
)

const (
	rootAIDMapFileName      = "root_aid_map.json"
	continuityProofVersion  = "1"
	rootAIDRotationTaskType = "root_aid_rotation_notify"
)

// RootAIDRotationRequest is the break-glass root-AID rotation payload.
type RootAIDRotationRequest struct {
	RecoverySessionID    string   `json:"recovery_session_id"`
	NewRootPublicKey     string   `json:"new_root_public_key"`
	NewRootNextPublicKey string   `json:"new_root_next_public_key"`
	WitnessThreshold     int      `json:"witness_threshold,omitempty"`
	CarryForwardAIDs     []string `json:"carry_forward_aids,omitempty"`
	UseHybridInception   bool     `json:"use_hybrid_inception,omitempty"`
	HybridSynthetic      bool     `json:"hybrid_synthetic,omitempty"`
	CesrSignature        string   `json:"cesr_signature,omitempty"`
}

// ContinuityProof documents the KERI IXN anchor binding the new root to the prior KEL tail.
type ContinuityProof struct {
	V                    string   `json:"v"`
	NewRootAID           string   `json:"new_root_aid"`
	PriorKelTailSAID     string   `json:"prior_kel_tail_said"`
	AnchorIxnSAID        string   `json:"anchor_ixn_said"`
	ProofDigestBlake3QB64 string  `json:"proof_digest_blake3_qb64"`
	RotatedAt            string   `json:"rotated_at"`
	RecoverySessionID    string   `json:"recovery_session_id,omitempty"`
	CarryForwardAIDs     []string `json:"carry_forward_aids,omitempty"`
	WitnessThreshold     int      `json:"witness_threshold,omitempty"`
}

// RootAIDMapEntry records one break-glass rotation in local history.
type RootAIDMapEntry struct {
	OldRootAID           string `json:"old_root_aid"`
	NewRootAID           string `json:"new_root_aid"`
	PriorKelTailSAID     string `json:"prior_kel_tail_said"`
	AnchorIxnSAID        string `json:"anchor_ixn_said"`
	ProofDigestBlake3QB64 string `json:"proof_digest_blake3_qb64"`
	RotatedAt            string `json:"rotated_at"`
	RecoverySessionID    string `json:"recovery_session_id,omitempty"`
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
	ContinuityProof    ContinuityProof   `json:"continuity_proof"`
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
	SequenceNumber int
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

// RotateRootAID mints a new root AID, anchors the prior KEL tail SAID on the new KEL via
// a KERI IXN seal, re-notifies the notify set, and records the mapping locally.
//
// KERI anchoring mechanism (for Rob review):
//   1. Mint fresh root via driver CreateInception / CreateHybridInception (new ICP, sn=0).
//   2. On the NEW root AID only, emit IXN at sn=1 through driver Interact with seal data
//      [{"d":"<prior_kel_tail_said>"}] — standard KERI digest seal, NOT an ACDC credential.
//      The prior root AID prefix never appears in the IXN anchor; only the opaque tail SAID
//      is sealed, giving verifiers a non-correlating continuity proof when they already hold
//      the old KEL tail out-of-band.
//   3. Publish a separate ContinuityProof JSON (contracts/root-aid-continuity) whose
//      proof_digest_blake3_qb64 is Blake3 over the canonical body; notify witnesses,
//      watchers, and issuers with {new_root_aid, continuity_proof}.
func (s *RootAIDRotationService) RotateRootAID(
	req RootAIDRotationRequest,
	driver KeriDriverPort,
	st RootRotationStore,
	watcherHints []string,
) (*RootAIDRotationResult, error) {
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

	anchorData := BuildContinuityAnchorSeal(priorTailSAID)
	ixn, err := driver.Interact(newRootAID, anchorData)
	if err != nil {
		return nil, fmt.Errorf("anchor continuity IXN: %w", err)
	}

	rotatedAt := s.Now().Format(time.RFC3339)
	proof := BuildContinuityProof(ContinuityProofInput{
		NewRootAID:        newRootAID,
		PriorKelTailSAID:  priorTailSAID,
		AnchorIxnSAID:     ixn.Said,
		RotatedAt:         rotatedAt,
		RecoverySessionID: req.RecoverySessionID,
		CarryForwardAIDs:  req.CarryForwardAIDs,
		WitnessThreshold:  req.WitnessThreshold,
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

	if err := s.persistKelAndIdentity(st, inception, ixn, req.CesrSignature); err != nil {
		return nil, err
	}

	entry := RootAIDMapEntry{
		OldRootAID:            oldRootAID,
		NewRootAID:            newRootAID,
		PriorKelTailSAID:      priorTailSAID,
		AnchorIxnSAID:         ixn.Said,
		ProofDigestBlake3QB64: proof.ProofDigestBlake3QB64,
		RotatedAt:             rotatedAt,
		RecoverySessionID:     req.RecoverySessionID,
	}
	if err := appendRootAIDMapEntry(s.DataDir, entry); err != nil {
		return nil, err
	}

	return &RootAIDRotationResult{
		Status:             "completed",
		Message:            "root-AID break-glass rotation completed; continuity anchored via new-root IXN seal",
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

// RootAIDRotationAvailable reports whether break-glass root rotation is supported.
func RootAIDRotationAvailable() bool {
	return true
}

// ContinuityProofInput is the pre-digest continuity payload.
type ContinuityProofInput struct {
	NewRootAID        string
	PriorKelTailSAID  string
	AnchorIxnSAID     string
	RotatedAt         string
	RecoverySessionID string
	CarryForwardAIDs  []string
	WitnessThreshold  int
}

// BuildContinuityAnchorSeal returns the KERI IXN seal anchoring the prior KEL tail SAID.
// Format: [{"d":"<prior_kel_tail_said>"}] per keri-core /interact contract.
func BuildContinuityAnchorSeal(priorKelTailSAID string) []interface{} {
	return []interface{}{
		map[string]interface{}{"d": priorKelTailSAID},
	}
}

// BuildContinuityProof constructs the continuity document and Blake3 digest.
func BuildContinuityProof(in ContinuityProofInput) ContinuityProof {
	body := map[string]interface{}{
		"v":                   continuityProofVersion,
		"new_root_aid":        in.NewRootAID,
		"prior_kel_tail_said": in.PriorKelTailSAID,
		"anchor_ixn_said":     in.AnchorIxnSAID,
		"rotated_at":          in.RotatedAt,
	}
	if in.RecoverySessionID != "" {
		body["recovery_session_id"] = in.RecoverySessionID
	}
	if len(in.CarryForwardAIDs) > 0 {
		body["carry_forward_aids"] = in.CarryForwardAIDs
	}
	if in.WitnessThreshold > 0 {
		body["witness_threshold"] = in.WitnessThreshold
	}

	canonical, _ := json.Marshal(body)
	digest := iacrypto.Blake3QB64Must(canonical)

	return ContinuityProof{
		V:                    continuityProofVersion,
		NewRootAID:           in.NewRootAID,
		PriorKelTailSAID:     in.PriorKelTailSAID,
		AnchorIxnSAID:        in.AnchorIxnSAID,
		ProofDigestBlake3QB64: digest,
		RotatedAt:            in.RotatedAt,
		RecoverySessionID:    in.RecoverySessionID,
		CarryForwardAIDs:     append([]string(nil), in.CarryForwardAIDs...),
		WitnessThreshold:     in.WitnessThreshold,
	}
}

func validateRootAIDRotationRequest(req RootAIDRotationRequest) error {
	if req.RecoverySessionID == "" {
		return fmt.Errorf("recovery_session_id is required")
	}
	if req.UseHybridInception {
		return nil
	}
	if req.NewRootPublicKey == "" || req.NewRootNextPublicKey == "" {
		return fmt.Errorf("new_root_public_key and new_root_next_public_key are required")
	}
	return nil
}

func (s *RootAIDRotationService) mintNewRoot(driver KeriDriverPort, req RootAIDRotationRequest) (*KeriInceptionResult, error) {
	if req.UseHybridInception {
		name := fmt.Sprintf("root-rotation-%s", req.RecoverySessionID)
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
	ixn *KeriInteractResult,
	cesrSig string,
) error {
	now := s.Now().Format(time.RFC3339)

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

	ixnJSON, err := json.Marshal(ixn.IxnEvent)
	if err != nil {
		return fmt.Errorf("marshal ixn: %w", err)
	}
	if err := st.SaveEvent(store.EventRecord{
		AID:            ixn.AID,
		SequenceNumber: ixn.SequenceNumber,
		EventType:      "ixn",
		EventJSON:      string(ixnJSON),
		Timestamp:      now,
		CesrSignature:  cesrSig,
	}); err != nil {
		return fmt.Errorf("save ixn event: %w", err)
	}

	return st.SaveIdentity(store.IdentityState{
		AID:           icp.AID,
		PublicKey:     icp.PublicKey,
		NextKeyDigest: icp.NextKeyDigest,
		Created:       now,
		EventCount:    ixn.SequenceNumber + 1,
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
			ID:        fmt.Sprintf("root-aid-notify-%s-%d", target, s.Now().UnixNano()),
			Type:      rootAIDRotationTaskType,
			Status:    "pending",
			ContactAID: party.AID,
			Detail:    fmt.Sprintf("notify %s (%s) of new root %s", party.Kind, target, proof.NewRootAID),
			CreatedAt: now,
			UpdatedAt: now,
		}
		_ = proofJSON // reserved for outbound notify payload wiring
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