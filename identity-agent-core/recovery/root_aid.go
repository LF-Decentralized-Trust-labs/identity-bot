package recovery

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/keriengine"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

const (
	rootAIDMapFileName      = "root_aid_map.json"
	continuityProofVersion  = "2"
	rootAIDRotationTaskType = "root_aid_rotation_notify"
)

// RootAIDRotationEnabled gates break-glass rotation until the signed old→new
// delegation anchor mechanism is reviewed and explicitly enabled.
var RootAIDRotationEnabled = false

// RootAIDRotationRequest is the break-glass root-AID rotation payload: the
// three events it writes, each prepared by this core (PrepareRootAIDRotation)
// and signed by whoever holds the key it needs (ADR-061). Nothing is written
// unless all three carry a signature and the logs they make verify.
type RootAIDRotationRequest struct {
	RecoverySessionID string `json:"recovery_session_id"`
	// NewRootFounding is the new root's inception, signed by its own key.
	NewRootFounding drivers.SignedEventBytes `json:"new_root_founding"`
	// OldRootRotation is the old root's rotation, signed by the key it reveals
	// (the old root's pre-committed next key, not its compromised current key).
	// It seals the new root's inception in its anchors.
	OldRootRotation drivers.SignedEventBytes `json:"old_root_rotation"`
	// NewRootInteraction is the new root's first interaction, signed by the
	// new root's key. It seals the old root's log tail.
	NewRootInteraction drivers.SignedEventBytes `json:"new_root_interaction"`
	WitnessThreshold   int                      `json:"witness_threshold,omitempty"`
	CarryForwardAIDs   []string                 `json:"carry_forward_aids,omitempty"`
	// UseHybridInception is refused: a root this core mints from its own key
	// material is one its owner's app does not sign for.
	UseHybridInception bool `json:"use_hybrid_inception,omitempty"`
	// HybridSynthetic is refused when true. It once minted the new root from
	// fixed material whose private half anyone can rebuild from a public
	// seed, so the root would have belonged to everyone.
	HybridSynthetic bool `json:"hybrid_synthetic,omitempty"`
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

// RootRotationStore is the persistence surface required for break-glass root rotation.
type RootRotationStore interface {
	NotifySetSource
	GetEvents(aid string) ([]store.EventRecord, error)
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

// CommitEvent commits one signed event of the rotation through the core's one
// commit path (the same that /api/events/commit and a recovery's rotation
// use), and fails unless the event is now in the log.
type CommitEvent func(raw []byte, sigs []string) error

// EventPreparer builds an event without adding it (keriengine.Engine.Prepare).
type EventPreparer interface {
	Prepare(keriengine.PrepareRequest) (*keriengine.Prepared, error)
}

// RotateRootAID founds a new root and proves continuity via an old-root-signed
// delegation anchor, by committing three events, each signed by the key it needs.
//
// The events, in the order they are written, and who signs each:
//
//  1. The new root's inception (icp, sn 0). Signed by the new root's own first
//     key, which satisfies its kt. Harmless alone, so it goes first.
//  2. The old root's rotation (rot). It reveals the old root's pre-committed next
//     key, so it is signed by that key, not by the compromised current key, and
//     it seals the new inception's SAID in its anchors `a` (keripy
//     eventing.rotate data=...). This is the old->new authorization.
//  3. The new root's first interaction (ixn, sn 1). Signed by the new root's key
//     in force (its inception key). It seals the old root's log tail as it stood
//     before the rotation: the new->old back-reference.
//
// Both establishment events carry the post-quantum commitment: two next-key
// digests with nt "1" (ADR-061 sections 1 and 6).
//
// Nothing is written until all three are known to be signed and the two logs
// they make (the old root's with the rotation, the new root's with the
// interaction) verify. The identity record moves from the old root to the new
// one between 2 and 3, as the commit of 3 extends the identity kept here.
//
// Security boundary: if both the old current key AND its pre-rotation next key are
// compromised, root-level break-glass cannot help; guardians/social recovery take over.
func (s *RootAIDRotationService) RotateRootAID(
	req RootAIDRotationRequest,
	commit CommitEvent,
	st RootRotationStore,
	watcherHints []string,
) (*RootAIDRotationResult, error) {
	if !RootAIDRotationEnabled {
		return nil, fmt.Errorf("root-AID rotation is gated pending security review of the signed delegation anchor")
	}
	if commit == nil {
		return nil, fmt.Errorf("a commit path is required for root-AID rotation")
	}
	if st == nil {
		return nil, fmt.Errorf("identity store is required for root-AID rotation")
	}
	if err := validateRootAIDRotationRequest(req); err != nil {
		return nil, err
	}
	checked, err := checkSignedRootRotation(req, st)
	if err != nil {
		return nil, err
	}
	oldRootAID, newRootAID := checked.oldRootAID, checked.icp.Identifier
	newInceptionSAID := checked.icp.SAID

	contacts, err := st.GetContacts()
	if err != nil {
		return nil, fmt.Errorf("load contacts for carry-forward: %w", err)
	}
	notifySet, err := BuildNotifySet(st, oldRootAID, watcherHints)
	if err != nil {
		return nil, err
	}

	if err := commit(checked.icpRaw, req.NewRootFounding.Sigs); err != nil {
		return nil, fmt.Errorf("new root inception: %w", err)
	}
	if err := commit(checked.rotRaw, req.OldRootRotation.Sigs); err != nil {
		return nil, fmt.Errorf("old-root authorization rotation: %w", err)
	}
	rotatedAt := s.Now().Format(time.RFC3339)
	if err := st.SaveIdentity(store.IdentityState{
		AID:           newRootAID,
		PublicKey:     checked.icp.Keys[0],
		NextKeyDigest: checked.icp.NextDigest[0],
		Created:       rotatedAt,
		EventCount:    1,
	}); err != nil {
		return nil, fmt.Errorf("move the identity record to the new root: %w", err)
	}
	if err := commit(checked.ixnRaw, req.NewRootInteraction.Sigs); err != nil {
		return nil, fmt.Errorf("new root back-reference interaction: %w", err)
	}

	proof := BuildContinuityProof(ContinuityProofInput{
		OldRootAID:                 oldRootAID,
		NewRootAID:                 newRootAID,
		NewInceptionSAID:           newInceptionSAID,
		AuthorizationEvent:         checked.rotKED,
		AuthorizationCesrSignature: req.OldRootRotation.Sigs[0],
		AuthorizationEventSAID:     checked.rot.SAID,
		BackAnchorEvent:            checked.ixnKED,
		BackAnchorCesrSignature:    req.NewRootInteraction.Sigs[0],
		BackAnchorEventSAID:        checked.ixn.SAID,
		PriorKelTailSAID:           checked.priorTailSAID,
		RotatedAt:                  rotatedAt,
		RecoverySessionID:          req.RecoverySessionID,
		CarryForwardAIDs:           req.CarryForwardAIDs,
		WitnessThreshold:           req.WitnessThreshold,
	})

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

	entry := RootAIDMapEntry{
		OldRootAID:                 oldRootAID,
		NewRootAID:                 newRootAID,
		NewInceptionSAID:           newInceptionSAID,
		AuthorizationEventSAID:     checked.rot.SAID,
		AuthorizationCesrSignature: req.OldRootRotation.Sigs[0],
		BackAnchorEventSAID:        checked.ixn.SAID,
		PriorKelTailSAID:           checked.priorTailSAID,
		RotatedAt:                  rotatedAt,
		RecoverySessionID:          req.RecoverySessionID,
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
	commit CommitEvent,
	st RootRotationStore,
	dataDir string,
	watcherHints []string,
) (*RootAIDRotationResult, error) {
	return NewRootAIDRotationService(dataDir).RotateRootAID(req, commit, st, watcherHints)
}

// PrepareRootAIDRotationRequest is what the signer chooses for the break-glass
// events: the core composes no key or digest of its own.
type PrepareRootAIDRotationRequest struct {
	// NewRoot is the new root's founding: its key, and the two next-key
	// digests (classical, post-quantum) it commits to.
	NewRoot struct {
		K []string `json:"k"`
		N []string `json:"n"`
	} `json:"new_root"`
	// OldRoot is the old root's rotation: the pre-committed key it reveals, the
	// two next-key digests it commits to, and the event it follows, which must
	// be the log's tip.
	OldRoot struct {
		K     []string `json:"k"`
		N     []string `json:"n"`
		After struct {
			S string `json:"s"`
			D string `json:"d"`
		} `json:"after"`
	} `json:"old_root"`
}

// PreparedRootAIDEvent is one prepared event.
type PreparedRootAIDEvent struct {
	RawB64 string          `json:"raw_b64"`
	Hint   keriengine.Hint `json:"hint"`
}

// PreparedRootAIDRotation is the three events, built and not added.
type PreparedRootAIDRotation struct {
	NewRootFounding    PreparedRootAIDEvent `json:"new_root_founding"`
	OldRootRotation    PreparedRootAIDEvent `json:"old_root_rotation"`
	NewRootInteraction PreparedRootAIDEvent `json:"new_root_interaction"`
}

var one = json.RawMessage(`"1"`)

// PrepareRootAIDRotation builds the three events of the rotation and adds none.
// The rotation seals the founding's SAID and the interaction seals the old
// log's tail, so the founding is built first.
func PrepareRootAIDRotation(req PrepareRootAIDRotationRequest, prep EventPreparer, st RootRotationStore) (*PreparedRootAIDRotation, error) {
	if !RootAIDRotationEnabled {
		return nil, fmt.Errorf("root-AID rotation is gated pending security review of the signed delegation anchor")
	}
	if len(req.NewRoot.K) != 1 || len(req.OldRoot.K) != 1 {
		return nil, fmt.Errorf("each root names one key")
	}
	if len(req.NewRoot.N) != 2 || len(req.OldRoot.N) != 2 {
		return nil, fmt.Errorf("each establishment event commits to two next-key digests, " +
			"a classical key and a post-quantum key (ADR-061 section 6)")
	}
	identity, err := st.GetIdentity()
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}
	if identity == nil || identity.AID == "" {
		return nil, fmt.Errorf("no existing root identity to rotate")
	}
	tipSN, tipSAID, err := kelTip(st, identity.AID)
	if err != nil {
		return nil, err
	}
	afterSN, err := sequenceFromHex(req.OldRoot.After.S)
	if err != nil || afterSN != tipSN || req.OldRoot.After.D != tipSAID {
		return nil, fmt.Errorf("the rotation must follow the log's tip, sequence number %x (%s): "+
			"a break-glass rotation supersedes nothing", tipSN, tipSAID)
	}

	icp, err := prep.Prepare(keriengine.PrepareRequest{Ilk: "icp", Keys: req.NewRoot.K, Kt: one,
		Next: req.NewRoot.N, Nt: one})
	if err != nil {
		return nil, fmt.Errorf("new root inception: %w", err)
	}
	seal, err := json.Marshal(BuildDelegationAnchorSeal(icp.Hint.D)[0])
	if err != nil {
		return nil, err
	}
	rot, err := prep.Prepare(keriengine.PrepareRequest{Name: identity.AID, Ilk: "rot", Keys: req.OldRoot.K, Kt: one,
		Next: req.OldRoot.N, Nt: one, Anchors: []json.RawMessage{seal},
		After: &keriengine.Place{SN: tipSN, SAID: tipSAID}})
	if err != nil {
		return nil, fmt.Errorf("old root rotation: %w", err)
	}
	back, err := json.Marshal(BuildContinuityBackReferenceSeal(tipSAID)[0])
	if err != nil {
		return nil, err
	}
	ixnRaw, err := keri.BuildInteraction(keri.InteractionInput{Prefix: icp.Hint.I, PriorSAID: icp.Hint.D, SN: 1,
		Data: []json.RawMessage{back}})
	if err != nil {
		return nil, fmt.Errorf("building the new root's interaction: %w", err)
	}
	ixn, err := keri.ParseEvent(ixnRaw)
	if err != nil {
		return nil, err
	}
	enc := func(p *keriengine.Prepared) PreparedRootAIDEvent {
		return PreparedRootAIDEvent{RawB64: base64.StdEncoding.EncodeToString(p.Raw), Hint: p.Hint}
	}
	return &PreparedRootAIDRotation{
		NewRootFounding: enc(icp),
		OldRootRotation: enc(rot),
		NewRootInteraction: PreparedRootAIDEvent{RawB64: base64.StdEncoding.EncodeToString(ixnRaw),
			Hint: keriengine.Hint{T: "ixn", I: ixn.Identifier, S: "1", P: icp.Hint.D, D: ixn.SAID}},
	}, nil
}

func sequenceFromHex(s string) (int, error) {
	n, err := iacrypto.ParseHexCount(s)
	return int(n), err
}

// checkedRootRotation is the three events, parsed and judged.
type checkedRootRotation struct {
	oldRootAID             string
	priorTailSAID          string
	icp, rot, ixn          *keri.Event
	icpRaw, rotRaw, ixnRaw []byte
	rotKED, ixnKED         map[string]interface{}
}

// checkSignedRootRotation judges the rotation before anything is written: each
// event is the shape this rotation writes, every one carries a signature, and
// the two logs they make verify, the old root's from its founding with the
// rotation on its tip and the new root's with its interaction.
func checkSignedRootRotation(req RootAIDRotationRequest, st RootRotationStore) (*checkedRootRotation, error) {
	identity, err := st.GetIdentity()
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}
	if identity == nil || identity.AID == "" {
		return nil, fmt.Errorf("no existing root identity to rotate")
	}
	c := &checkedRootRotation{oldRootAID: identity.AID}

	decode := func(label string, e drivers.SignedEventBytes, ilk string) (*keri.Event, []byte, map[string]interface{}, error) {
		if len(e.Sigs) == 0 {
			return nil, nil, nil, fmt.Errorf("%s is not signed: a break-glass rotation writes nothing unless all three events are", label)
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(e.RawB64)
		if err != nil || len(raw) == 0 {
			return nil, nil, nil, fmt.Errorf("%s is not the event's bytes in standard base64", label)
		}
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%s does not parse: %w", label, err)
		}
		if ev.Ilk != ilk {
			return nil, nil, nil, fmt.Errorf("%s must be %s, got %q", label, ilk, ev.Ilk)
		}
		var ked map[string]interface{}
		if err := json.Unmarshal(raw, &ked); err != nil {
			return nil, nil, nil, fmt.Errorf("%s: %w", label, err)
		}
		return ev, raw, ked, nil
	}
	var icpKED map[string]interface{}
	if c.icp, c.icpRaw, icpKED, err = decode("new_root_founding", req.NewRootFounding, "icp"); err != nil {
		return nil, err
	}
	if c.rot, c.rotRaw, c.rotKED, err = decode("old_root_rotation", req.OldRootRotation, "rot"); err != nil {
		return nil, err
	}
	if c.ixn, c.ixnRaw, c.ixnKED, err = decode("new_root_interaction", req.NewRootInteraction, "ixn"); err != nil {
		return nil, err
	}

	if c.rot.Identifier != c.oldRootAID {
		return nil, fmt.Errorf("old_root_rotation is of %s, not the identity kept here, %s", c.rot.Identifier, c.oldRootAID)
	}
	if c.icp.Identifier == c.oldRootAID {
		return nil, fmt.Errorf("new_root_founding founds the identity already kept here")
	}
	if c.ixn.Identifier != c.icp.Identifier || c.ixn.SN != 1 || c.ixn.PriorSAID != c.icp.SAID {
		return nil, fmt.Errorf("new_root_interaction must be the new root's sequence number 1, following its inception")
	}
	if err := ValidateAuthorizationEvent(c.oldRootAID, c.icp.SAID, c.rotKED); err != nil {
		return nil, err
	}
	if len(anchorsOf(c.rotKED)) != 1 || len(anchorsOf(icpKED)) != 0 {
		return nil, fmt.Errorf("the rotation anchors the new inception and nothing else, and the inception anchors nothing")
	}
	tipSN, tail, err := kelTip(st, c.oldRootAID)
	if err != nil {
		return nil, err
	}
	c.priorTailSAID = tail
	if c.rot.PriorSAID != tail || int(c.rot.SN) != tipSN+1 {
		return nil, fmt.Errorf("old_root_rotation must follow the log's tip, sequence number %x (%s)", tipSN, tail)
	}
	back := anchorsOf(c.ixnKED)
	if len(back) != 1 || back[0]["d"] != tail {
		return nil, fmt.Errorf("new_root_interaction must seal the old root's log tail %s and nothing else", tail)
	}
	for label, raw := range map[string][]byte{"new_root_founding": c.icpRaw, "old_root_rotation": c.rotRaw} {
		if err := requirePostQuantumCommitment(raw); err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
	}

	newLog := []drivers.SignedEventBytes{req.NewRootFounding, req.NewRootInteraction}
	if err := verifyLog(c.icp.Identifier, newLog); err != nil {
		return nil, fmt.Errorf("the new root's log does not verify: %w", err)
	}
	events, err := st.GetEvents(c.oldRootAID)
	if err != nil {
		return nil, fmt.Errorf("load KEL events: %w", err)
	}
	var oldLog []drivers.SignedEventBytes
	for _, rec := range events {
		sigs := rec.ControllerSignatures()
		if rec.RawBytesB64 == "" || len(sigs) == 0 {
			return nil, fmt.Errorf("the old root's event %d is kept without its signed bytes, so a rotation of it cannot be checked", rec.SequenceNumber)
		}
		oldLog = append(oldLog, drivers.SignedEventBytes{RawB64: rec.RawBytesB64, Sigs: sigs})
	}
	if err := verifyLog(c.oldRootAID, append(oldLog, req.OldRootRotation)); err != nil {
		return nil, fmt.Errorf("the old root's log with the rotation does not verify: %w", err)
	}
	return c, nil
}

func verifyLog(aid string, events []drivers.SignedEventBytes) error {
	messages, err := drivers.LogMessages(events)
	if err != nil {
		return err
	}
	_, err = drivers.VerifiedLogOf(aid, messages)
	return err
}

// requirePostQuantumCommitment is the shape every rotation here carries: two
// next-key digests and a next threshold of one (ADR-061 sections 1 and 6).
func requirePostQuantumCommitment(raw []byte) error {
	var ev struct {
		N  []string `json:"n"`
		Nt string   `json:"nt"`
	}
	if err := json.Unmarshal(raw, &ev); err != nil {
		return err
	}
	if len(ev.N) != 2 || ev.Nt != "1" {
		return fmt.Errorf("it must commit to two next-key digests, classical and post-quantum, with nt \"1\"")
	}
	return nil
}

func anchorsOf(ked map[string]interface{}) []map[string]interface{} {
	var out []map[string]interface{}
	seals, _ := ked["a"].([]interface{})
	for _, a := range seals {
		m, _ := a.(map[string]interface{})
		out = append(out, m)
	}
	return out
}

// RootAIDRotationAvailable reports whether break-glass root rotation is exposed.
func RootAIDRotationAvailable() bool {
	return RootAIDRotationEnabled
}

// RootAIDRotationSigned reports whether the events break-glass root rotation
// writes are signed by their keys. They are: each is prepared by this core
// and committed with the signatures of whoever holds its key, and a rotation
// with any event unsigned is refused whole, before anything is written.
var RootAIDRotationSigned = true

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
	if req.HybridSynthetic {
		return fmt.Errorf("hybrid_synthetic is not taken: a root minted from fixed material has a " +
			"private half anyone can rebuild, so it would belong to everyone")
	}
	if req.UseHybridInception {
		return fmt.Errorf("use_hybrid_inception is not taken: a root this core mints from its own key material " +
			"is not one its owner's app signs for")
	}
	return nil
}

// kelTip is the sequence number and digest of the last event kept of aid.
func kelTip(st RootRotationStore, aid string) (int, string, error) {
	events, err := st.GetEvents(aid)
	if err != nil {
		return 0, "", fmt.Errorf("load KEL events: %w", err)
	}
	if len(events) == 0 {
		return 0, "", fmt.Errorf("no KEL events for root AID %s", aid)
	}
	tail := events[len(events)-1]
	var ked map[string]interface{}
	if err := json.Unmarshal([]byte(tail.EventJSON), &ked); err != nil {
		return 0, "", fmt.Errorf("parse tail event: %w", err)
	}
	said, _ := ked["d"].(string)
	if said == "" {
		return 0, "", fmt.Errorf("tail KEL event missing SAID (d)")
	}
	return tail.SequenceNumber, said, nil
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
