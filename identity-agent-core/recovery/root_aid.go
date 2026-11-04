package recovery

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/keriengine"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

const (
	rootAIDMapFileName      = "root_aid_map.json"
	continuityProofVersion  = "3"
	rootAIDRotationTaskType = "root_aid_rotation_notify"
)

// RootAIDRotationEnabled gates break-glass rotation until the signed old→new
// delegation anchor mechanism is reviewed and explicitly enabled.
var RootAIDRotationEnabled = false

// RootAIDRotationRequest is the break-glass root-AID rotation payload: the
// three events it writes, each prepared by this core (PrepareRootAIDRotation)
// and signed by whoever holds the key it needs (ADR-061). Nothing is written
// unless the checks pass, and a run stopped part way is finished by sending
// the same request again.
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
// new root inception. It carries each event as the bytes that were signed and
// every signature on it, so a verifier holding only the proof recomputes each
// digest and checks each signature (VerifyContinuityProof). It also carries the
// old root's log up to the rotation, so the trust gate, the rotation signed by
// the key the old root committed to, is judged from the proof alone.
type ContinuityProof struct {
	V                string `json:"v"`
	OldRootAID       string `json:"old_root_aid"`
	NewRootAID       string `json:"new_root_aid"`
	NewInceptionSAID string `json:"new_inception_said"`
	// NewInceptionRawB64 and NewInceptionSignatures are the new root's
	// inception as signed: its key, which the back-anchor is checked against.
	NewInceptionRawB64     string   `json:"new_inception_raw_b64"`
	NewInceptionSignatures []string `json:"new_inception_signatures"`
	// AuthorizationEventRawB64 is the old root's rotation, exactly the bytes
	// signed, in standard base64; AuthorizationSignatures every indexed
	// signature on it.
	AuthorizationEventRawB64 string   `json:"authorization_event_raw_b64"`
	AuthorizationSignatures  []string `json:"authorization_signatures"`
	AuthorizationEventSAID   string   `json:"authorization_event_said"`
	// BackAnchorEventRawB64 is the new root's first interaction, which seals
	// the authorization event's digest.
	BackAnchorEventRawB64 string   `json:"back_anchor_event_raw_b64"`
	BackAnchorSignatures  []string `json:"back_anchor_signatures"`
	BackAnchorEventSAID   string   `json:"back_anchor_event_said"`
	// OldRootLog is the old root's log from its inception up to the event the
	// authorization rotation follows, each event as the bytes signed with its
	// signatures. With the authorization event it is the old root's log up to
	// and including the rotation, which is what shows the rotation was signed
	// by the key the old root committed to, at its threshold.
	OldRootLog []drivers.SignedEventBytes `json:"old_root_log"`
	// PriorKelTailSAID is the event of the old root's log the authorization
	// rotation follows: the last establishment event or an interaction the
	// owner kept. Any interaction after it was superseded.
	PriorKelTailSAID  string   `json:"prior_kel_tail_said"`
	RotatedAt         string   `json:"rotated_at"`
	RecoverySessionID string   `json:"recovery_session_id,omitempty"`
	CarryForwardAIDs  []string `json:"carry_forward_aids,omitempty"`
	WitnessThreshold  int      `json:"witness_threshold,omitempty"`
}

// RootAIDMapEntry records one break-glass rotation in local history.
type RootAIDMapEntry struct {
	OldRootAID              string   `json:"old_root_aid"`
	NewRootAID              string   `json:"new_root_aid"`
	NewInceptionSAID        string   `json:"new_inception_said"`
	AuthorizationEventSAID  string   `json:"authorization_event_said"`
	AuthorizationSignatures []string `json:"authorization_signatures"`
	BackAnchorEventSAID     string   `json:"back_anchor_event_said,omitempty"`
	PriorKelTailSAID        string   `json:"prior_kel_tail_said,omitempty"`
	RotatedAt               string   `json:"rotated_at"`
	RecoverySessionID       string   `json:"recovery_session_id,omitempty"`
	// WitnessedAt is when the old root's witnesses were shown to hold its log
	// through the rotation, and WitnessingGaveUpAt when this core stopped
	// trying after the witnesses never did. Either ends the job that sends the
	// old root's log to them.
	WitnessedAt        string `json:"witnessed_at,omitempty"`
	WitnessingGaveUpAt string `json:"witnessing_gave_up_at,omitempty"`
}

// WrittenBySignedPath is whether the entry was written by the signed rotation,
// which records the signature the old root's rotation carries. Break-glass was
// ungated, and wrote this file without signing anything, before 746602a8
// (2026-06-21): an entry from then names a root whose rotation was never
// signed, and nothing it names is to be sent to witnesses as the old root's log.
func (e RootAIDMapEntry) WrittenBySignedPath() bool {
	return e.OldRootAID != "" && e.AuthorizationEventSAID != "" && len(e.AuthorizationSignatures) > 0
}

// WitnessingIsOpen is whether the old root's log is still to be sent to its
// witnesses: the entry is from the signed path and neither done nor given up.
func (e RootAIDMapEntry) WitnessingIsOpen() bool {
	return e.WrittenBySignedPath() && e.WitnessedAt == "" && e.WitnessingGaveUpAt == ""
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
//  2. The old root's rotation (rot). It follows the event the app names, the
//     last establishment event or an interaction the owner keeps, and
//     supersedes the interactions after it, as a recovery rotation does
//     (ADR-061 section 4): whatever the holder of the stolen key added is not
//     the owner's, and cannot stop this. It reveals the old root's
//     pre-committed next key, so it is signed by that key, not by the
//     compromised current key, and it seals the new inception's SAID in its
//     anchors `a`. This is the old->new authorization.
//  3. The new root's first interaction (ixn, sn 1). Signed by the new root's key
//     in force (its inception key). It seals the old root's tip after the
//     rotation, the rotation itself: the new->old back-reference.
//
// Both establishment events carry the post-quantum commitment: two next-key
// digests with nt "1" (ADR-061 sections 1 and 6).
//
// Nothing is written until all three are known to be signed and the two logs
// they make (the old root's with the rotation, the new root's with the
// interaction) verify. The identity record moves from the old root to the new
// one between 2 and 3.
//
// A run that stops part way is finished by sending the same request again.
// Each event already in its log is recognised by its digest, the identity
// record is moved only if it has not been, and the notification tasks and the
// root map entry are written under keys the request fixes, so a repeat leaves
// what a run that never stopped leaves.
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

	// The time of the rotation is the one the identity record was moved at, if
	// a run before this one got that far, so a repeat records the same time.
	rotatedAt := checked.rotatedAt
	if rotatedAt == "" {
		rotatedAt = s.Now().Format(time.RFC3339)
	}

	// Committing an event the log already holds adds nothing, so each is
	// committed whether or not an earlier run got to it.
	if err := commit(checked.icpRaw, checked.icpSigs); err != nil {
		return nil, fmt.Errorf("new root inception: %w", err)
	}
	if err := commit(checked.rotRaw, checked.rotSigs); err != nil {
		return nil, fmt.Errorf("old-root authorization rotation: %w", err)
	}
	if !checked.moved {
		if err := st.SaveIdentity(store.IdentityState{
			AID:           newRootAID,
			PublicKey:     checked.icp.Keys[0],
			NextKeyDigest: checked.icp.NextDigest[0],
			Created:       rotatedAt,
			EventCount:    1,
		}); err != nil {
			return nil, fmt.Errorf("move the identity record to the new root: %w", err)
		}
	}
	if err := commit(checked.ixnRaw, checked.ixnSigs); err != nil {
		return nil, fmt.Errorf("new root back-reference interaction: %w", err)
	}

	proof := BuildContinuityProof(ContinuityProofInput{
		OldRootAID:               oldRootAID,
		NewRootAID:               newRootAID,
		NewInceptionSAID:         newInceptionSAID,
		NewInceptionRawB64:       req.NewRootFounding.RawB64,
		NewInceptionSignatures:   checked.icpSigs,
		AuthorizationEventRawB64: req.OldRootRotation.RawB64,
		AuthorizationSignatures:  checked.rotSigs,
		AuthorizationEventSAID:   checked.rot.SAID,
		BackAnchorEventRawB64:    req.NewRootInteraction.RawB64,
		BackAnchorSignatures:     checked.ixnSigs,
		BackAnchorEventSAID:      checked.ixn.SAID,
		OldRootLog:               checked.oldLog,
		PriorKelTailSAID:         checked.after,
		RotatedAt:                rotatedAt,
		RecoverySessionID:        req.RecoverySessionID,
		CarryForwardAIDs:         req.CarryForwardAIDs,
		WitnessThreshold:         req.WitnessThreshold,
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
		OldRootAID:              oldRootAID,
		NewRootAID:              newRootAID,
		NewInceptionSAID:        newInceptionSAID,
		AuthorizationEventSAID:  checked.rot.SAID,
		AuthorizationSignatures: checked.rotSigs,
		BackAnchorEventSAID:     checked.ixn.SAID,
		PriorKelTailSAID:        checked.after,
		RotatedAt:               rotatedAt,
		RecoverySessionID:       req.RecoverySessionID,
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
	// NewRoot is the new root's founding, asked for as POST /api/events/prepare
	// asks for an icp: its key, the two next-key digests (classical,
	// post-quantum) it commits to, and optionally its anchors (the messaging
	// keyset from POST /api/keystore/messaging-seed among them), its owner, and
	// its witnesses and their threshold. Witnesses default to the old root's
	// when b is absent.
	NewRoot struct {
		K        []string          `json:"k"`
		N        []string          `json:"n"`
		A        []json.RawMessage `json:"a,omitempty"`
		OwnerAID string            `json:"owner_aid,omitempty"`
		B        []string          `json:"b,omitempty"`
		Bt       *json.RawMessage  `json:"bt,omitempty"`
	} `json:"new_root"`
	// OldRoot is the old root's rotation: the pre-committed key it reveals, the
	// two next-key digests it commits to, and the event it follows (After),
	// which is the last establishment event or an interaction the owner keeps.
	// The rotation supersedes every interaction after it.
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
// founding is the new root's inception exactly as an ordinary founding is
// prepared (the server's one founding preparation: owner seal, anchors,
// witnesses); the rotation seals its SAID and the interaction seals the
// rotation's, so they are built in that order.
//
// The rotation follows req.OldRoot.After and supersedes the interactions after
// it, as a recovery rotation does; the engine refuses a place that is not the
// last establishment event or an interaction after it.
func PrepareRootAIDRotation(req PrepareRootAIDRotationRequest, founding keriengine.PrepareRequest, prep EventPreparer, st RootRotationStore) (*PreparedRootAIDRotation, error) {
	if !RootAIDRotationEnabled {
		return nil, fmt.Errorf("root-AID rotation is gated pending security review of the signed delegation anchor")
	}
	if founding.Ilk != "icp" || len(founding.Keys) != 1 || len(req.OldRoot.K) != 1 {
		return nil, fmt.Errorf("each root names one key")
	}
	if len(founding.Next) != 2 || len(req.OldRoot.N) != 2 {
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
	afterSN, err := sequenceFromHex(req.OldRoot.After.S)
	if err != nil {
		return nil, fmt.Errorf("after: %w", err)
	}

	icp, err := prep.Prepare(founding)
	if err != nil {
		return nil, fmt.Errorf("new root inception: %w", err)
	}
	seal, err := json.Marshal(BuildDelegationAnchorSeal(icp.Hint.D)[0])
	if err != nil {
		return nil, err
	}
	rot, err := prep.Prepare(keriengine.PrepareRequest{Name: identity.AID, Ilk: "rot", Keys: req.OldRoot.K, Kt: one,
		Next: req.OldRoot.N, Nt: one, Anchors: []json.RawMessage{seal},
		After: &keriengine.Place{SN: afterSN, SAID: req.OldRoot.After.D}})
	if err != nil {
		return nil, fmt.Errorf("old root rotation: %w", err)
	}
	back, err := json.Marshal(BuildContinuityBackReferenceSeal(rot.Hint.D)[0])
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
	oldRootAID string
	// after is the digest of the old root's event the rotation follows.
	after                  string
	icp, rot, ixn          *keri.Event
	icpRaw, rotRaw, ixnRaw []byte
	// The indexed signatures each event is committed and proven with.
	icpSigs, rotSigs, ixnSigs []string
	rotKED                    map[string]interface{}
	// oldLog is the old root's log up to the event the rotation follows, as kept.
	oldLog []drivers.SignedEventBytes
	// moved is whether the identity record is already the new root, and
	// rotatedAt the time an earlier run moved it.
	moved     bool
	rotatedAt string
}

// checkSignedRootRotation judges the rotation before anything is written: each
// event is the shape this rotation writes, every one carries a signature, and
// the two logs they make verify, the old root's from its founding with the
// rotation on the event it follows and the new root's with its interaction.
//
// It judges a run that stopped part way as well as a fresh one: the rotation
// may already be in the old root's log (the same digest), the founding in the
// new root's, and the identity record may already be the new root.
func checkSignedRootRotation(req RootAIDRotationRequest, st RootRotationStore) (*checkedRootRotation, error) {
	identity, err := st.GetIdentity()
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}
	if identity == nil || identity.AID == "" {
		return nil, fmt.Errorf("no existing root identity to rotate")
	}
	c := &checkedRootRotation{}

	decode := func(label string, e drivers.SignedEventBytes, ilk string) (*keri.Event, []byte, map[string]interface{}, []string, error) {
		if len(e.Sigs) == 0 {
			return nil, nil, nil, nil, fmt.Errorf("%s is not signed: a break-glass rotation writes nothing unless all three events are", label)
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(e.RawB64)
		if err != nil || len(raw) == 0 {
			return nil, nil, nil, nil, fmt.Errorf("%s is not the event's bytes in standard base64", label)
		}
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("%s does not parse: %w", label, err)
		}
		if ev.Ilk != ilk {
			return nil, nil, nil, nil, fmt.Errorf("%s must be %s, got %q", label, ilk, ev.Ilk)
		}
		var ked map[string]interface{}
		if err := json.Unmarshal(raw, &ked); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("%s: %w", label, err)
		}
		signers := len(ev.Keys)
		if signers == 0 {
			signers = 1
		}
		sigs, err := drivers.IndexedSignatures(e.Sigs, signers)
		if err != nil || len(sigs) == 0 {
			return nil, nil, nil, nil, fmt.Errorf("%s is not signed with indexed signatures: %v", label, err)
		}
		return ev, raw, ked, sigs, nil
	}
	if c.icp, c.icpRaw, _, c.icpSigs, err = decode("new_root_founding", req.NewRootFounding, "icp"); err != nil {
		return nil, err
	}
	if c.rot, c.rotRaw, c.rotKED, c.rotSigs, err = decode("old_root_rotation", req.OldRootRotation, "rot"); err != nil {
		return nil, err
	}
	var ixnKED map[string]interface{}
	if c.ixn, c.ixnRaw, ixnKED, c.ixnSigs, err = decode("new_root_interaction", req.NewRootInteraction, "ixn"); err != nil {
		return nil, err
	}

	c.oldRootAID = c.rot.Identifier
	if c.icp.Identifier == c.oldRootAID {
		return nil, fmt.Errorf("new_root_founding founds the identity already kept here")
	}
	if c.ixn.Identifier != c.icp.Identifier || c.ixn.SN != 1 || c.ixn.PriorSAID != c.icp.SAID {
		return nil, fmt.Errorf("new_root_interaction must be the new root's sequence number 1, following its inception")
	}
	if err := ValidateAuthorizationEvent(c.oldRootAID, c.icp.SAID, c.rotKED); err != nil {
		return nil, err
	}
	if len(anchorsOf(c.rotKED)) != 1 {
		return nil, fmt.Errorf("the rotation anchors the new inception and nothing else")
	}
	back := anchorsOf(ixnKED)
	if len(back) != 1 || back[0]["d"] != c.rot.SAID {
		return nil, fmt.Errorf("new_root_interaction must seal the old root's rotation %s and nothing else", c.rot.SAID)
	}
	for label, raw := range map[string][]byte{"new_root_founding": c.icpRaw, "old_root_rotation": c.rotRaw} {
		if err := requirePostQuantumCommitment(raw); err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
	}

	// The old root's log: the events up to the one the rotation follows, then
	// either the rotation itself (an earlier run added it) or interactions it
	// supersedes. Anything else at that place is not a rotation of this log.
	events, err := st.GetEvents(c.oldRootAID)
	if err != nil {
		return nil, fmt.Errorf("load KEL events: %w", err)
	}
	at := int(c.rot.SN)
	if at < 1 || at > len(events) {
		return nil, fmt.Errorf("old_root_rotation is at sequence number %x, which does not follow an event of the log kept here", at)
	}
	if c.after, err = saidOfRecord(events[at-1]); err != nil {
		return nil, err
	}
	if c.after != c.rot.PriorSAID {
		return nil, fmt.Errorf("old_root_rotation follows %s, not the event at sequence number %x of the log kept here (%s)",
			c.rot.PriorSAID, at-1, c.after)
	}
	rotAdded := false
	if len(events) > at {
		first, err := saidOfRecord(events[at])
		if err != nil {
			return nil, err
		}
		if first == c.rot.SAID {
			rotAdded = true
		} else {
			for _, rec := range events[at:] {
				if rec.EventType != "ixn" {
					return nil, fmt.Errorf("old_root_rotation takes the place of %s at sequence number %x, "+
						"and a rotation supersedes only interactions", rec.EventType, rec.SequenceNumber)
				}
			}
		}
	}
	var oldLog []drivers.SignedEventBytes
	for _, rec := range events[:at] {
		sigs := rec.ControllerSignatures()
		if rec.RawBytesB64 == "" || len(sigs) == 0 {
			return nil, fmt.Errorf("the old root's event %d is kept without its signed bytes, so a rotation of it cannot be checked", rec.SequenceNumber)
		}
		oldLog = append(oldLog, drivers.SignedEventBytes{RawB64: rec.RawBytesB64, Sigs: sigs})
	}
	c.oldLog = oldLog
	if err := verifyLog(c.oldRootAID, append(append([]drivers.SignedEventBytes(nil), oldLog...), req.OldRootRotation)); err != nil {
		return nil, fmt.Errorf("the old root's log with the rotation does not verify: %w", err)
	}
	newLog := []drivers.SignedEventBytes{req.NewRootFounding, req.NewRootInteraction}
	if err := verifyLog(c.icp.Identifier, newLog); err != nil {
		return nil, fmt.Errorf("the new root's log does not verify: %w", err)
	}

	// The identity kept here is the old root, or, once an earlier run moved
	// it, the new root, which that run could only have done after the rotation
	// was in the old root's log and the founding in the new root's.
	switch identity.AID {
	case c.oldRootAID:
	case c.icp.Identifier:
		founded, err := st.GetEvents(c.icp.Identifier)
		if err != nil {
			return nil, fmt.Errorf("load KEL events: %w", err)
		}
		if !rotAdded || len(founded) == 0 {
			return nil, fmt.Errorf("the identity kept here is %s, which this rotation does not found", identity.AID)
		}
		c.moved, c.rotatedAt = true, identity.Created
	default:
		return nil, fmt.Errorf("old_root_rotation is of %s, not the identity kept here, %s", c.rot.Identifier, identity.AID)
	}
	return c, nil
}

// CheckRootAIDRotation judges a rotation request as RotateRootAID does before
// it writes anything, and says which root it moves on from. A caller that has
// to prepare something for the rotation (the server hands the new root's
// messaging keys over) does so only for a request that passes.
func CheckRootAIDRotation(req RootAIDRotationRequest, st RootRotationStore) (oldRootAID string, err error) {
	if err := validateRootAIDRotationRequest(req); err != nil {
		return "", err
	}
	checked, err := checkSignedRootRotation(req, st)
	if err != nil {
		return "", err
	}
	return checked.oldRootAID, nil
}

// saidOfRecord is the digest of a kept event.
func saidOfRecord(rec store.EventRecord) (string, error) {
	var ked struct {
		D string `json:"d"`
	}
	if err := json.Unmarshal([]byte(rec.EventJSON), &ked); err != nil || ked.D == "" {
		return "", fmt.Errorf("the event at sequence number %d is kept without its digest", rec.SequenceNumber)
	}
	return ked.D, nil
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
	OldRootAID               string
	NewRootAID               string
	NewInceptionSAID         string
	NewInceptionRawB64       string
	NewInceptionSignatures   []string
	AuthorizationEventRawB64 string
	AuthorizationSignatures  []string
	AuthorizationEventSAID   string
	BackAnchorEventRawB64    string
	BackAnchorSignatures     []string
	BackAnchorEventSAID      string
	OldRootLog               []drivers.SignedEventBytes
	PriorKelTailSAID         string
	RotatedAt                string
	RecoverySessionID        string
	CarryForwardAIDs         []string
	WitnessThreshold         int
}

// BuildDelegationAnchorSeal returns the rot/ixn seal authorizing a new root inception.
// Format: [{"d":"<new_inception_said>"}] per keripy eventing.rotate/interact data=….
func BuildDelegationAnchorSeal(newInceptionSAID string) []interface{} {
	return []interface{}{
		map[string]interface{}{"d": newInceptionSAID},
	}
}

// BuildContinuityBackReferenceSeal returns the new→old back-reference seal: the
// digest of the old root's tip after the rotation, which is the rotation.
func BuildContinuityBackReferenceSeal(oldRootTipSAID string) []interface{} {
	return BuildDelegationAnchorSeal(oldRootTipSAID)
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
		V:                        continuityProofVersion,
		OldRootAID:               in.OldRootAID,
		NewRootAID:               in.NewRootAID,
		NewInceptionSAID:         in.NewInceptionSAID,
		NewInceptionRawB64:       in.NewInceptionRawB64,
		NewInceptionSignatures:   append([]string(nil), in.NewInceptionSignatures...),
		AuthorizationEventRawB64: in.AuthorizationEventRawB64,
		AuthorizationSignatures:  append([]string(nil), in.AuthorizationSignatures...),
		AuthorizationEventSAID:   in.AuthorizationEventSAID,
		BackAnchorEventRawB64:    in.BackAnchorEventRawB64,
		BackAnchorSignatures:     append([]string(nil), in.BackAnchorSignatures...),
		BackAnchorEventSAID:      in.BackAnchorEventSAID,
		OldRootLog:               append([]drivers.SignedEventBytes(nil), in.OldRootLog...),
		PriorKelTailSAID:         in.PriorKelTailSAID,
		RotatedAt:                in.RotatedAt,
		RecoverySessionID:        in.RecoverySessionID,
		CarryForwardAIDs:         append([]string(nil), in.CarryForwardAIDs...),
		WitnessThreshold:         in.WitnessThreshold,
	}
}

// VerifyContinuityProof checks a proof from what it carries alone: each
// event's digest is recomputed from its bytes; the new root's two events are
// judged as a signed log of their own; and the old root's log up to and
// including the authorization rotation is judged from the old root's inception,
// so the rotation is shown to be signed by the key the old root committed to,
// at the threshold the log set, and to follow the event the proof names as the
// tail it follows (PriorKelTailSAID).
func VerifyContinuityProof(p ContinuityProof) error {
	read := func(label, rawB64, ilk, said string) ([]byte, *keri.Event, error) {
		raw, err := base64.StdEncoding.Strict().DecodeString(rawB64)
		if err != nil || len(raw) == 0 {
			return nil, nil, fmt.Errorf("%s: raw bytes are not standard base64", label)
		}
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", label, err)
		}
		if ev.Ilk != ilk {
			return nil, nil, fmt.Errorf("%s is a %s, not a %s", label, ev.Ilk, ilk)
		}
		got, err := keri.ComputeSAID(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", label, err)
		}
		if got != said || ev.SAID != said {
			return nil, nil, fmt.Errorf("%s: its bytes digest to %s, the proof says %s", label, got, said)
		}
		return raw, ev, nil
	}
	icpRaw, icp, err := read("new inception", p.NewInceptionRawB64, "icp", p.NewInceptionSAID)
	if err != nil {
		return err
	}
	rotRaw, rot, err := read("authorization event", p.AuthorizationEventRawB64, "rot", p.AuthorizationEventSAID)
	if err != nil {
		return err
	}
	ixnRaw, ixn, err := read("back-anchor event", p.BackAnchorEventRawB64, "ixn", p.BackAnchorEventSAID)
	if err != nil {
		return err
	}
	if icp.Identifier != p.NewRootAID || rot.Identifier != p.OldRootAID || ixn.Identifier != icp.Identifier ||
		ixn.SN != 1 || ixn.PriorSAID != icp.SAID {
		return fmt.Errorf("the events are not the ones that tie %s to %s", p.OldRootAID, p.NewRootAID)
	}
	var rotKED, ixnKED map[string]interface{}
	if err := json.Unmarshal(rotRaw, &rotKED); err != nil {
		return err
	}
	if err := json.Unmarshal(ixnRaw, &ixnKED); err != nil {
		return err
	}
	if err := ValidateAuthorizationEvent(p.OldRootAID, icp.SAID, rotKED); err != nil {
		return err
	}
	if back := anchorsOf(ixnKED); len(back) != 1 || back[0]["d"] != rot.SAID {
		return fmt.Errorf("the back-anchor event does not seal the authorization event")
	}
	icpMsg, err := drivers.SignedMessage(icpRaw, p.NewInceptionSignatures)
	if err != nil {
		return fmt.Errorf("new inception: %w", err)
	}
	ixnMsg, err := drivers.SignedMessage(ixnRaw, p.BackAnchorSignatures)
	if err != nil {
		return fmt.Errorf("back-anchor event: %w", err)
	}
	if _, err := keri.ValidateSignedKEL([][]byte{icpMsg, ixnMsg}); err != nil {
		return fmt.Errorf("the new root's events do not verify: %w", err)
	}

	// The old root's log, from its inception, with the rotation as its last
	// event: the rotation is judged by the log's own rules, as any verifier
	// judges a rotation, not by the key the rotation names for itself.
	if len(p.OldRootLog) == 0 {
		return fmt.Errorf("the proof carries none of the old root's log, so the rotation cannot be shown to be the old root's")
	}
	if p.PriorKelTailSAID == "" || rot.PriorSAID != p.PriorKelTailSAID || int(rot.SN) != len(p.OldRootLog) {
		return fmt.Errorf("the authorization event follows %s at sequence number %x, not the tail the proof names (%s) of a log of %d events",
			rot.PriorSAID, rot.SN, p.PriorKelTailSAID, len(p.OldRootLog))
	}
	tailRaw, err := base64.StdEncoding.Strict().DecodeString(p.OldRootLog[len(p.OldRootLog)-1].RawB64)
	if err != nil {
		return fmt.Errorf("the old root's log: the last event is not standard base64")
	}
	if tail, err := keri.ComputeSAID(tailRaw); err != nil || tail != p.PriorKelTailSAID {
		return fmt.Errorf("the old root's log ends at %s, not at the tail the proof names (%s)", tail, p.PriorKelTailSAID)
	}
	authorization := drivers.SignedEventBytes{RawB64: p.AuthorizationEventRawB64, Sigs: p.AuthorizationSignatures}
	if err := verifyLog(p.OldRootAID, append(append([]drivers.SignedEventBytes(nil), p.OldRootLog...), authorization)); err != nil {
		return fmt.Errorf("the old root's log with the authorization event does not verify: %w", err)
	}
	return nil
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

// dispatchNotifications queues one task per party to tell, each carrying the
// continuity proof (the line after the first of its detail). A task's id is
// fixed by the new root and the party, so queuing again replaces a task rather
// than adding one. Nothing sends them here.
func (s *RootAIDRotationService) dispatchNotifications(st RootRotationStore, set *NotifySet, proof ContinuityProof) (int, error) {
	if set == nil {
		return 0, nil
	}
	proofJSON, err := json.Marshal(proof)
	if err != nil {
		return 0, fmt.Errorf("marshal continuity proof: %w", err)
	}

	sent := 0
	for _, party := range set.All() {
		target := party.AID
		if target == "" {
			target = party.URL
		}
		task := store.TaskRecord{
			ID:         fmt.Sprintf("root-aid-notify-%s-%s-%s", proof.NewRootAID, party.Kind, target),
			Type:       rootAIDRotationTaskType,
			Status:     "pending",
			ContactAID: party.AID,
			Detail: fmt.Sprintf("notify %s (%s) of new root %s with signed delegation anchor\n%s",
				party.Kind, target, proof.NewRootAID, proofJSON),
			CreatedAt: proof.RotatedAt,
			UpdatedAt: proof.RotatedAt,
		}
		if err := st.SaveTask(task); err != nil {
			return sent, fmt.Errorf("queue notify task for %s: %w", target, err)
		}
		sent++
	}
	return sent, nil
}

// ContinuityProofOfTask reads the proof a notification task carries.
func ContinuityProofOfTask(task store.TaskRecord) (ContinuityProof, error) {
	var p ContinuityProof
	_, body, found := strings.Cut(task.Detail, "\n")
	if !found {
		return p, fmt.Errorf("task %s carries no continuity proof", task.ID)
	}
	err := json.Unmarshal([]byte(body), &p)
	return p, err
}

// rootAIDMapMu serialises the writes of the map: the rotation appends and the
// witnessing worker marks, and neither may overwrite the other's change.
var rootAIDMapMu sync.Mutex

// RecordRootAIDWitnessing marks the entry of oldRootAID's rotation authorised by
// authorizationSAID as witnessed (its witnesses hold the log) or, when
// gaveUp, as no longer tried, at the time given.
func RecordRootAIDWitnessing(dataDir, oldRootAID, authorizationSAID string, gaveUp bool, at time.Time) error {
	rootAIDMapMu.Lock()
	defer rootAIDMapMu.Unlock()
	m, err := LoadRootAIDMap(dataDir)
	if err != nil {
		return err
	}
	for i, e := range m.Entries {
		if e.OldRootAID != oldRootAID || e.AuthorizationEventSAID != authorizationSAID {
			continue
		}
		if gaveUp {
			m.Entries[i].WitnessingGaveUpAt = at.UTC().Format(time.RFC3339)
		} else {
			m.Entries[i].WitnessedAt = at.UTC().Format(time.RFC3339)
		}
		return writeRootAIDMap(dataDir, m)
	}
	return nil
}

func writeRootAIDMap(dataDir string, m *RootAIDMap) error {
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal root aid map: %w", err)
	}
	// Written whole beside the file and renamed over it: the witnessing worker
	// reads the map while the rotation or the worker writes it.
	path := filepath.Join(dataDir, rootAIDMapFileName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0600); err != nil {
		return fmt.Errorf("write root aid map: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("write root aid map: %w", err)
	}
	return nil
}

func appendRootAIDMapEntry(dataDir string, entry RootAIDMapEntry) error {
	if dataDir == "" {
		return fmt.Errorf("data directory is required")
	}
	rootAIDMapMu.Lock()
	defer rootAIDMapMu.Unlock()
	path := filepath.Join(dataDir, rootAIDMapFileName)

	var existing RootAIDMap
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &existing)
	}
	if existing.Version == 0 {
		existing.Version = 1
	}
	for _, e := range existing.Entries {
		if e.OldRootAID == entry.OldRootAID && e.NewRootAID == entry.NewRootAID &&
			e.AuthorizationEventSAID == entry.AuthorizationEventSAID {
			// A run that stopped after writing this entry, sent again.
			return nil
		}
	}
	existing.Entries = append(existing.Entries, entry)
	return writeRootAIDMap(dataDir, &existing)
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
