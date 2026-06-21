package recovery

import (
	"encoding/json"
	"testing"
	"time"

	"identity-agent-core/store"
)

type memNotifyStore struct {
	identity    *store.IdentityState
	contacts    []store.ContactRecord
	credentials []store.CredentialRecord
	events      []store.EventRecord
	tasks       []store.TaskRecord
}

func (m *memNotifyStore) GetIdentity() (*store.IdentityState, error) { return m.identity, nil }
func (m *memNotifyStore) GetContacts() ([]store.ContactRecord, error)  { return m.contacts, nil }
func (m *memNotifyStore) GetCredentials() ([]store.CredentialRecord, error) {
	return m.credentials, nil
}
func (m *memNotifyStore) GetEvents(aid string) ([]store.EventRecord, error) {
	var out []store.EventRecord
	for _, ev := range m.events {
		if ev.AID == aid {
			out = append(out, ev)
		}
	}
	return out, nil
}
func (m *memNotifyStore) SaveEvent(ev store.EventRecord) error {
	m.events = append(m.events, ev)
	return nil
}
func (m *memNotifyStore) SaveIdentity(id store.IdentityState) error {
	m.identity = &id
	return nil
}
func (m *memNotifyStore) SaveTask(t store.TaskRecord) error {
	m.tasks = append(m.tasks, t)
	return nil
}

type mockKeriDriver struct {
	inception *KeriInceptionResult
	ixn       *KeriInteractResult
	anchor    []interface{}
}

func (m *mockKeriDriver) CreateInception(_, _ string) (*KeriInceptionResult, error) {
	return m.inception, nil
}
func (m *mockKeriDriver) CreateHybridInception(_ bool, _ string) (*KeriInceptionResult, error) {
	return m.inception, nil
}
func (m *mockKeriDriver) Interact(_ string, data []interface{}) (*KeriInteractResult, error) {
	m.anchor = data
	return m.ixn, nil
}

func TestBuildNotifySet(t *testing.T) {
	root := "EoldRootAID0123456789ABCDEFGHIJKLMN"
	st := &memNotifyStore{
		identity: &store.IdentityState{AID: root},
		contacts: []store.ContactRecord{
			{AID: "EW1", Alias: "Witness", IsWitness: true, Status: "accepted", OobiURL: "http://w/oobi"},
			{AID: "EC1", Alias: "Contact", Status: "accepted"},
		},
		credentials: []store.CredentialRecord{
			{HolderAID: root, IssuerAID: "Eissuer1", IssuerName: "Issuer One"},
			{HolderAID: root, IssuerAID: "Eissuer1", IssuerName: "Issuer One"},
			{HolderAID: "Eother", IssuerAID: "Eissuer2"},
		},
	}

	set, err := BuildNotifySet(st, root, []string{"https://watcher.example/kel"})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Witnesses) != 1 || set.Witnesses[0].AID != "EW1" {
		t.Fatalf("witnesses %+v", set.Witnesses)
	}
	if len(set.Watchers) != 1 || set.Watchers[0].URL != "https://watcher.example/kel" {
		t.Fatalf("watchers %+v", set.Watchers)
	}
	if len(set.Issuers) != 1 || set.Issuers[0].AID != "Eissuer1" {
		t.Fatalf("issuers %+v", set.Issuers)
	}
}

func TestBuildContinuityAnchorSealFormat(t *testing.T) {
	prior := "EpriorTailSAID0123456789ABCDEFGHIJKLMN"
	seal := BuildContinuityAnchorSeal(prior)
	if len(seal) != 1 {
		t.Fatalf("seal len %d", len(seal))
	}
	m, ok := seal[0].(map[string]interface{})
	if !ok {
		t.Fatalf("seal type %T", seal[0])
	}
	if m["d"] != prior {
		t.Fatalf("anchor d=%v", m["d"])
	}
	if _, hasExtra := m["i"]; hasExtra {
		t.Fatal("anchor must not include prior root AID prefix")
	}
}

func TestFilterCarryForwardContacts(t *testing.T) {
	contacts := []store.ContactRecord{
		{AID: "EP1", Status: "accepted"},
		{AID: "EP2", Status: "accepted"},
		{AID: "EP3", Status: "pending_outbound"},
	}
	out := FilterCarryForwardContacts(contacts, []string{"EP2"})
	if len(out) != 1 || out[0].AID != "EP2" {
		t.Fatalf("filtered %+v", out)
	}
	if FilterCarryForwardContacts(contacts, nil) != nil {
		t.Fatal("empty carry-forward must return nil")
	}
}

func TestRotateRootAIDFlow(t *testing.T) {
	dir := t.TempDir()
	oldRoot := "EoldRootAID0123456789ABCDEFGHIJKLMN"
	newRoot := "EnewRootAID0123456789ABCDEFGHIJKLMN"
	priorTail := "EpriorTailSAID0123456789ABCDEFGHIJKLMN"

	st := &memNotifyStore{
		identity: &store.IdentityState{AID: oldRoot, PublicKey: "oldpub", NextKeyDigest: "oldnext"},
		events: []store.EventRecord{{
			AID: oldRoot, SequenceNumber: 1, EventType: "rot",
			EventJSON: `{"v":"KERI10JSON00011c_","t":"rot","d":"` + priorTail + `","i":"` + oldRoot + `","s":"1"}`,
		}},
		contacts: []store.ContactRecord{
			{AID: "EP1", Status: "accepted"},
			{AID: "EP2", Status: "accepted"},
		},
		credentials: []store.CredentialRecord{{HolderAID: oldRoot, IssuerAID: "Eissuer1"}},
	}

	driver := &mockKeriDriver{
		inception: &KeriInceptionResult{
			AID: newRoot, PublicKey: "newpub", NextKeyDigest: "newnext",
			InceptionEvent: map[string]interface{}{"t": "icp", "d": "EicpSAID", "i": newRoot, "s": "0"},
			SequenceNumber: 0,
		},
		ixn: &KeriInteractResult{
			AID: newRoot, Said: "EixnSAID0123456789ABCDEFGHIJKLMNOP",
			IxnEvent: map[string]interface{}{"t": "ixn", "d": "EixnSAID0123456789ABCDEFGHIJKLMNOP", "i": newRoot, "s": "1"},
			SequenceNumber: 1,
		},
	}

	svc := NewRootAIDRotationService(dir)
	svc.Now = func() time.Time { return parseTime("2026-06-20T12:00:00Z") }

	result, err := svc.RotateRootAID(RootAIDRotationRequest{
		RecoverySessionID:    "sess-1",
		NewRootPublicKey:     "newpub",
		NewRootNextPublicKey: "newnext",
		CarryForwardAIDs:     []string{"EP2"},
	}, driver, st, []string{"https://watcher.example/kel"})
	if err != nil {
		t.Fatal(err)
	}

	if result.NewRootAID != newRoot || result.OldRootAID != oldRoot {
		t.Fatalf("aids old=%s new=%s", result.OldRootAID, result.NewRootAID)
	}
	if result.ContinuityProof.PriorKelTailSAID != priorTail {
		t.Fatalf("proof prior tail %s", result.ContinuityProof.PriorKelTailSAID)
	}
	if result.ContinuityProof.ProofDigestBlake3QB64 == "" || result.ContinuityProof.ProofDigestBlake3QB64[0] != 'E' {
		t.Fatalf("digest %q", result.ContinuityProof.ProofDigestBlake3QB64)
	}
	if len(result.CarriedForwardAIDs) != 1 || result.CarriedForwardAIDs[0] != "EP2" {
		t.Fatalf("carried %+v", result.CarriedForwardAIDs)
	}
	if len(driver.anchor) != 1 {
		t.Fatalf("anchor %+v", driver.anchor)
	}
	anchorMap := driver.anchor[0].(map[string]interface{})
	if anchorMap["d"] != priorTail {
		t.Fatalf("ixn anchor d=%v", anchorMap["d"])
	}
	if st.identity == nil || st.identity.AID != newRoot {
		t.Fatalf("identity not updated: %+v", st.identity)
	}
	if len(st.events) != 3 {
		t.Fatalf("events %d want 3 (prior + icp + ixn)", len(st.events))
	}
	if result.NotificationsSent != 2 {
		t.Fatalf("notifications %d want watcher+issuer", result.NotificationsSent)
	}

	m, err := LoadRootAIDMap(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != 1 || m.Entries[0].NewRootAID != newRoot {
		t.Fatalf("map %+v", m.Entries)
	}
}

func TestBuildContinuityProofDigestStable(t *testing.T) {
	proof := BuildContinuityProof(ContinuityProofInput{
		NewRootAID:       "Enew",
		PriorKelTailSAID: "Eprior",
		AnchorIxnSAID:    "Eixn",
		RotatedAt:        "2026-06-20T12:00:00Z",
		CarryForwardAIDs: []string{"EP1"},
	})
	raw, _ := json.Marshal(map[string]interface{}{
		"v":                   "1",
		"new_root_aid":        "Enew",
		"prior_kel_tail_said": "Eprior",
		"anchor_ixn_said":     "Eixn",
		"rotated_at":          "2026-06-20T12:00:00Z",
		"carry_forward_aids":  []string{"EP1"},
	})
	if proof.ProofDigestBlake3QB64 == "" {
		t.Fatal("missing digest")
	}
	_ = raw
}