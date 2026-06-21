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
	inception    *KeriInceptionResult
	rot          *KeriRotationResult
	ixn          *KeriInteractResult
	authAnchor   []interface{}
	backAnchor   []interface{}
}

func (m *mockKeriDriver) CreateInception(_, _ string) (*KeriInceptionResult, error) {
	return m.inception, nil
}
func (m *mockKeriDriver) CreateHybridInception(_ bool, _ string) (*KeriInceptionResult, error) {
	return m.inception, nil
}
func (m *mockKeriDriver) RotateWithAnchor(_ string, _, _ string, data []interface{}) (*KeriRotationResult, error) {
	m.authAnchor = data
	return m.rot, nil
}
func (m *mockKeriDriver) Interact(_ string, data []interface{}) (*KeriInteractResult, error) {
	m.backAnchor = data
	return m.ixn, nil
}

func withRootAIDRotationEnabled(t *testing.T, fn func()) {
	t.Helper()
	prev := RootAIDRotationEnabled
	RootAIDRotationEnabled = true
	t.Cleanup(func() { RootAIDRotationEnabled = prev })
	fn()
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

func TestBuildDelegationAnchorSealFormat(t *testing.T) {
	newInception := "EnewInceptionSAID0123456789ABCDEFGHIJKLMN"
	seal := BuildDelegationAnchorSeal(newInception)
	if len(seal) != 1 {
		t.Fatalf("seal len %d", len(seal))
	}
	m, ok := seal[0].(map[string]interface{})
	if !ok {
		t.Fatalf("seal type %T", seal[0])
	}
	if m["d"] != newInception {
		t.Fatalf("anchor d=%v", m["d"])
	}
	if _, hasExtra := m["i"]; hasExtra {
		t.Fatal("anchor must not include AID prefix in seal dict")
	}
}

func TestValidateAuthorizationEvent(t *testing.T) {
	oldRoot := "EoldRootAID0123456789ABCDEFGHIJKLMN"
	newInception := "EnewInceptionSAID0123456789ABCDEFGHIJKLMN"
	valid := map[string]interface{}{
		"t": "rot",
		"i": oldRoot,
		"a": []interface{}{map[string]interface{}{"d": newInception}},
	}
	if err := ValidateAuthorizationEvent(oldRoot, newInception, valid); err != nil {
		t.Fatal(err)
	}
	bad := map[string]interface{}{
		"t": "ixn",
		"i": oldRoot,
		"a": []interface{}{map[string]interface{}{"d": newInception}},
	}
	if err := ValidateAuthorizationEvent(oldRoot, newInception, bad); err == nil {
		t.Fatal("ixn must not pass authorization validation")
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

func TestRootAIDRotationGatedWhenDisabled(t *testing.T) {
	if RootAIDRotationAvailable() {
		t.Fatal("root-AID rotation must be gated by default")
	}
	st := &memNotifyStore{
		identity: &store.IdentityState{AID: "EoldRootAID0123456789ABCDEFGHIJKLMN"},
	}
	_, err := RotateRootAID(RootAIDRotationRequest{RecoverySessionID: "sess-1"}, &mockKeriDriver{}, st, t.TempDir(), nil)
	if err == nil {
		t.Fatal("gated rotation must error")
	}
}

func TestRotateRootAIDFlow(t *testing.T) {
	withRootAIDRotationEnabled(t, func() {
		dir := t.TempDir()
		oldRoot := "EoldRootAID0123456789ABCDEFGHIJKLMN"
		newRoot := "EnewRootAID0123456789ABCDEFGHIJKLMN"
		priorTail := "EpriorTailSAID0123456789ABCDEFGHIJKLMN"
		newInception := "EicpSAID0123456789ABCDEFGHIJKLMNOP"
		authSAID := "EauthRotSAID0123456789ABCDEFGHIJKLMN"
		authSig := "0BsigCESRsignatureExample"

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
				InceptionEvent: map[string]interface{}{"t": "icp", "d": newInception, "i": newRoot, "s": "0"},
				InceptionSAID:  newInception,
				SequenceNumber: 0,
			},
			rot: &KeriRotationResult{
				AID: oldRoot, NewPublicKey: "prerotpub", NewNextKeyDigest: "prerotnext",
				RotationEvent: map[string]interface{}{
					"t": "rot", "d": authSAID, "i": oldRoot, "s": "2",
					"a": []interface{}{map[string]interface{}{"d": newInception}},
				},
				RotationSAID:   authSAID,
				SequenceNumber: 2,
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
			RecoverySessionID:          "sess-1",
			NewRootPublicKey:           "newpub",
			NewRootNextPublicKey:       "newnext",
			PreRotationPublicKey:       "prerotpub",
			PreRotationNextPublicKey:   "prerotnext",
			AuthorizationCesrSignature: authSig,
			CarryForwardAIDs:           []string{"EP2"},
		}, driver, st, []string{"https://watcher.example/kel"})
		if err != nil {
			t.Fatal(err)
		}

		if result.NewRootAID != newRoot || result.OldRootAID != oldRoot {
			t.Fatalf("aids old=%s new=%s", result.OldRootAID, result.NewRootAID)
		}
		if result.ContinuityProof.V != "2" {
			t.Fatalf("proof version %s", result.ContinuityProof.V)
		}
		if result.ContinuityProof.NewInceptionSAID != newInception {
			t.Fatalf("new inception %s", result.ContinuityProof.NewInceptionSAID)
		}
		if result.ContinuityProof.AuthorizationEventSAID != authSAID {
			t.Fatalf("auth said %s", result.ContinuityProof.AuthorizationEventSAID)
		}
		if result.ContinuityProof.AuthorizationCesrSignature != authSig {
			t.Fatalf("auth sig %s", result.ContinuityProof.AuthorizationCesrSignature)
		}
		if result.ContinuityProof.PriorKelTailSAID != priorTail {
			t.Fatalf("proof prior tail %s", result.ContinuityProof.PriorKelTailSAID)
		}
		if len(result.CarriedForwardAIDs) != 1 || result.CarriedForwardAIDs[0] != "EP2" {
			t.Fatalf("carried %+v", result.CarriedForwardAIDs)
		}
		if len(driver.authAnchor) != 1 {
			t.Fatalf("auth anchor %+v", driver.authAnchor)
		}
		authMap := driver.authAnchor[0].(map[string]interface{})
		if authMap["d"] != newInception {
			t.Fatalf("rot anchor d=%v", authMap["d"])
		}
		if len(driver.backAnchor) != 1 {
			t.Fatalf("back anchor %+v", driver.backAnchor)
		}
		backMap := driver.backAnchor[0].(map[string]interface{})
		if backMap["d"] != priorTail {
			t.Fatalf("ixn back anchor d=%v", backMap["d"])
		}
		if st.identity == nil || st.identity.AID != newRoot {
			t.Fatalf("identity not updated: %+v", st.identity)
		}
		if len(st.events) != 4 {
			t.Fatalf("events %d want 4 (prior + auth rot + icp + ixn)", len(st.events))
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
		if m.Entries[0].AuthorizationEventSAID != authSAID {
			t.Fatalf("map auth said %s", m.Entries[0].AuthorizationEventSAID)
		}
	})
}

func TestBuildContinuityProofV2(t *testing.T) {
	proof := BuildContinuityProof(ContinuityProofInput{
		OldRootAID:                 "Eold",
		NewRootAID:                 "Enew",
		NewInceptionSAID:           "Eicp",
		AuthorizationEvent:         map[string]interface{}{"t": "rot", "d": "Eauth"},
		AuthorizationCesrSignature: "0Bsig",
		AuthorizationEventSAID:     "Eauth",
		BackAnchorEventSAID:        "Eixn",
		PriorKelTailSAID:           "Eprior",
		RotatedAt:                  "2026-06-20T12:00:00Z",
		CarryForwardAIDs:           []string{"EP1"},
	})
	if proof.V != "2" {
		t.Fatalf("version %s", proof.V)
	}
	if proof.AuthorizationEventSAID != "Eauth" {
		t.Fatalf("auth said %s", proof.AuthorizationEventSAID)
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["authorization_event_said"] != "Eauth" {
		t.Fatalf("json %+v", decoded)
	}
}