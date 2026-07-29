package witness

import (
	"context"
	"testing"

	"identity-agent-core/store"
)

type memContacts struct {
	contacts map[string]store.ContactRecord
	identity *store.IdentityState
	tasks    []store.TaskRecord
}

func (m *memContacts) GetContacts() ([]store.ContactRecord, error) {
	var out []store.ContactRecord
	for _, c := range m.contacts {
		out = append(out, c)
	}
	return out, nil
}

func (m *memContacts) GetContact(aid string) (*store.ContactRecord, error) {
	c, ok := m.contacts[aid]
	if !ok {
		return nil, nil
	}
	return &c, nil
}

func (m *memContacts) SaveContact(c store.ContactRecord) error {
	m.contacts[c.AID] = c
	return nil
}

func (m *memContacts) GetIdentity() (*store.IdentityState, error) {
	return m.identity, nil
}

func (m *memContacts) SaveWitnessReceipt(store.WitnessReceiptRecord) error { return nil }
func (m *memContacts) SaveTask(t store.TaskRecord) error {
	if m.tasks == nil {
		m.tasks = []store.TaskRecord{}
	}
	for i, existing := range m.tasks {
		if existing.ID == t.ID {
			m.tasks[i] = t
			return nil
		}
	}
	m.tasks = append(m.tasks, t)
	return nil
}
func (m *memContacts) GetTasks() ([]store.TaskRecord, error) { return m.tasks, nil }

func testService(t *testing.T) (*Service, *memContacts) {
	t.Helper()
	st := setupTestSQLite(t)
	mc := &memContacts{
		contacts: make(map[string]store.ContactRecord),
		identity: &store.IdentityState{AID: "ERootAID0123456789ABCDEFGHIJKLMN"},
	}
	s := NewService(st, mc, nil, BackendDesktop)
	s.OurAID = func() string { return mc.identity.AID }
	return s, mc
}

func TestMobileBackendRejected(t *testing.T) {
	s, _ := testService(t)
	ok, reason := s.EvaluateRequest("ESigner", "http://x/oobi", BackendMobile)
	if ok || reason != "mobile_backend" {
		t.Fatalf("ok=%v reason=%s", ok, reason)
	}
}

func TestTransactionalContactIneligible(t *testing.T) {
	c := store.ContactRecord{Status: "accepted", ContactCategory: "general", ContactSource: ContactSourceTransactional}
	if IsContactWitnessEligible(c) {
		t.Fatal("transactional must be excluded")
	}
}

func TestReceiveEventSequenceGap(t *testing.T) {
	s, mc := testService(t)
	signer := "ESignerAID0123456789ABCDEFGHIJKLMN"
	mc.contacts[signer] = store.ContactRecord{AID: signer, Status: "accepted"}
	_ = s.Store.SaveContactMeta(ContactMeta{ContactAID: signer, WitnessingFor: true, BackendType: BackendDesktop})
	_ = s.Store.StoreKelEvent(KelEvent{SignerAID: signer, SequenceNum: 0, EventJSON: `{"i":"` + signer + `","s":"0","t":"icp"}`, StoredAt: NowRFC3339()})
	_, err := s.ReceiveEvent(signer, map[string]interface{}{"i": signer, "s": "2", "t": "rot"})
	if err == nil || err.Error() != "sequence_gap" {
		t.Fatalf("err=%v want sequence_gap", err)
	}
}

func TestReceiveEventUnknownSigner(t *testing.T) {
	s, _ := testService(t)
	_, err := s.ReceiveEvent("EUnknown", map[string]interface{}{"i": "EUnknown", "s": "0", "t": "icp"})
	if err == nil || err.Error() != "not_witnessing" {
		t.Fatalf("err=%v", err)
	}
}

func TestPairwiseCommercialOnly(t *testing.T) {
	s, mc := testService(t)
	mc.contacts["EContact"] = store.ContactRecord{AID: "EContact", IsWitness: true, OobiURL: "http://c/oobi"}
	mc.contacts["ECommercial"] = store.ContactRecord{AID: "ECommercial", IsWitness: true, OobiURL: "http://m/oobi"}
	_ = s.Store.SaveContactMeta(ContactMeta{ContactAID: "EContact", BackendType: BackendDesktop, WitnessStatus: StatusOnline})
	_ = s.Store.SaveContactMeta(ContactMeta{ContactAID: "ECommercial", BackendType: BackendCommercial, IsCommercial: true, WitnessStatus: StatusOnline})
	targets, err := s.enrolledWitnesses(AidKindPairwise)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || !targets[0].Commercial {
		t.Fatalf("pairwise pool=%+v want commercial only", targets)
	}
}

func TestHealthRetentionDropsWitness(t *testing.T) {
	s, mc := testService(t)
	aid := "EWitnessContact0123456789ABCDEFGHIJ"
	mc.contacts[aid] = store.ContactRecord{AID: aid, IsWitness: true, Status: "accepted"}
	_ = s.Store.SaveContactMeta(ContactMeta{ContactAID: aid, BackendType: BackendDesktop, WitnessStatus: StatusOnline})
	for i := 0; i < OfflineFailureThreshold; i++ {
		s.RecordHeartbeatResult(aid, false)
	}
	c, _ := mc.GetContact(aid)
	if c.IsWitness {
		t.Fatal("HR1: flaky desktop witness must be dropped")
	}
}

func TestFinalizeThreshold(t *testing.T) {
	s, _ := testService(t)
	said := "EHtestevent"
	_ = s.Store.SaveFinalization(FinalizationState{
		EventSAID: said, SignerAID: "ERoot", SequenceNum: 1,
		State: FinalizePending, Threshold: 5, StartedAt: NowRFC3339(), UpdatedAt: NowRFC3339(),
	})
	for i := 0; i < 5; i++ {
		s.onReceipt(said, "EW"+string(rune('0'+i)), "")
	}
	f, _ := s.Store.GetFinalization(said)
	if f.State != FinalizeFinalized {
		t.Fatalf("state=%s want finalized", f.State)
	}
}

func TestMajorityThresholdFloor(t *testing.T) {
	if MajorityThreshold(9) != 5 {
		t.Fatalf("majority floor wrong")
	}
	if s := DefaultThreshold; s < 5 {
		t.Fatalf("default threshold %d below majority", s)
	}
}

func TestBroadcastSkipsOffline(t *testing.T) {
	s, mc := testService(t)
	root := mc.identity.AID
	mc.contacts["EW1"] = store.ContactRecord{AID: "EW1", IsWitness: true, OobiURL: "http://w1/oobi"}
	_ = s.Store.SaveContactMeta(ContactMeta{ContactAID: "EW1", WitnessStatus: StatusOffline, BackendType: BackendDesktop})
	targets, _ := s.enrolledWitnesses(ClassifyAID(root, root))
	for _, tg := range targets {
		if tg.AID == "EW1" {
			t.Fatalf("an offline witness was included: %+v", targets)
		}
	}
	// Previously this asserted zero targets. That was the intent stated as a
	// count, and the count stopped being right once a root identity falls back
	// to the bootstrap pool: an identity whose only contact witness is offline
	// is exactly the case bootstrap exists for, and having none at all is worse
	// than having those. The assertion now says what it always meant — the
	// offline one is excluded.
	if len(targets) == 0 {
		t.Fatal("with its only contact witness offline, a root identity fell back to nothing")
	}
}

func TestTELStubBlocked(t *testing.T) {
	s, _ := testService(t)
	out := s.ServeTELStub("EIssuer")
	if out["blocked"] != true {
		t.Fatal("TEL stub must report blocked")
	}
}

func TestSendWitnessRequestIneligible(t *testing.T) {
	s, mc := testService(t)
	aid := "EBad"
	mc.contacts[aid] = store.ContactRecord{AID: aid, Status: "accepted", ContactSource: ContactSourceTransactional}
	if err := s.SendWitnessRequest(context.Background(), aid); err == nil {
		t.Fatal("expected ineligible error")
	}
}