package witness

import (
	"context"
	keri "github.com/grapeid/keri-go"
	"sync"
	"testing"

	"identity-agent-core/store"
)

type memContacts struct {
	// mu: the service reads contacts from goroutines it starts, such as a
	// reciprocal witness request, while a test is still writing them.
	mu       sync.Mutex
	contacts map[string]store.ContactRecord
	identity *store.IdentityState
	tasks    []store.TaskRecord
	receipts map[string]store.WitnessReceiptRecord
}

func (m *memContacts) GetContacts() ([]store.ContactRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.ContactRecord
	for _, c := range m.contacts {
		out = append(out, c)
	}
	return out, nil
}

func (m *memContacts) GetContact(aid string) (*store.ContactRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.contacts[aid]
	if !ok {
		return nil, nil
	}
	return &c, nil
}

func (m *memContacts) SaveContact(c store.ContactRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.contacts[c.AID] = c
	return nil
}

func (m *memContacts) GetIdentity() (*store.IdentityState, error) {
	return m.identity, nil
}

func (m *memContacts) SaveWitnessReceipt(r store.WitnessReceiptRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.receipts == nil {
		m.receipts = map[string]store.WitnessReceiptRecord{}
	}
	m.receipts[r.EventSAID+"|"+r.WitnessAID] = r
	return nil
}

func (m *memContacts) GetWitnessReceipts(said string) ([]store.WitnessReceiptRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.WitnessReceiptRecord
	for _, r := range m.receipts {
		if r.EventSAID == said {
			out = append(out, r)
		}
	}
	return out, nil
}
func (m *memContacts) SaveTask(t store.TaskRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
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
func (m *memContacts) GetTasks() ([]store.TaskRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tasks, nil
}

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
	_, err := s.ReceiveEvent(signer,
		[]byte(`{"i":"`+signer+`","s":"2","t":"rot"}`), "0Bsignature-placeholder")
	if err == nil || err.Error() != "sequence_gap" {
		t.Fatalf("err=%v want sequence_gap", err)
	}
}

func TestReceiveEventUnknownSigner(t *testing.T) {
	s, _ := testService(t)
	_, err := s.ReceiveEvent("EUnknown",
		[]byte(`{"i":"EUnknown","s":"0","t":"icp"}`), "0Bsignature-placeholder")
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
	targets, err := s.enrolledWitnesses(AidKindPairwise, "EPairwiseTestAID")
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
	var designated []string
	var ws []testWitness
	for i := 0; i < 5; i++ {
		w := newTestWitness(t)
		ws = append(ws, w)
		designated = append(designated, w.aid)
	}
	for _, w := range ws {
		s.onReceipt(said, w.aid, w.sign(said), designated)
	}
	f, _ := s.Store.GetFinalization(said)
	if f.State != FinalizeFinalized || f.ReceiptCount != 5 {
		t.Fatalf("state=%s count=%d want finalized with 5", f.State, f.ReceiptCount)
	}
}

type testWitness struct {
	aid  string
	sign func(said string) string
}

func newTestWitness(t *testing.T) testWitness {
	t.Helper()
	sg, err := keri.GenerateSigner(false)
	if err != nil {
		t.Fatal(err)
	}
	aid, err := sg.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return testWitness{aid: aid, sign: func(said string) string {
		raw, err := sg.Sign([]byte(said))
		if err != nil {
			t.Fatal(err)
		}
		q, err := keri.MatterQB64(keri.CodeEd25519Sig, raw)
		if err != nil {
			t.Fatal(err)
		}
		return q
	}}
}

func pendingEvent(t *testing.T, s *Service, said string, threshold int) {
	t.Helper()
	_ = s.Store.SaveFinalization(FinalizationState{
		EventSAID: said, SignerAID: "ERoot", SequenceNum: 1,
		State: FinalizePending, Threshold: threshold, StartedAt: NowRFC3339(), UpdatedAt: NowRFC3339(),
	})
}

// One witness answering twice is one receipt, so it cannot meet a threshold of two.
func TestOneWitnessReceiptingTwiceCountsOnce(t *testing.T) {
	s, _ := testService(t)
	const said = "EHtwice"
	pendingEvent(t, s, said, 2)
	w, other := newTestWitness(t), newTestWitness(t)
	des := []string{w.aid, other.aid}
	s.onReceipt(said, w.aid, w.sign(said), des)
	s.onReceipt(said, w.aid, w.sign(said), des)
	f, _ := s.Store.GetFinalization(said)
	if f.ReceiptCount != 1 || f.State == FinalizeFinalized {
		t.Fatalf("count=%d state=%s: one witness counted twice", f.ReceiptCount, f.State)
	}
	s.onReceipt(said, other.aid, other.sign(said), des)
	f, _ = s.Store.GetFinalization(said)
	if f.ReceiptCount != 2 || f.State != FinalizeFinalized {
		t.Fatalf("count=%d state=%s: two distinct designated witnesses should finalize", f.ReceiptCount, f.State)
	}
}

// A genuine signature from a witness the identity did not designate is not kept or counted.
func TestAReceiptFromAnUndesignatedWitnessIsRefused(t *testing.T) {
	s, mc := testService(t)
	const said = "EHundesignated"
	pendingEvent(t, s, said, 1)
	named, stranger := newTestWitness(t), newTestWitness(t)
	s.onReceipt(said, stranger.aid, stranger.sign(said), []string{named.aid})
	f, _ := s.Store.GetFinalization(said)
	if f.ReceiptCount != 0 || f.State == FinalizeFinalized {
		t.Fatalf("count=%d state=%s: an undesignated witness was counted", f.ReceiptCount, f.State)
	}
	if held, _ := mc.GetWitnessReceipts(said); len(held) != 0 {
		t.Fatalf("an undesignated witness's receipt was kept: %+v", held)
	}
}

// A designated witness's signature over some other event is refused.
func TestAReceiptOverADifferentEventIsRefused(t *testing.T) {
	s, mc := testService(t)
	const said = "EHreal"
	pendingEvent(t, s, said, 1)
	w := newTestWitness(t)
	s.onReceipt(said, w.aid, w.sign("EHsomethingelse"), []string{w.aid})
	if held, _ := mc.GetWitnessReceipts(said); len(held) != 0 {
		t.Fatalf("a receipt over another event was kept: %+v", held)
	}
	f, _ := s.Store.GetFinalization(said)
	if f.ReceiptCount != 0 {
		t.Fatalf("count=%d", f.ReceiptCount)
	}
}

// Two events of the same length never share an identifier, and one with none
// is an error rather than an invented name.
func TestEventSAIDIsNeverInvented(t *testing.T) {
	a := map[string]interface{}{"t": "ixn", "i": "EAAAA", "s": "1"}
	b := map[string]interface{}{"t": "ixn", "i": "EBBBB", "s": "1"}
	if _, err := eventSAID(a); err == nil {
		t.Fatal("an event with no d field was given an identifier")
	}
	if _, err := eventSAID(b); err == nil {
		t.Fatal("an event with no d field was given an identifier")
	}
	a["d"], b["d"] = "EDigestA", "EDigestB"
	x, _ := eventSAID(a)
	y, _ := eventSAID(b)
	if x == y || x != "EDigestA" {
		t.Fatalf("identifiers %q %q", x, y)
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
	targets, _ := s.enrolledWitnesses(ClassifyAID(root, root), root)
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
