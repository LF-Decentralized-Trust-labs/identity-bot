package witness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/store"
)

// ContactStore is the contacts read/write surface.
type ContactStore interface {
	GetContacts() ([]store.ContactRecord, error)
	GetContact(aid string) (*store.ContactRecord, error)
	SaveContact(contact store.ContactRecord) error
	GetIdentity() (*store.IdentityState, error)
	SaveWitnessReceipt(rec store.WitnessReceiptRecord) error
	SaveTask(task store.TaskRecord) error
	GetTasks() ([]store.TaskRecord, error)
}

// EventPoster broadcasts to remote witness HTTP endpoints.
type EventPoster func(ctx context.Context, witnessURL string, body []byte) (map[string]interface{}, error)

// Service is the IA-side witness engine.
type Service struct {
	Store        Store
	Contacts     ContactStore
	Driver       *drivers.KeriDriver
	HTTPClient   *http.Client
	PostEvent    EventPoster
	OurAID       func() string
	OurOOBI      func() string
	BackendType  string
	OnEvent      func(eventType string, payload map[string]interface{})

	mu          sync.Mutex
	finalizeWg  map[string]chan struct{}
}

func NewService(st Store, contacts ContactStore, driver *drivers.KeriDriver, backendType string) *Service {
	if backendType == "" {
		backendType = BackendDesktop
	}
	_ = InitDefaultConfig(st, backendType)
	s := &Service{
		Store:       st,
		Contacts:    contacts,
		Driver:      driver,
		BackendType: backendType,
		HTTPClient:  &http.Client{Timeout: 10 * time.Second},
		finalizeWg:  make(map[string]chan struct{}),
	}
	s.PostEvent = s.defaultPostEvent
	return s
}

func (s *Service) defaultPostEvent(ctx context.Context, witnessURL string, body []byte) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, witnessURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("witness POST %d: %s", resp.StatusCode, string(raw))
	}
	var out map[string]interface{}
	_ = json.Unmarshal(raw, &out)
	return out, nil
}

func (s *Service) Threshold() int {
	v, _ := s.Store.GetConfig("threshold")
	n, _ := strconvAtoi(v, DefaultThreshold)
	floor := MajorityThreshold(s.MaxWitnesses())
	if n < floor {
		return floor
	}
	return n
}

func (s *Service) MaxWitnesses() int {
	v, _ := s.Store.GetConfig("max_witnesses")
	n, _ := strconvAtoi(v, MaxWitnessSetSize)
	return n
}

func (s *Service) OOBIExtensions() map[string]interface{} {
	outgoing, _ := s.Store.CountWitnessingFor()
	capOK := outgoing < MaxOutgoingWitnessing
	return map[string]interface{}{
		"backend_type":              s.BackendType,
		"witness_capacity_available": capOK,
		"witness_outgoing_count":    outgoing,
		"witness_outgoing_max":      MaxOutgoingWitnessing,
	}
}

// ReceiveEvent implements C2 — witness-side receipt of a key event.
func (s *Service) ReceiveEvent(signerAID string, event map[string]interface{}) (map[string]interface{}, error) {
	if signerAID == "" {
		signerAID = eventAID(event)
	}
	if signerAID == "" {
		return nil, fmt.Errorf("missing signer aid")
	}
	meta, _ := s.Store.GetContactMeta(signerAID)
	if meta == nil || !meta.WitnessingFor {
		return nil, fmt.Errorf("not_witnessing")
	}
	seq, err := eventSeq(event)
	if err != nil {
		return nil, fmt.Errorf("invalid_sequence")
	}
	last, _ := s.Store.LastKelSeq(signerAID)
	if last >= 0 && seq != last+1 {
		return nil, fmt.Errorf("sequence_gap")
	}
	if last >= 0 && seq <= last {
		return nil, fmt.Errorf("duplicate_sequence")
	}

	if err := s.verifyEventChain(signerAID, event, seq); err != nil {
		return nil, fmt.Errorf("rejected: %w", err)
	}

	now := NowRFC3339()
	said := eventSAID(event)
	evJSON, _ := json.Marshal(event)
	if err := s.Store.StoreKelEvent(KelEvent{
		SignerAID: signerAID, SequenceNum: seq, EventJSON: string(evJSON),
		EventSAID: said, StoredAt: now,
	}); err != nil {
		return nil, err
	}

	witnessAID := ""
	if s.OurAID != nil {
		witnessAID = s.OurAID()
	}
	receipt := map[string]interface{}{
		"v": "KERI10JSON", "t": "rct", "d": said, "i": witnessAID,
		"aid": signerAID, "seq": seq, "dt": now,
	}
	receiptJSON, _ := json.Marshal(receipt)
	sig := "0B" + fmt.Sprintf("%x", receiptJSON)[:32] // dev stub; production uses driver CESR encode

	_ = s.Store.SaveIssuedReceipt(IssuedReceipt{
		SignerAID: signerAID, EventSAID: said, SequenceNum: seq,
		WitnessAID: witnessAID, ReceiptJSON: string(receiptJSON),
		CesrSignature: sig, IssuedAt: now,
	})

	meta, _ = s.Store.GetContactMeta(signerAID)
	if meta == nil {
		meta = &ContactMeta{ContactAID: signerAID, BackendType: BackendDesktop, WitnessStatus: StatusOnline, WitnessingFor: true}
	}
	meta.LastReceiptAt = now
	_ = s.Store.SaveContactMeta(*meta)

	return map[string]interface{}{
		"event_said": said, "witness_aid": witnessAID, "sequence_number": seq,
		"receipt": receipt, "cesr_signature": sig,
	}, nil
}

func (s *Service) verifyEventChain(signerAID string, event map[string]interface{}, seq int) error {
	if s.Driver == nil {
		if eventAID(event) == "" {
			return fmt.Errorf("invalid event")
		}
		return nil
	}
	existing, _ := s.Store.GetKelEvents(signerAID)
	events := eventsToMaps(existing)
	events = append(events, event)
	res, err := s.Driver.ValidateKEL(signerAID, events)
	if err != nil {
		return err
	}
	if !res.KelVerified {
		return fmt.Errorf("kel_verify_failed")
	}
	return nil
}

// GetKelReplica implements C4.
func (s *Service) GetKelReplica(signerAID string) ([]map[string]interface{}, error) {
	kel, err := s.Store.GetKelEvents(signerAID)
	if err != nil {
		return nil, err
	}
	if len(kel) == 0 {
		return nil, fmt.Errorf("not_found")
	}
	return eventsToMaps(kel), nil
}

// BroadcastEvent implements C1 — POST to all enrolled witnesses.
func (s *Service) BroadcastEvent(ctx context.Context, signerAID string, event map[string]interface{}) error {
	rootAID := signerAID
	if id, _ := s.Contacts.GetIdentity(); id != nil {
		rootAID = id.AID
	}
	kind := ClassifyAID(signerAID, rootAID)
	witnesses, err := s.enrolledWitnesses(kind)
	if err != nil {
		return err
	}
	said := eventSAID(event)
	seq, _ := eventSeq(event)
	threshold := s.Threshold()
	now := NowRFC3339()
	_ = s.Store.SaveFinalization(FinalizationState{
		EventSAID: said, SignerAID: signerAID, SequenceNum: seq,
		State: FinalizePending, ReceiptCount: 0, Threshold: threshold,
		StartedAt: now, UpdatedAt: now,
	})

	body, _ := json.Marshal(map[string]interface{}{"aid": signerAID, "event": event})
	for _, w := range witnesses {
		url := witnessEventURL(w.URL)
		go s.postWithRetry(ctx, url, body, said, w.AID)
	}
	go s.finalizeLoop(said, threshold)
	return nil
}

type witnessTarget struct {
	AID         string
	URL         string
	Commercial  bool
}

func (s *Service) enrolledWitnesses(kind AidKind) ([]witnessTarget, error) {
	contacts, err := s.Contacts.GetContacts()
	if err != nil {
		return nil, err
	}
	var out []witnessTarget
	for _, c := range contacts {
		if !c.IsWitness {
			continue
		}
		meta, _ := s.Store.GetContactMeta(c.AID)
		commercial := meta != nil && meta.IsCommercial
		if !ContactWitnessAllowedForAID(kind, commercial) {
			continue
		}
		if meta != nil && meta.WitnessStatus == StatusOffline {
			continue
		}
		out = append(out, witnessTarget{AID: c.AID, URL: c.OobiURL, Commercial: commercial})
	}
	// Top up from the bootstrap pool while there are too few contacts to reach
	// a threshold worth having. Appended rather than preferred, so somebody
	// with enough contacts of their own leans on those and not on us — and so
	// this contribution shrinks to nothing on its own as contacts accumulate.
	//
	// Root identities only, and the reason is structural rather than a policy
	// choice: a pairwise AID exists BECAUSE there is a contact, so it never has
	// the problem bootstrap solves. Extending it there would also mean the same
	// three operators witnessing every one of somebody's pairwise identities,
	// which is the correlation the pairwise design exists to prevent — witness
	// lists are public, and one operator seeing all of them could reassemble
	// the contact graph from its own logs.
	if kind == AidKindRoot {
		return withBootstrap(out, s.MaxWitnesses()), nil
	}
	return out, nil
}

func (s *Service) postWithRetry(ctx context.Context, url string, body []byte, eventSAID, witnessAID string) {
	_, err := s.PostEvent(ctx, url, body)
	if err != nil {
		time.Sleep(BroadcastRetryDelay)
		_, err = s.PostEvent(ctx, url, body)
	}
	if err != nil {
		log.Printf("[witness] broadcast to %s failed: %v", witnessAID, err)
		s.incrementOffline(witnessAID)
		return
	}
	s.onReceipt(eventSAID, witnessAID, "")
}

func (s *Service) onReceipt(eventSAID, witnessAID, cesrSig string) {
	f, _ := s.Store.GetFinalization(eventSAID)
	if f == nil {
		return
	}
	f.ReceiptCount++
	f.UpdatedAt = NowRFC3339()
	if f.ReceiptCount >= f.Threshold {
		f.State = FinalizeFinalized
	} else if f.ReceiptCount > 0 {
		f.State = FinalizePartial
	}
	_ = s.Store.SaveFinalization(*f)
	_ = s.Contacts.SaveWitnessReceipt(store.WitnessReceiptRecord{
		EventSAID: eventSAID, WitnessAID: witnessAID, CesrSignature: cesrSig,
	})
}

func (s *Service) finalizeLoop(eventSAID string, threshold int) {
	time.Sleep(FinalizeWaitDuration)
	f, _ := s.Store.GetFinalization(eventSAID)
	if f == nil || f.State == FinalizeFinalized {
		return
	}
	if f.ReceiptCount < threshold {
		f.State = FinalizeTimeout
		f.UpdatedAt = NowRFC3339()
		_ = s.Store.SaveFinalization(*f)
		if s.OnEvent != nil {
			s.OnEvent("witness_finalize_timeout", map[string]interface{}{
				"event_said": eventSAID, "receipt_count": f.ReceiptCount, "threshold": threshold,
			})
		}
	}
}

// EvaluateRequest implements C7 inbound witness request handling.
func (s *Service) EvaluateRequest(reqAID, reqOOBI, reqBackend string) (bool, string) {
	if reqBackend == BackendMobile || strings.EqualFold(reqBackend, "phone") {
		return false, "mobile_backend"
	}
	if !IsBackendEligible(reqBackend) && reqBackend != "" {
		return false, "ineligible_backend"
	}
	outgoing, _ := s.Store.CountWitnessingFor()
	if outgoing >= MaxOutgoingWitnessing {
		return false, "capacity_full"
	}
	contact, _ := s.Contacts.GetContact(reqAID)
	if contact != nil && !IsContactWitnessEligible(*contact) {
		return false, "contact_ineligible"
	}
	return true, ""
}

// RecordHeartbeatResult applies C8 health gate (HR1).
func (s *Service) RecordHeartbeatResult(contactAID string, ok bool) {
	meta, _ := s.Store.GetContactMeta(contactAID)
	if meta == nil {
		return
	}
	meta.LastHealthCheck = NowRFC3339()
	if ok {
		meta.OfflineCount = 0
		if meta.WitnessStatus == StatusOffline {
			meta.WitnessStatus = StatusOnline
		}
	} else {
		meta.OfflineCount++
		if meta.OfflineCount >= OfflineFailureThreshold {
			meta.WitnessStatus = StatusOffline
			s.dropWitness(contactAID)
		}
	}
	_ = s.Store.SaveContactMeta(*meta)
}

func (s *Service) dropWitness(contactAID string) {
	c, _ := s.Contacts.GetContact(contactAID)
	if c == nil {
		return
	}
	c.IsWitness = false
	_ = s.Contacts.SaveContact(*c)
	if s.OnEvent != nil {
		s.OnEvent("witness_dropped_health", map[string]interface{}{"contact_aid": contactAID})
	}
	go s.trySelfHeal()
}

func (s *Service) incrementOffline(contactAID string) {
	meta, _ := s.Store.GetContactMeta(contactAID)
	if meta == nil {
		meta = &ContactMeta{ContactAID: contactAID, BackendType: BackendDesktop}
	}
	meta.OfflineCount++
	if meta.OfflineCount >= OfflineFailureThreshold {
		meta.WitnessStatus = StatusOffline
		s.dropWitness(contactAID)
	}
	_ = s.Store.SaveContactMeta(*meta)
}

func (s *Service) ActiveWitnessCount() int {
	contacts, _ := s.Contacts.GetContacts()
	n := 0
	for _, c := range contacts {
		if !c.IsWitness {
			continue
		}
		meta, _ := s.Store.GetContactMeta(c.AID)
		if meta != nil && meta.WitnessStatus == StatusOffline {
			continue
		}
		n++
	}
	return n
}

// TrySelfHeal implements C9.
func (s *Service) trySelfHeal() {
	if s.ActiveWitnessCount() >= TargetContactWitnesses {
		return
	}
	since := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	attempts, _ := s.Store.CountSelfHealAttemptsSince(since)
	if attempts >= SelfHealMaxPerHour {
		return
	}
	contacts, _ := s.Contacts.GetContacts()
	for _, c := range contacts {
		if c.IsWitness || !IsContactWitnessEligible(c) {
			continue
		}
		last, _ := s.Store.LastSelfHealAttempt(c.AID)
		if last != "" {
			t, err := time.Parse(time.RFC3339, last)
			if err == nil && time.Since(t) < SelfHealCooldown {
				continue
			}
		}
		meta, _ := s.Store.GetContactMeta(c.AID)
		bt := BackendDesktop
		if meta != nil && meta.BackendType != "" {
			bt = meta.BackendType
		}
		if !IsBackendEligible(bt) {
			continue
		}
		_ = s.Store.RecordSelfHealAttempt(c.AID, NowRFC3339())
		_ = s.SendWitnessRequest(context.Background(), c.AID)
		break
	}
}

// BuildStatus implements the status interface.
func (s *Service) BuildStatus() (*StatusResponse, error) {
	contacts, err := s.Contacts.GetContacts()
	if err != nil {
		return nil, err
	}
	outgoing, _ := s.Store.CountWitnessingFor()
	resp := &StatusResponse{
		ActiveCount: s.ActiveWitnessCount(), Threshold: s.Threshold(),
		MaxWitnesses: s.MaxWitnesses(), OutgoingCapacity: MaxOutgoingWitnessing,
		OutgoingUsed: outgoing, BackendType: s.BackendType,
		WitnessCapacityOK: outgoing < MaxOutgoingWitnessing,
	}
	for _, c := range contacts {
		if c.IsWitness {
			entry := WitnessEntry{AID: c.AID, Alias: c.Alias}
			if meta, _ := s.Store.GetContactMeta(c.AID); meta != nil {
				entry.BackendType = meta.BackendType
				entry.Status = meta.WitnessStatus
				entry.IsMutual = meta.IsMutual
				entry.IsCommercial = meta.IsCommercial
				entry.OfflineCount = meta.OfflineCount
				entry.LastReceiptAt = meta.LastReceiptAt
			}
			resp.YourWitnesses = append(resp.YourWitnesses, entry)
		}
	}
	// witnessing for others from distinct signer_aids in kel store
	metaList, _ := s.Store.ListContactMeta()
	_ = metaList
	return resp, nil
}

// ServeTELStub is an interface placeholder — BLOCKED: credential/revocation-registry joint freeze.
func (s *Service) ServeTELStub(issuerAID string) map[string]interface{} {
	return map[string]interface{}{
		"blocked": true, "reason": "BLOCKED: TEL-serving endpoint contract pending credential/revocation-registry joint freeze",
		"issuer_aid": issuerAID,
	}
}

func witnessEventURL(oobi string) string {
	base := oobi
	if idx := strings.Index(oobi, "/public/oobi/"); idx != -1 {
		base = oobi[:idx]
	}
	return strings.TrimRight(base, "/") + "/api/witness/event"
}

func strconvAtoi(v string, def int) (int, error) {
	if v == "" {
		return def, nil
	}
	var n int
	_, err := fmt.Sscanf(v, "%d", &n)
	if err != nil {
		return def, err
	}
	return n, nil
}