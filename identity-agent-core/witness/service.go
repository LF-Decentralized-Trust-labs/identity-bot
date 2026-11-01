package witness

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
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
	Store       Store
	Contacts    ContactStore
	Driver      drivers.KeriEngine
	HTTPClient  *http.Client
	PostEvent   EventPoster
	delegatesMu sync.Mutex
	// receiving holds a *sync.Mutex per identity, so one identity's events
	// are judged and stored one at a time: an event judged against a log
	// another event is changing could be stored on a history that no longer
	// exists.
	receiving sync.Map
	// confirmed is, by identity and witness, the furthest place a witness
	// has confirmed holding: by its signed tip, or its receipt.
	confirmed sync.Map
	// AskToCoverDelegates says whether this agent's witness requests ask for
	// the identities it delegates to be witnessed too.
	AskToCoverDelegates func() bool
	// SignAsRequester signs a witness request as this Identity Agent's
	// identity, with its current key, where it holds it. Answers to requests
	// are signed with the witness key instead (SignReceipt).
	SignAsRequester func(statement string) (string, error)
	// acceptMu serialises acting on answers to witness requests, so one answer
	// is not acted on twice.
	acceptMu sync.Mutex
	// FetchTip asks a witness how far it holds an identity's key log. Replaceable
	// so a test needs no network.
	FetchTip func(ctx context.Context, url string) (TipAnswer, error)
	// FetchEvent asks a witness for one signed event of a key log.
	FetchEvent  func(ctx context.Context, url string) (SignedEvent, error)
	OurAID      func() string
	OurOOBI     func() string
	BackendType string
	OnEvent     func(eventType string, payload map[string]interface{})

	// SignReceipt signs a key event's SAID as this witness, returning the
	// witness's own identifier alongside the signature.
	//
	// Supplied by the host rather than done here because the key belongs to the
	// agent, not to this package. Unset means this agent cannot witness, and
	// ReceiveEvent refuses rather than issuing something that looks like a
	// receipt and proves nothing.
	SignReceipt func(said string) (witnessAID, cesrSig string, err error)
	// OurWitnessAID reports the identifier this agent witnesses under, without
	// signing anything.
	//
	// Needed where the identifier is the answer rather than a by-product:
	// publishing it so a peer can designate this agent, and naming it when
	// standing down. Supplied by the host for the same reason SignReceipt is —
	// the key belongs to the agent, not to this package.
	OurWitnessAID func() (string, error)
	// OurEntityType reports whether this agent belongs to a person or an
	// organization. A peer may only witness for its own kind, so an agent that
	// cannot answer this enrols no peer witnesses at all.
	OurEntityType func() EntityType
	// CheckIdentity asks a witness service which identity it is answering as,
	// so a pinned identifier can be confirmed before it is designated. Nil uses
	// a plain HTTP request; set in tests so they need no network.
	CheckIdentity IdentityChecker
	// IsOfficialService reports whether a witness is a registered service
	// provider rather than a peer.
	//
	// Service providers are exempt from the same-kind rule: one serves a large
	// population, so naming it discloses almost nothing about its subject.
	// Asked of the provider registry rather than read off a per-contact flag,
	// so the exemption is a line in a shipped file that somebody can audit.
	IsOfficialService func(aidOrURL string) bool

	mu         sync.Mutex
	finalizeWg map[string]chan struct{}
}

func NewService(st Store, contacts ContactStore, driver drivers.KeriEngine, backendType string) *Service {
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
	s.FetchTip = s.defaultFetchTip
	s.FetchEvent = s.defaultFetchEvent
	return s
}

func (s *Service) defaultFetchEvent(ctx context.Context, url string) (SignedEvent, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return SignedEvent{}, err
	}
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return SignedEvent{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return SignedEvent{}, fmt.Errorf("witness GET %d", resp.StatusCode)
	}
	var out SignedEvent
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return SignedEvent{}, err
	}
	return out, nil
}

// EventAt is one event of an identity's key log as a witness holds it, with
// its controller's signature: what an Identity Agent asks for to take up an
// event signed on the device that holds the key.
func (s *Service) EventAt(aid string, sn int) (SignedEvent, error) {
	kel, err := s.Store.GetKelEvents(aid)
	if err != nil {
		return SignedEvent{}, err
	}
	for _, e := range kel {
		if sigs := e.ControllerSignatures(); e.SequenceNum == sn && e.RawBytesB64 != "" && len(sigs) > 0 {
			return SignedEvent{RawBytesB64: e.RawBytesB64, CesrSignature: sigs[0], Signatures: sigs}, nil
		}
	}
	return SignedEvent{}, fmt.Errorf("not_found")
}

// EventsHeldAt asks each designated witness for the event at sn of an
// identity's key log. What comes back is only a candidate: the asker checks
// it extends its own key log and is signed by the identity's key.
func (s *Service) EventsHeldAt(ctx context.Context, aid string, sn int, designated []string) []SignedEvent {
	targets := s.designatedTargets(designated)
	var out []SignedEvent
	for _, key := range designated {
		w, ok := targets[key]
		if !ok {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		url := witnessBase(w.URL) + witnessPathPrefix(w.Commercial) + "/witness/kel/" + aid + "/event/" + strconv.Itoa(sn)
		ev, err := s.FetchEvent(cctx, url)
		cancel()
		if err == nil && ev.RawBytesB64 != "" {
			out = append(out, ev)
		}
	}
	return out
}

func (s *Service) defaultFetchTip(ctx context.Context, url string) (TipAnswer, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return TipAnswer{}, err
	}
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return TipAnswer{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return TipAnswer{}, fmt.Errorf("witness GET %d", resp.StatusCode)
	}
	var out TipAnswer
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil {
		return TipAnswer{}, err
	}
	return out, nil
}

// SignedEvent is a key event as published, with its controller's signature.
type SignedEvent struct {
	RawBytesB64   string `json:"raw_bytes_b64"`
	CesrSignature string `json:"cesr_signature"`
	// Signatures are every controller signature over the event, for an
	// identity with several signers; CesrSignature is the first.
	Signatures []string `json:"cesr_signatures,omitempty"`
}

// TipAnswer is a witness's answer to how far it holds an identity's key log:
// the newest event's place and digest (-1 and empty when it holds nothing),
// signed by the witness's key together with the nonce it was asked with.
type TipAnswer struct {
	AID        string `json:"aid"`
	Nonce      string `json:"nonce"`
	SN         int    `json:"sn"`
	SAID       string `json:"said"`
	WitnessAID string `json:"witness_aid"`
	Signature  string `json:"signature"`
}

// TipStatement is what a witness signs in a TipAnswer.
func TipStatement(aid, nonce string, sn int, said string) string {
	return fmt.Sprintf("witness-kel-tip/v1\n%s\n%s\n%d\n%s", aid, nonce, sn, said)
}

// KelTip is this witness's signed answer for how far it holds aid's key log.
func (s *Service) KelTip(aid, nonce string) (TipAnswer, error) {
	if s.SignReceipt == nil {
		return TipAnswer{}, fmt.Errorf("this agent has no witnessing key")
	}
	out := TipAnswer{AID: aid, Nonce: nonce, SN: -1}
	if kel, err := s.Store.GetKelEvents(aid); err == nil && len(kel) > 0 {
		last := kel[len(kel)-1]
		out.SN, out.SAID = last.SequenceNum, last.EventSAID
	}
	wit, sig, err := s.SignReceipt(TipStatement(aid, nonce, out.SN, out.SAID))
	if err != nil {
		return TipAnswer{}, err
	}
	out.WitnessAID, out.Signature = wit, sig
	return out, nil
}

// askTip asks one witness for its tip with a fresh nonce, and believes the
// answer only when it carries that nonce and is signed by that witness's key.
func (s *Service) askTip(ctx context.Context, w witnessTarget, key, aid string) (HeldTip, bool) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return HeldTip{}, false
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	url := witnessBase(w.URL) + witnessPathPrefix(w.Commercial) + "/witness/kel/" + aid + "/tip?nonce=" + nonce
	answer, err := s.FetchTip(ctx, url)
	if err != nil {
		return HeldTip{}, false
	}
	return heldTipOf(aid, key, nonce, answer)
}

// heldTipOf checks a witness's answer: for this identity, with this nonce,
// signed by the witness asked.
func heldTipOf(aid, witnessKey, nonce string, a TipAnswer) (HeldTip, bool) {
	if a.AID != aid || a.Nonce != nonce || a.WitnessAID != witnessKey || (a.SN >= 0) == (a.SAID == "") {
		return HeldTip{}, false
	}
	if drivers.VerifyReceipt(witnessKey, TipStatement(aid, nonce, a.SN, a.SAID), a.Signature) != nil {
		return HeldTip{}, false
	}
	return HeldTip{SN: a.SN, SAID: a.SAID}, true
}

// KelHeldBy asks each designated witness how far the key log it holds for aid
// goes, and returns, by witness key, the sequence number and digest of the
// newest event each holds. A witness that cannot be reached, holds nothing, or
// does not sign, with its own key, the tip together with the nonce it was
// asked with, is left out: so an answer is fresh and the witness's own.
func (s *Service) KelHeldBy(ctx context.Context, aid string, designated []string) map[string]HeldTip {
	known := s.designatedTargets(designated)
	out := map[string]HeldTip{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, key := range designated {
		w, ok := known[key]
		if !ok {
			continue
		}
		wg.Add(1)
		go func(key string, w witnessTarget) {
			defer wg.Done()
			tip, ok := s.askTip(ctx, w, key, aid)
			if !ok || tip.SN < 0 {
				return
			}
			mu.Lock()
			out[key] = tip
			mu.Unlock()
		}(key, w)
	}
	wg.Wait()
	return out
}

// HeldTip is the newest event a witness holds for an identity.
type HeldTip struct {
	SN   int
	SAID string
}

// designatedTargets finds, by witness key, where each witness is reached:
// among this agent's witnesses and the bootstrap pool.
func (s *Service) designatedTargets(designated []string) map[string]witnessTarget {
	known := map[string]witnessTarget{}
	// A bootstrap witness's address is pinned: a contact naming the same key
	// does not redirect where it is asked.
	for _, b := range BootstrapPool() {
		known[b.WitnessKey] = witnessTarget{AID: b.AID, WitnessKey: b.WitnessKey, URL: b.URL, Commercial: true}
	}
	if contacts, err := s.Contacts.GetContacts(); err == nil {
		for _, c := range contacts {
			if meta, _ := s.Store.GetContactMeta(c.AID); meta != nil && meta.WitnessKey != "" {
				if _, pinned := known[meta.WitnessKey]; !pinned {
					known[meta.WitnessKey] = witnessTarget{AID: c.AID, URL: c.OobiURL, WitnessKey: meta.WitnessKey}
				}
			}
		}
	}
	return known
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
	// The key this agent signs receipts with, so anybody who wants it to
	// witness for them can name it in their inception event. Without publishing
	// this an agent can be asked to witness and can never be DESIGNATED, since
	// what an event names is the witness key and not the contact.
	//
	// Public by design: it is a verifying key, and it appears in the events of
	// everybody this agent witnesses for.
	witnessKey, err := s.witnessAID()
	if err != nil {
		witnessKey = ""
	}
	return map[string]interface{}{
		"witness_key":                witnessKey,
		"backend_type":               s.BackendType,
		"witness_capacity_available": capOK,
		"witness_outgoing_count":     outgoing,
		"witness_outgoing_max":       MaxOutgoingWitnessing,
	}
}

// ReceiveEvent implements C2 — witness-side receipt of a key event.
//
// Takes the event as published, plus the controller's signature over those
// bytes. Both are required, and that is the point of this function rather than
// an inconvenience in it.
//
// A receipt says: this witness saw this exact event, and the identity it claims
// to come from authorised it. Neither half can be established from a parsed
// event. The digest is over an exact byte sequence in an exact field order, so
// a re-encoded event is a different event; and there is nothing to check
// authorship against without a signature. Receipting on those terms produces
// evidence that somebody sent a JSON object, which is not what a receipt is
// read as meaning.
func (s *Service) ReceiveEvent(signerAID string, rawEvent []byte, cesrSig string) (map[string]interface{}, error) {
	var sigs []string
	if cesrSig != "" {
		sigs = []string{cesrSig}
	}
	return s.ReceiveSignedEvent(signerAID, rawEvent, sigs)
}

// ReceiveSignedEvent is ReceiveEvent for an event carrying any number of
// controller signatures: one for each signer of an identity with several. It is
// judged against the key log held here by keri-go's Admit, so it is receipted
// when it extends the log, repeats an event the log holds, or is a recovery
// rotation replacing the interactions after the last establishment event (those
// are kept as superseded, never deleted). A correctly signed event at a place
// the log holds a different event at, which may not replace it, is refused and
// kept as evidence of duplicity.
func (s *Service) ReceiveSignedEvent(signerAID string, rawEvent []byte, sigs []string) (map[string]interface{}, error) {
	if len(rawEvent) == 0 {
		return nil, fmt.Errorf("missing_event_bytes")
	}
	var event map[string]interface{}
	if err := json.Unmarshal(rawEvent, &event); err != nil {
		return nil, fmt.Errorf("invalid event")
	}
	if signerAID == "" {
		signerAID = eventAID(event)
	}
	if signerAID == "" {
		return nil, fmt.Errorf("missing signer aid")
	}
	mu, _ := s.receiving.LoadOrStore(signerAID, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
	defer mu.(*sync.Mutex).Unlock()
	if len(sigs) == 0 {
		// Refused rather than receipted unsigned. A witness that will attest to
		// an unsigned event is a witness anyone can make say anything, and its
		// receipts stop distinguishing a real history from an invented one.
		return nil, fmt.Errorf("unsigned_event")
	}
	meta, _ := s.Store.GetContactMeta(signerAID)
	enrolAs, enrolUnder := "", ""
	if meta != nil && meta.WitnessingFor {
		// A delegate is witnessed only while its delegator is.
		if delegator := s.delegateOf(signerAID); delegator != "" {
			if dm, _ := s.Store.GetContactMeta(delegator); dm == nil || !dm.WitnessingFor {
				s.dropDelegatesOf(delegator)
				return nil, fmt.Errorf("not_witnessing")
			}
		}
	} else {
		// An identity delegated by one this agent witnesses for is witnessed
		// too, from its inception, when the delegator's key log this agent
		// holds approves exactly that inception: the delegator has already
		// said it is theirs, in the log this agent agreed to witness. The
		// operator can switch this off or cap it.
		delegator, ok := s.delegatorApproves(event)
		if !ok {
			return nil, fmt.Errorf("not_witnessing")
		}
		if !s.delegatesAccepted(delegator) {
			return nil, fmt.Errorf("not_witnessing: the delegator's agreement does not cover its delegates, or this witness's operator does not accept them")
		}
		enrolAs, enrolUnder = BackendDesktop, delegator
		if dm, _ := s.Store.GetContactMeta(delegator); dm != nil && dm.BackendType != "" {
			enrolAs = dm.BackendType
		}
	}
	seq, err := eventSeq(event)
	if err != nil {
		return nil, fmt.Errorf("invalid_sequence")
	}
	if last, _ := s.Store.LastKelSeq(signerAID); seq > last+1 {
		return nil, errSequenceGap
	}
	got, err := s.admit(signerAID, rawEvent, sigs)
	switch {
	case errors.Is(err, errUnverifiableLog):
		if last, _ := s.Store.LastKelSeq(signerAID); last >= 0 && seq <= last {
			return s.alreadyHeld(signerAID, seq, eventSAID(event))
		}
		return nil, fmt.Errorf("rejected: %w", err)
	case errors.Is(err, errPlaceTaken):
		// An interaction a recovery rotation replaced, sent again, is kept
		// as superseded already: it is not evidence of duplicity.
		if got != nil && got.conflict != nil && !s.supersededHere(signerAID, got.conflict.EventSAID) {
			got.conflict.SeenAt = NowRFC3339()
			if serr := s.Store.SaveKelConflict(*got.conflict); serr != nil {
				log.Printf("[witness] could not keep a conflicting event of %s: %v", signerAID, serr)
			}
		}
		return nil, errPlaceTaken
	case errors.Is(err, errSequenceGap):
		return nil, errSequenceGap
	case err != nil && err.Error() == "unsigned_event":
		return nil, err
	case err != nil:
		return nil, fmt.Errorf("rejected: %w", err)
	}
	if got.Repeat {
		// A repeat may carry signatures this witness did not hold, which
		// are kept; it is answered with the receipt already issued.
		if got.held != nil {
			merged := mergeSignatures(got.held.ControllerSignatures(), got.Signatures)
			if len(merged) > len(got.held.ControllerSignatures()) {
				if err := s.Store.SetKelSignatures(signerAID, seq, merged); err != nil {
					return nil, err
				}
			}
		}
		if held, err := s.alreadyHeld(signerAID, seq, eventSAID(event)); err == nil {
			return held, nil
		}
		// Held, but never receipted here: receipted now.
	}
	if enrolAs != "" {
		if err := s.enrollWitnessingFor(signerAID, enrolAs); err != nil {
			return nil, err
		}
		s.recordDelegate(signerAID, enrolUnder)
	}

	now := NowRFC3339()
	said := eventSAID(event)
	// The published bytes are stored alongside the readable form. Storing only
	// the readable form is what made every event a witness held unverifiable
	// after the fact. Only the signatures that verified are kept.
	stored := KelEvent{
		SignerAID: signerAID, SequenceNum: seq, EventJSON: string(rawEvent),
		EventSAID: said, StoredAt: now,
		RawBytesB64: base64.StdEncoding.EncodeToString(rawEvent),
		Signatures:  got.Signatures,
	}
	switch {
	case got.Repeat:
	case got.Supersedes > 0:
		if err := s.Store.SupersedeKelEvents(signerAID, stored,
			int(got.Log.State().SN())+got.Supersedes-1); err != nil {
			return nil, err
		}
	default:
		if err := s.Store.StoreKelEvent(stored); err != nil {
			return nil, err
		}
	}

	// Signed with a key, or not issued at all.
	//
	// What stood here derived the "signature" by hashing the receipt itself:
	// public data in, public data out, no key involved. Anybody holding the
	// event could produce the same value, so it distinguished a genuine witness
	// from an impostor not at all, while looking exactly like protection to
	// every reader downstream.
	//
	// Refusing is the right failure. A witness that cannot sign has nothing to
	// say, and saying it anyway is what made this dangerous rather than merely
	// incomplete — the controller believed its event was witnessed and it was
	// not.
	if s.SignReceipt == nil {
		return nil, fmt.Errorf("this agent has no witnessing key, so it cannot receipt anything")
	}
	witnessAID, sig, serr := s.SignReceipt(said)
	if serr != nil {
		return nil, fmt.Errorf("could not sign a receipt: %w", serr)
	}
	receipt := map[string]interface{}{
		"v": "KERI10JSON", "t": "rct", "d": said, "i": witnessAID,
		"aid": signerAID, "seq": seq, "dt": now,
	}
	receiptJSON, _ := json.Marshal(receipt)

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

// eventBody is an event as it is sent to a witness: its published bytes and
// every controller signature over them. cesr_signatures is the whole list and
// cesr_signature its first, for a witness that reads one.
func eventBody(signerAID, rawB64 string, sigs []string) []byte {
	sigs = nonEmpty(sigs)
	m := map[string]interface{}{"aid": signerAID, "event_b64": rawB64, "cesr_signature": ""}
	if len(sigs) > 0 {
		m["cesr_signature"] = sigs[0]
		m["cesr_signatures"] = sigs
	}
	body, _ := json.Marshal(m)
	return body
}

func nonEmpty(sigs []string) []string {
	var out []string
	for _, s := range sigs {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
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
//
// Sends the event as published, with the controller's signature over those
// bytes. A witness cannot earn its receipt without both, so sending anything
// less would be asking for an attestation nobody could make honestly.
func (s *Service) BroadcastEvent(ctx context.Context, signerAID string, rawEvent []byte, cesrSigs ...string) error {
	if len(rawEvent) == 0 {
		return fmt.Errorf("an event cannot be broadcast without the bytes it was published as")
	}
	var event map[string]interface{}
	if err := json.Unmarshal(rawEvent, &event); err != nil {
		return fmt.Errorf("the event to broadcast is not readable: %w", err)
	}
	if len(nonEmpty(cesrSigs)) == 0 {
		// Reported rather than sent. Every witness would refuse it, so sending
		// it would turn one local fault into a round of remote refusals whose
		// cause is much harder to see from here.
		return fmt.Errorf("refusing to broadcast an unsigned event for %s: a witness cannot "+
			"attest to an event it cannot verify", signerAID)
	}
	rootAID := signerAID
	if id, _ := s.Contacts.GetIdentity(); id != nil {
		rootAID = id.AID
	}
	kind := ClassifyAID(signerAID, rootAID)
	witnesses, err := s.enrolledWitnesses(kind, signerAID)
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

	body := eventBody(signerAID, base64.StdEncoding.EncodeToString(rawEvent), cesrSigs)
	for _, w := range witnesses {
		url := witnessEventURL(w)
		go s.postWithRetry(ctx, url, body, said, w.AID)
	}
	go s.finalizeLoop(said, threshold)
	return nil
}

// BringUpToDate sends each designated witness, in order, every event of
// signerAID's key log it does not hold yet, and keeps the receipts they
// return. A witness refuses an event that does not follow the last one it
// holds, so a key log some of whose events never reached its witnesses has to
// be sent from where each witness stopped, not one event at a time. Each
// witness is asked only for its tip, and one whose tip is not known is sent
// nothing this time.
func (s *Service) BringUpToDate(ctx context.Context, signerAID string, events []SignedEvent, designated []string, threshold int) {
	if len(events) == 0 {
		return
	}
	localTip := -1
	if raw, err := base64.StdEncoding.DecodeString(events[len(events)-1].RawBytesB64); err == nil {
		var ev map[string]interface{}
		if json.Unmarshal(raw, &ev) == nil {
			localTip, _ = eventSeq(ev)
		}
	}
	known := s.designatedTargets(designated)
	// Only events past what every witness has confirmed can still be sent, so
	// only those are looked at here.
	lowest := localTip
	for _, key := range designated {
		if c := s.confirmedTip(signerAID, key); c < lowest {
			lowest = c
		}
	}
	if localTip >= 0 && lowest >= localTip {
		return
	}
	// Each event's receipts are counted against its threshold, so each has a
	// finalisation to count them on.
	for _, e := range events {
		raw, _ := base64.StdEncoding.DecodeString(e.RawBytesB64)
		var ev map[string]interface{}
		if json.Unmarshal(raw, &ev) != nil {
			continue
		}
		if sn, err := eventSeq(ev); err == nil && sn <= lowest {
			continue
		}
		said := eventSAID(ev)
		if f, _ := s.Store.GetFinalization(said); f == nil {
			seq, _ := eventSeq(ev)
			now := NowRFC3339()
			_ = s.Store.SaveFinalization(FinalizationState{
				EventSAID: said, SignerAID: signerAID, SequenceNum: seq,
				State: FinalizePending, Threshold: threshold, StartedAt: now, UpdatedAt: now,
			})
		}
	}
	var wg sync.WaitGroup
	for _, key := range designated {
		w, ok := known[key]
		if !ok {
			log.Printf("[witness] %s designates %s, which this agent has no address for", signerAID, key)
			continue
		}
		// A witness that has already confirmed holding the log as far as it
		// goes here is not asked again until there is more to send.
		if localTip >= 0 && s.confirmedTip(signerAID, key) >= localTip {
			continue
		}
		wg.Add(1)
		go func(key string, w witnessTarget) {
			defer wg.Done()
			// A witness whose tip is not known this time, because it did not
			// answer, answered too often, has no tip route or answered with
			// something that does not check out, is left for the next pass.
			// Sending it the whole log instead is what overruns a witness's
			// limits, and an older witness reads an event it holds as a
			// conflicting history.
			tip, ok := s.askTip(ctx, w, key, signerAID)
			if !ok {
				return
			}
			s.heldNow(signerAID, key, tip.SN)
			from := tip.SN + 1
			for _, e := range events {
				raw, err := base64.StdEncoding.DecodeString(e.RawBytesB64)
				if err != nil {
					return
				}
				var ev map[string]interface{}
				if json.Unmarshal(raw, &ev) != nil {
					return
				}
				if sn, err := eventSeq(ev); err != nil || sn < from {
					continue
				}
				// An event not yet signed ends this witness's pass. A witness
				// cannot verify it and refuses it, and every event after it
				// would be held back as a gap; it is sent once it is signed.
				sigs := store.ControllerSignaturesOf(e.Signatures, e.CesrSignature)
				if len(sigs) == 0 {
					return
				}
				body := eventBody(signerAID, e.RawBytesB64, sigs)
				said := eventSAID(ev)
				resp, err := s.PostEvent(ctx, witnessEventURL(w), body)
				if err != nil {
					log.Printf("[witness] %s did not take event %s of %s: %v", key, said, signerAID, err)
					return
				}
				if sig, wit, verr := receiptFromResponse(resp, said); verr == nil && wit == key {
					s.onReceipt(said, key, sig)
					if sn, err := eventSeq(ev); err == nil {
						s.confirm(signerAID, key, sn)
					}
				}
			}
		}(key, w)
	}
	wg.Wait()
}

// BroadcastToDesignated sends an event to the witnesses an identity's own key
// log designates, found by their keys among this agent's witnesses and the
// bootstrap pool, and keeps the receipts they return. Used for an identity
// that names its delegator's witnesses rather than ones chosen for it here.
func (s *Service) BroadcastToDesignated(ctx context.Context, signerAID string, rawEvent []byte, cesrSigs []string, designated []string, threshold int) error {
	var event map[string]interface{}
	if err := json.Unmarshal(rawEvent, &event); err != nil {
		return fmt.Errorf("the event to broadcast is not readable: %w", err)
	}
	if len(nonEmpty(cesrSigs)) == 0 {
		return fmt.Errorf("refusing to broadcast an unsigned event for %s", signerAID)
	}
	known := s.designatedTargets(designated)
	said := eventSAID(event)
	seq, _ := eventSeq(event)
	now := NowRFC3339()
	_ = s.Store.SaveFinalization(FinalizationState{
		EventSAID: said, SignerAID: signerAID, SequenceNum: seq,
		State: FinalizePending, Threshold: threshold, StartedAt: now, UpdatedAt: now,
	})
	body := eventBody(signerAID, base64.StdEncoding.EncodeToString(rawEvent), cesrSigs)
	for _, key := range designated {
		w, ok := known[key]
		if !ok {
			log.Printf("[witness] %s designates %s, which this agent has no address for", signerAID, key)
			continue
		}
		go s.postWithRetry(ctx, witnessEventURL(w), body, said, key)
	}
	go s.finalizeLoop(said, threshold)
	return nil
}

type witnessTarget struct {
	AID string
	URL string
	// WitnessKey is the non-transferable identifier this witness signs receipts
	// with. Empty when it has not published one, in which case it can be asked
	// to witness but cannot be DESIGNATED — see DesignatableWitnesses.
	WitnessKey string
	Commercial bool
}

func (s *Service) enrolledWitnesses(kind AidKind, aid string) ([]witnessTarget, error) {
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
		// A registered service provider counts as commercial whatever the
		// contact record says, because the registry is the declaration and the
		// flag is only a cache of one.
		commercial := meta != nil && meta.IsCommercial
		if !commercial && s.IsOfficialService != nil &&
			(s.IsOfficialService(c.AID) || s.IsOfficialService(c.OobiURL)) {
			commercial = true
		}
		if !ContactWitnessAllowedForAID(kind, commercial) {
			continue
		}
		// Peers of the same kind only. An organization witnessing an individual
		// would write that organization permanently into the individual's
		// founding event, which is public and cannot be amended away — see
		// PeerAllowedAcross. A dedicated witness service is not a peer
		// and is not subject to this.
		if !commercial && !s.peerWitnessAllowed(meta) {
			continue
		}
		if meta != nil && meta.WitnessStatus == StatusOffline {
			continue
		}
		// The contact's own witness key travels with it, because that — not the
		// contact identifier — is what an event names when it designates. A
		// contact whose key this agent has not learned can still be sent events
		// to witness; it just cannot be written into one.
		witnessKey := ""
		if meta != nil {
			witnessKey = meta.WitnessKey
		}
		out = append(out, witnessTarget{
			AID: c.AID, URL: c.OobiURL, WitnessKey: witnessKey, Commercial: commercial,
		})
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

	// A pairwise AID reaches here with only commercial contacts, if any — the
	// eligibility gate drops the rest, because a distinctive contact set shared
	// across two pairwise AIDs would link them to one person. That gate is
	// right, but on its own it leaves a fresh identity's pairwise AIDs with no
	// witness at all, and an unwitnessed AID has nobody positioned to notice
	// duplicity. So take exactly one from the bootstrap pool.
	if len(out) == 0 {
		if w, ok := oneBootstrapFor(aid); ok {
			out = append(out, w)
		}
	}
	return out, nil
}

// postWithRetry submits an event to one witness and records the receipt it
// returns.
//
// What is recorded is the receipt, not the fact that the request succeeded.
// Those were the same thing until now: a witness answering HTTP 200 counted
// towards the threshold and the reply was discarded, so "finalized" meant that
// some number of servers had responded — not that anybody had attested to
// anything. A witness returning 200 and no receipt finalised an event just as
// well as one that signed it.
func (s *Service) postWithRetry(ctx context.Context, url string, body []byte, eventSAID, witnessAID string) {
	// Its own time, not the caller's: every caller starts this in the
	// background and returns, and a caller that cancels its context on return
	// cancelled the post before it reached the witness.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	resp, err := s.PostEvent(ctx, url, body)
	if err != nil {
		time.Sleep(BroadcastRetryDelay)
		resp, err = s.PostEvent(ctx, url, body)
	}
	if err != nil {
		log.Printf("[witness] broadcast to %s failed: %v", witnessAID, err)
		s.incrementOffline(witnessAID)
		return
	}

	// The reply is read, not assumed.
	//
	// What stood here threw the response away and counted a receipt because the
	// POST returned 2xx. So the threshold was met by HTTP status: a witness that
	// accepted the event and signed nothing, or signed something else, or was
	// not the witness we addressed, counted exactly the same as one that
	// witnessed properly. The signature was then stored as an empty string,
	// which is what the counting was supposedly built on.
	//
	// A receipt that does not check out is worse than a witness being down,
	// because being down is visible in the count and a bad receipt is not.
	sig, wit, verr := receiptFromResponse(resp, eventSAID)
	if verr != nil {
		log.Printf("[witness] %s answered but its receipt does not check out: %v", witnessAID, verr)
		return
	}
	if wit != witnessAID {
		// The witness we asked is the witness the identity designated. One that
		// answers under another name may be perfectly honest and is still not
		// the one this threshold is counting.
		log.Printf("[witness] asked %s for a receipt and %s answered; not counted", witnessAID, wit)
		return
	}
	s.onReceipt(eventSAID, witnessAID, sig)
}

// receiptFromResponse pulls a verified receipt out of a witness's reply.
//
// A witness is named by a non-transferable identifier, so the identifier IS the
// key this checks against — there is nothing to fetch and nothing that could
// answer the fetch wrongly.
func receiptFromResponse(resp map[string]interface{}, eventSAID string) (sig, witnessAID string, err error) {
	if resp == nil {
		return "", "", fmt.Errorf("the witness returned nothing to check")
	}
	sig, _ = resp["cesr_signature"].(string)
	witnessAID, _ = resp["witness_aid"].(string)
	if sig == "" || witnessAID == "" {
		return "", "", fmt.Errorf("the reply carries no signed receipt")
	}
	if err := drivers.VerifyReceipt(witnessAID, eventSAID, sig); err != nil {
		return "", "", err
	}
	return sig, witnessAID, nil
}

func (s *Service) onReceipt(eventSAID, witnessAID, cesrSig string) {
	f, _ := s.Store.GetFinalization(eventSAID)
	if f == nil {
		return
	}
	// Counted only once it is kept, so the count never runs ahead of the
	// receipts anyone can be shown.
	if err := s.Contacts.SaveWitnessReceipt(store.WitnessReceiptRecord{
		EventSAID: eventSAID, WitnessAID: witnessAID, CesrSignature: cesrSig,
	}); err != nil {
		log.Printf("[witness] receipt from %s for %s not kept: %v", witnessAID, eventSAID, err)
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
			// Back, so resume relying on it.
			//
			// Dropping was never a removal: the key log went on designating this
			// witness throughout, so resuming costs nothing and clears the
			// disagreement between what this agent does and what its own log
			// says. Without this, dropping was automatic and permanent while
			// restoring needed a fresh enrolment exchange — so one bad night
			// cost a witness for good.
			s.resumeWitness(contactAID)
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

// dropWitness stops relying on a witness that is no longer answering.
//
// This changes what THIS agent does; it does not change what the identity has
// published. The designated set lives in the key log and can only be amended by
// a rotation, so until one happens the log still names this witness and a
// verifier still expects receipts from it — receipts that will not come, so the
// threshold cannot be met.
//
// Reported for exactly that reason. Falling silently out of step with one's own
// published log is the failure worth avoiding: the agent believes it has three
// witnesses, the log says four, and nobody notices until a verification fails
// for a reason nothing explains.
func (s *Service) dropWitness(contactAID string) {
	c, _ := s.Contacts.GetContact(contactAID)
	if c == nil {
		return
	}
	c.IsWitness = false
	_ = s.Contacts.SaveContact(*c)
	if meta, _ := s.Store.GetContactMeta(contactAID); meta != nil && meta.WitnessKey != "" {
		s.noteDesignationDrift(contactAID, meta.WitnessKey)
	}
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

// witnessEndpointURL is where a witness accepts endpoint records. Separate from
// the event path because these are replies rather than key events, and a
// witness should be free to treat them differently — not least by serving them
// back to somebody asking where this identity currently is.
// Two kinds of witness answer on two different paths.
//
// A contact witnessing for somebody is an Identity Agent, and everything an
// Identity Agent serves sits under /api. A commercial witness is a service
// built for the one job and serves the witness protocol at the root. Posting an
// agent's path to a service — which is what happened until now — reaches a
// route that does not exist, so every event sent to the bootstrap pool was
// answered 404 and no receipt ever came back. Nothing reported it, because a
// witness that does not answer is indistinguishable from one that is down, and
// the broadcast is deliberately tolerant of that.
func witnessBase(oobi string) string {
	base := oobi
	if idx := strings.Index(oobi, "/public/oobi/"); idx != -1 {
		base = oobi[:idx]
	}
	return strings.TrimRight(base, "/")
}

func witnessPathPrefix(commercial bool) string {
	if commercial {
		return ""
	}
	return "/api"
}

func witnessEndpointURL(t witnessTarget) string {
	return witnessBase(t.URL) + witnessPathPrefix(t.Commercial) + "/witness/endpoint"
}

func witnessEventURL(t witnessTarget) string {
	return witnessBase(t.URL) + witnessPathPrefix(t.Commercial) + "/witness/event"
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

// PublishEndpointRecord sends a signed endpoint reply to an AID's witnesses.
//
// This is what makes a relay address disposable. An OOBI handed to somebody
// persists in their store long after the address stops working, so when a relay
// is left or an allocation expires, every counterparty holding that string is
// stranded — the relationship breaks from an infrastructure change neither
// party made. Publishing where this identity currently is, to the witnesses
// named in its KEL, gives a stranded counterparty somewhere stable to ask.
//
// Deliberately NOT BroadcastEvent. An endpoint record is a reply, not a key
// event: it has no sequence number, takes no place in the KEL, and there is
// nothing for a receipt threshold to mean. Running it through finalization
// would invent a pending state that never resolves. What matters here is
// reaching the witnesses, not agreeing with them.
//
// Reaching SOME witnesses is success. A counterparty needs one that answers,
// not a quorum — and refusing to publish because one operator is down would
// leave the address stale everywhere, which is the failure being prevented.
func (s *Service) PublishEndpointRecord(ctx context.Context, signerAID string, record map[string]interface{}) error {
	rootAID := signerAID
	if id, _ := s.Contacts.GetIdentity(); id != nil {
		rootAID = id.AID
	}
	kind := ClassifyAID(signerAID, rootAID)
	witnesses, err := s.enrolledWitnesses(kind, signerAID)
	if err != nil {
		return err
	}
	if len(witnesses) == 0 {
		// Worth reporting rather than passing silently: an identity with no
		// witnesses has nowhere to publish, so a changed address will strand
		// every counterparty it was ever given to.
		return fmt.Errorf("no witnesses for %s — a changed address cannot be published", signerAID)
	}

	body, err := json.Marshal(map[string]interface{}{"aid": signerAID, "record": record})
	if err != nil {
		return fmt.Errorf("marshal endpoint record: %w", err)
	}

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		delivered int
	)
	for _, w := range witnesses {
		wg.Add(1)
		go func(target witnessTarget) {
			defer wg.Done()
			if _, perr := s.PostEvent(ctx, witnessEndpointURL(target), body); perr != nil {
				log.Printf("[witness] endpoint record to %s failed: %v", target.AID, perr)
				return
			}
			mu.Lock()
			delivered++
			mu.Unlock()
		}(w)
	}
	wg.Wait()

	if delivered == 0 {
		return fmt.Errorf("endpoint record for %s reached none of its %d witnesses",
			signerAID, len(witnesses))
	}
	log.Printf("[witness] endpoint record for %s published to %d/%d witnesses",
		signerAID, delivered, len(witnesses))
	return nil
}

// delegatorApproves is the delegator of a delegated inception, when this agent
// witnesses for that delegator and holds, in its key log, the approval of
// exactly this inception.
func (s *Service) delegatorApproves(event map[string]interface{}) (string, bool) {
	if event["t"] != "dip" {
		return "", false
	}
	delegator, _ := event["di"].(string)
	aid, _ := event["i"].(string)
	said := eventSAID(event)
	if delegator == "" || aid == "" || said == "" {
		return "", false
	}
	dm, _ := s.Store.GetContactMeta(delegator)
	if dm == nil || !dm.WitnessingFor {
		return "", false
	}
	held, err := s.Store.GetKelEvents(delegator)
	if err != nil {
		return "", false
	}
	for _, e := range held {
		raw, err := base64.StdEncoding.DecodeString(e.RawBytesB64)
		if err != nil {
			continue
		}
		var ev map[string]interface{}
		if json.Unmarshal(raw, &ev) != nil {
			continue
		}
		seals, _ := ev["a"].([]interface{})
		for _, x := range seals {
			if seal, ok := x.(map[string]interface{}); ok && seal["i"] == aid && seal["s"] == "0" && seal["d"] == said {
				return delegator, true
			}
		}
	}
	return "", false
}

// alreadyHeld answers an event this witness already holds at seq: with its
// receipt when it is the same event, as a conflict when it is not.
// supersededHere is whether this witness holds the event as replaced by a
// recovery rotation.
func (s *Service) supersededHere(signerAID, said string) bool {
	gone, err := s.Store.GetSupersededKelEvents(signerAID)
	if err != nil {
		return false
	}
	for _, e := range gone {
		if e.EventSAID == said {
			return true
		}
	}
	return false
}

func (s *Service) alreadyHeld(signerAID string, seq int, said string) (map[string]interface{}, error) {
	held, err := s.Store.GetKelEvents(signerAID)
	if err != nil {
		return nil, err
	}
	for _, e := range held {
		if e.SequenceNum != seq {
			continue
		}
		if e.EventSAID != said {
			return nil, fmt.Errorf("duplicate_sequence")
		}
		rct, _ := s.Store.GetIssuedReceipt(signerAID, said)
		if rct == nil {
			return nil, fmt.Errorf("duplicate_sequence: held without a receipt")
		}
		var receipt map[string]interface{}
		_ = json.Unmarshal([]byte(rct.ReceiptJSON), &receipt)
		return map[string]interface{}{
			"event_said": said, "witness_aid": rct.WitnessAID, "sequence_number": seq,
			"receipt": receipt, "cesr_signature": rct.CesrSignature,
		}, nil
	}
	return nil, fmt.Errorf("duplicate_sequence")
}

// The operator's settings for witnessing the identities an identity this
// agent witnesses for has delegated: on by default; "off" stops it, and a
// number caps how many one delegator may have witnessed.
const (
	ConfigDelegates    = "witness.delegates"
	ConfigDelegatesMax = "witness.delegates_max"
	configDelegateOf   = "witness.delegate_of"
)

func (s *Service) delegateMap() map[string]string {
	out := map[string]string{}
	if raw, err := s.Store.GetConfig(configDelegateOf); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	return out
}

func (s *Service) saveDelegateMap(m map[string]string) {
	raw, _ := json.Marshal(m)
	_ = s.Store.SetConfig(configDelegateOf, string(raw))
}

// delegateOf is the delegator a delegate is witnessed under, or "".
func (s *Service) delegateOf(aid string) string {
	return s.delegateMap()[aid]
}

func (s *Service) recordDelegate(aid, delegator string) {
	s.delegatesMu.Lock()
	defer s.delegatesMu.Unlock()
	m := s.delegateMap()
	m[aid] = delegator
	s.saveDelegateMap(m)
}

// configDelegatorsCovered are the identities whose agreement to be witnessed
// asked for their delegates to be witnessed too.
const configDelegatorsCovered = "witness.delegators_covered"

// agreeToDelegates records whether requester's agreement covers the
// identities it delegates.
func (s *Service) agreeToDelegates(requester string, covers bool) {
	s.delegatesMu.Lock()
	defer s.delegatesMu.Unlock()
	covered := map[string]bool{}
	if raw, err := s.Store.GetConfig(configDelegatorsCovered); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &covered)
	}
	if covers {
		covered[requester] = true
	} else {
		delete(covered, requester)
	}
	raw, _ := json.Marshal(covered)
	_ = s.Store.SetConfig(configDelegatorsCovered, string(raw))
}

// CoversDelegatesOf reports whether delegator's agreement asked for the
// identities it delegates to be witnessed too.
func (s *Service) CoversDelegatesOf(delegator string) bool { return s.delegatorCovered(delegator) }

// DelegatesWitnessedFor reports whether this witness will witness the
// identities delegator delegates: its agreement asked, and the operator has not
// switched delegate witnessing off.
func (s *Service) DelegatesWitnessedFor(delegator string) bool {
	if v, _ := s.Store.GetConfig(ConfigDelegates); strings.EqualFold(strings.TrimSpace(v), "off") {
		return false
	}
	return s.delegatorCovered(delegator)
}

func (s *Service) delegatorCovered(delegator string) bool {
	covered := map[string]bool{}
	if raw, err := s.Store.GetConfig(configDelegatorsCovered); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &covered)
	}
	return covered[delegator]
}

// delegatesAccepted reports whether another delegate of delegator may be
// witnessed: its agreement asked for it, and the operator's settings allow it.
func (s *Service) delegatesAccepted(delegator string) bool {
	if !s.delegatorCovered(delegator) {
		return false
	}
	if v, _ := s.Store.GetConfig(ConfigDelegates); strings.EqualFold(strings.TrimSpace(v), "off") {
		return false
	}
	v, _ := s.Store.GetConfig(ConfigDelegatesMax)
	max, err := strconv.Atoi(strings.TrimSpace(v))
	if v == "" || err != nil || max < 0 {
		return true
	}
	n := 0
	for _, d := range s.delegateMap() {
		if d == delegator {
			n++
		}
	}
	return n < max
}

// dropDelegatesOf stops witnessing every identity delegator delegated.
func (s *Service) dropDelegatesOf(delegator string) {
	s.delegatesMu.Lock()
	defer s.delegatesMu.Unlock()
	m := s.delegateMap()
	for aid, d := range m {
		if d != delegator {
			continue
		}
		if meta, _ := s.Store.GetContactMeta(aid); meta != nil && meta.WitnessingFor {
			meta.WitnessingFor = false
			_ = s.Store.SaveContactMeta(*meta)
		}
		delete(m, aid)
		log.Printf("[witness] stopped witnessing %s, delegated by %s, which this agent no longer witnesses", aid, delegator)
	}
	s.saveDelegateMap(m)
}

func (s *Service) confirmedTip(aid, witnessKey string) int {
	v, ok := s.confirmed.Load(aid + "|" + witnessKey)
	if !ok {
		return -1
	}
	c := v.(confirmation)
	// Asked again now and then even when nothing has changed here, so a
	// witness that has fallen behind (restored from an older copy, say) is
	// noticed and filled again.
	if time.Since(c.at) > RecheckWitnessesEvery {
		return -1
	}
	return c.sn
}

// RecheckWitnessesEvery is how long a witness's confirmed tip is trusted
// before the witness is asked again.
var RecheckWitnessesEvery = time.Hour

// confirmation is how far a witness was last shown to hold a key log, and
// when.
type confirmation struct {
	sn int
	at time.Time
}

// confirm records a receipt showing a witness holds a key log to sn: never
// lowered by one, and the time it was last shown kept.
func (s *Service) confirm(aid, witnessKey string, sn int) {
	key := aid + "|" + witnessKey
	for {
		now := confirmation{sn: sn, at: time.Now()}
		v, loaded := s.confirmed.LoadOrStore(key, now)
		if !loaded {
			return
		}
		old := v.(confirmation)
		if old.sn > sn {
			now.sn = old.sn
		}
		if s.confirmed.CompareAndSwap(key, v, now) {
			return
		}
	}
}

// heldNow records how far a witness says, in a signed tip, it holds a key
// log now: what it says, higher or lower than before.
func (s *Service) heldNow(aid, witnessKey string, sn int) {
	s.confirmed.Store(aid+"|"+witnessKey, confirmation{sn: sn, at: time.Now()})
}
