package witness

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/login"
)

// A witness holds the key log of an identifier only for one it was asked to
// witness: an accepted contact (enrollment.go), or an identifier delegated by
// one it witnesses for (the delegator's own log approves the inception). A plain
// identifier an owner makes for a purpose of its own, with no delegator, is
// neither: it is not a contact, and nothing in a key log can say whose it is. The
// owner says so, signed with the key it is witnessed under, and this is that
// statement.
//
// What the owner declares is "this identifier, whose inception is this event, is
// mine": the witness then holds its log under the owner exactly as it holds a
// delegate's (delegateOf, dropDelegatesOf, the owner's agreement to be
// witnessed covering them, the operator's switch and cap), so an owner that is
// no longer witnessed loses them with it. It carries no authority over the owner:
// it makes the witness hold a log, and nothing else.
const (
	coverVersion = "witness-cover/v1"
	// maxCoverInception bounds each event of the key log a declaration carries,
	// and maxCoverEvents how many.
	maxCoverInception = 8 << 10
	maxCoverEvents    = 256 // what a relay takes of one log (relayproto.MaxKELEvents)
)

// CoverStatement is what the owner signs, and what the identifier signs too, by
// its own current key, to show the owner did not claim someone else's: who it is, which witness (by the key
// its receipts are signed with, so a declaration for one cannot be replayed to
// another), which identifier, the SAID of the inception that makes it, and when.
func CoverStatement(owner, witnessKey, aid, inceptionSAID, stamp string) string {
	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s", coverVersion, owner, witnessKey, aid, inceptionSAID, stamp)
}

// CoverRequest is a declaration that aid is the owner's, to be witnessed. Log is
// the identifier's signed key log from its inception to now (a log is public, so
// it proves nothing alone), and AIDSignature is the identifier's own signature,
// by the key that log leaves in force, over the same statement the owner signs:
// the proof that the one declaring controls it.
type CoverRequest struct {
	Owner        string        `json:"owner_aid"`
	AID          string        `json:"aid"`
	Log          []SignedEvent `json:"log"`
	Stamp        string        `json:"stamp"`
	Signature    string        `json:"signature"`
	AIDSignature string        `json:"aid_signature"`
}

// AcceptCover is the witness's side: it holds the log of req.AID from now on,
// under req.Owner, when the owner is one this witness witnesses for whose
// agreement covers the identities it makes (and the operator's settings allow
// another), the declaration is the owner's own, fresh, for this witness, the
// key log is the identifier's own, and the key that log leaves in force signed
// it too: an inception is public, so the owner's word alone would let any
// witnessed owner claim another's identifier first and keep the real owner out.
// The reasons are for the owner's agent; nothing else is told them.
func (s *Service) AcceptCover(req CoverRequest) error {
	if req.Owner == "" || req.AID == "" || req.Owner == req.AID {
		return fmt.Errorf("not_covered: the declaration names no owner and identifier")
	}
	if len(req.Log) == 0 || len(req.Log) > maxCoverEvents {
		return fmt.Errorf("not_covered: the key log is not readable")
	}
	messages := make([][]byte, 0, len(req.Log))
	for _, e := range req.Log {
		raw, err := base64.StdEncoding.DecodeString(e.RawBytesB64)
		if err != nil || len(raw) == 0 || len(raw) > maxCoverInception {
			return fmt.Errorf("not_covered: the key log is not readable")
		}
		sigs := e.Signatures
		if len(sigs) == 0 && e.CesrSignature != "" {
			sigs = []string{e.CesrSignature}
		}
		m, err := signedMessage(raw, sigs)
		if err != nil {
			return fmt.Errorf("not_covered: the key log is not readable")
		}
		messages = append(messages, m)
	}
	own := ""
	if s.OurWitnessAID != nil {
		own, _ = s.OurWitnessAID()
	}
	if own == "" {
		return fmt.Errorf("not_covered: this agent has no witnessing key")
	}
	at, err := time.Parse(time.RFC3339Nano, req.Stamp)
	if err != nil || time.Since(at) > requestFreshness || time.Until(at) > requestFreshness {
		return fmt.Errorf("not_covered: the declaration is not fresh")
	}
	// One declaration of an identifier at a time, and not while its events are being judged.
	mu := s.receivingLock(req.AID)
	mu.Lock()
	defer mu.Unlock()
	// The cheap checks first, so a stranger spends this witness's work on a
	// signature and nothing more: the first event is the identifier's inception,
	// and the owner, which this witness witnesses for, signed the declaration.
	first, err := keri.ParseEvent(eventBytesOf(req.Log[0]))
	if err != nil || first.Ilk != "icp" || first.Identifier != req.AID {
		return fmt.Errorf("not_covered: the key log is not this identifier's")
	}
	statement := CoverStatement(req.Owner, own, req.AID, first.SAID, req.Stamp)
	if !s.signedBy(req.Owner, statement, req.Signature) {
		return fmt.Errorf("not_covered: the declaration is not signed by the owner")
	}
	if meta, _ := s.Store.GetContactMeta(req.Owner); meta == nil || !meta.WitnessingFor {
		return fmt.Errorf("not_covered: this witness does not witness for the owner")
	}
	// Then the proof of control. The log is the identifier's own and correctly
	// signed, from an inception that derives it, and the key it leaves in force is
	// one key, which signed the same statement.
	log, err := keri.ValidateSignedKEL(messages)
	if err != nil {
		return fmt.Errorf("not_covered: the key log does not verify")
	}
	keys := log.State().Keys()
	if len(keys) != 1 {
		return fmt.Errorf("not_covered: the identifier's control cannot be shown by one key")
	}
	if !signedByKey(keys[0], statement, req.AIDSignature) {
		return fmt.Errorf("not_covered: the identifier did not sign the declaration")
	}
	// An identifier already held is held under whoever it is held under: a
	// declaration cannot take it from them, nor take a contact this witness
	// already witnesses for (a root identifier's inception is public too), and it
	// takes no more of the owner's allowance to say it again.
	s.delegatesMu.Lock()
	defer s.delegatesMu.Unlock()
	heldUnder := s.delegateMap()[req.AID]
	meta, _ := s.Store.GetContactMeta(req.AID)
	if heldUnder != "" && heldUnder != req.Owner || heldUnder == "" && meta != nil && meta.WitnessingFor {
		return fmt.Errorf("not_covered: this identifier is already witnessed for another")
	}
	if heldUnder != req.Owner && !s.delegatesAccepted(req.Owner) {
		return fmt.Errorf("not_covered: the owner's agreement does not cover its identifiers, or this witness's operator does not accept more")
	}
	// Held under the owner as a delegate is, with no contact made for it.
	if meta == nil {
		meta = &ContactMeta{ContactAID: req.AID}
	}
	now := NowRFC3339()
	if !meta.WitnessingFor {
		meta.BackendType, meta.WitnessStatus, meta.WitnessingFor = BackendDesktop, StatusOnline, true
		meta.EnrolledAt, meta.LastHealthCheck = now, now
		if err := s.Store.SaveContactMeta(*meta); err != nil {
			return err
		}
	}
	m := s.delegateMap()
	m[req.AID] = req.Owner
	s.saveDelegateMap(m)
	return nil
}

// RequestCover is the owner's side: declares to the witness at root (the base
// its routes resolve against, ending in a slash, as ProposedWitness.Address) that
// aid, whose signed key log is log, is this agent's own, signed with the key this
// agent is witnessed under, and by the identifier's own key in force
// (signAsIdentifier). witnessKey is the key the witness's receipts are signed
// with (ProposedWitness.Key).
//
// Nothing in this repository calls it: the caller is a program that makes the
// identifier (an add-on), which holds the identifier's key and so can sign for it.
func (s *Service) RequestCover(ctx context.Context, root, witnessKey, aid string, log []SignedEvent, signAsIdentifier func(statement string) (string, error)) error {
	if s.SignAsRequester == nil || s.ourAID() == "" || signAsIdentifier == nil || len(log) == 0 {
		return fmt.Errorf("this agent cannot sign a declaration")
	}
	ev, err := keri.ParseEvent(eventBytesOf(log[0]))
	if err != nil || ev.Identifier != aid {
		return fmt.Errorf("the key log is not %s's", aid)
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	statement := CoverStatement(s.ourAID(), witnessKey, aid, ev.SAID, stamp)
	sig, err := s.SignAsRequester(statement)
	if err != nil {
		return err
	}
	idSig, err := signAsIdentifier(statement)
	if err != nil {
		return err
	}
	body, err := json.Marshal(CoverRequest{Owner: s.ourAID(), AID: aid, Log: log, Stamp: stamp, Signature: sig, AIDSignature: idSig})
	if err != nil {
		return err
	}
	url := strings.TrimRight(root, "/") + "/witness/cover"
	_, err = s.PostEvent(s.ownersLocalAllowed(ctx, url), url, body)
	return err
}

// eventBytesOf is the event a SignedEvent carries, nil when it does not decode.
func eventBytesOf(e SignedEvent) []byte {
	raw, _ := base64.StdEncoding.DecodeString(e.RawBytesB64)
	return raw
}

// signedByKey reports whether signature is over statement by key (a qb64 public key).
func signedByKey(key, statement, signature string) bool {
	if signature == "" {
		return false
	}
	raw, err := login.DecodeVerkey(key)
	if err != nil {
		return false
	}
	ok, err := login.VerifyString(statement, signature, raw)
	return err == nil && ok
}

// forgetDelegate drops aid's entry in the held-under map, whoever it was held under.
func (s *Service) forgetDelegate(aid string) {
	s.delegatesMu.Lock()
	defer s.delegatesMu.Unlock()
	m := s.delegateMap()
	if _, ok := m[aid]; ok {
		delete(m, aid)
		s.saveDelegateMap(m)
	}
}
