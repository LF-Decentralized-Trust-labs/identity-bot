package witness

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	keri "github.com/grapeid/keri-go"
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
	// maxCoverInception bounds the inception event a declaration carries.
	maxCoverInception = 8 << 10
)

// CoverStatement is what the owner signs: who it is, which witness (by the key
// its receipts are signed with, so a declaration for one cannot be replayed to
// another), which identifier, the SAID of the inception that makes it, and when.
func CoverStatement(owner, witnessKey, aid, inceptionSAID, stamp string) string {
	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s", coverVersion, owner, witnessKey, aid, inceptionSAID, stamp)
}

// CoverRequest is a declaration that aid is the owner's, to be witnessed.
type CoverRequest struct {
	Owner        string `json:"owner_aid"`
	AID          string `json:"aid"`
	InceptionB64 string `json:"inception_b64"`
	Stamp        string `json:"stamp"`
	Signature    string `json:"signature"`
}

// AcceptCover is the witness's side: it holds the log of req.AID from now on,
// under req.Owner, when the owner is one this witness witnesses for whose
// agreement covers the identities it makes (and the operator's settings allow
// another), the declaration is the owner's own, fresh, for this witness, and
// the inception is the identifier's own. The reasons are for the owner's
// agent; nothing else is told them.
func (s *Service) AcceptCover(req CoverRequest) error {
	if req.Owner == "" || req.AID == "" || req.Owner == req.AID {
		return fmt.Errorf("not_covered: the declaration names no owner and identifier")
	}
	if len(req.InceptionB64) > maxCoverInception*4/3+8 {
		return fmt.Errorf("not_covered: the inception is too large")
	}
	raw, err := base64.StdEncoding.DecodeString(req.InceptionB64)
	if err != nil || len(raw) == 0 || len(raw) > maxCoverInception {
		return fmt.Errorf("not_covered: the inception is not readable")
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
	// The inception is the identifier's own: one event, which derives it.
	ev, err := keri.ParseEvent(raw)
	if err != nil || ev.Ilk != "icp" || ev.Identifier != req.AID {
		return fmt.Errorf("not_covered: the inception is not this identifier's")
	}
	if err := keri.ValidateKEL([][]byte{raw}); err != nil {
		return fmt.Errorf("not_covered: the inception does not derive its identifier")
	}
	if !s.signedBy(req.Owner, CoverStatement(req.Owner, own, req.AID, ev.SAID, req.Stamp), req.Signature) {
		return fmt.Errorf("not_covered: the declaration is not signed by the owner")
	}
	if meta, _ := s.Store.GetContactMeta(req.Owner); meta == nil || !meta.WitnessingFor {
		return fmt.Errorf("not_covered: this witness does not witness for the owner")
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
// aid, whose inception is the event given, is this agent's own, signed with the
// key this agent is witnessed under. witnessKey is the key the witness's
// receipts are signed with (ProposedWitness.Key).
func (s *Service) RequestCover(ctx context.Context, root, witnessKey, aid string, inception []byte) error {
	if s.SignAsRequester == nil || s.ourAID() == "" {
		return fmt.Errorf("this agent cannot sign a declaration")
	}
	ev, err := keri.ParseEvent(inception)
	if err != nil || ev.Identifier != aid {
		return fmt.Errorf("the inception is not %s's", aid)
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	sig, err := s.SignAsRequester(CoverStatement(s.ourAID(), witnessKey, aid, ev.SAID, stamp))
	if err != nil {
		return err
	}
	body, err := json.Marshal(CoverRequest{Owner: s.ourAID(), AID: aid, InceptionB64: base64.StdEncoding.EncodeToString(inception), Stamp: stamp, Signature: sig})
	if err != nil {
		return err
	}
	url := strings.TrimRight(root, "/") + "/witness/cover"
	_, err = s.PostEvent(s.ownersLocalAllowed(ctx, url), url, body)
	return err
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
