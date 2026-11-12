package watcher

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	keri "github.com/grapeid/keri-go"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
	"identity-agent-core/iacrypto"
)

// Service is the watcher engine (L1 self-watch + L2/L3 clients).
type Service struct {
	// PeerAllowed gates which peers this agent will cross-check with. See
	// peer_boundary.go.
	PeerAllowed PeerAllowed
	Store       Store
	L2          *L2Client
	// PeerWatchers supplies the peers to cross-check with. See peer_selection.go.
	PeerWatchers PeerWatcherSource
	L3           *L3Client
	OnEvent      func(eventType string, payload map[string]interface{})
	// SignDigest signs the statement of a digest answer with this agent's
	// watcher key and names that key. Unset, answers go out unsigned, which no
	// verifier accepts.
	SignDigest func(statement string) (signerAID, cesrSig string, err error)
	// SignRequest signs a cross-check request to one contact, as the identifier
	// that contact knows this agent by, and names it. Unset, no peer is asked.
	// It is deliberately not the witness key: a signature by that key, which a
	// verifier can carry to others, would tell the contact (and anyone it showed)
	// that this agent asked about an identity, and the contact has no other reason
	// to know that key. The key a contact already knows us by says nothing new.
	SignRequest func(peerAID, statement string) (requesterAID, cesrSig string, err error)
	// VerifyRequester says whether requester is an accepted contact of this
	// agent and sig is its signature over statement. Unset, no cross-check is
	// answered with anything but "no match".
	VerifyRequester func(requester, statement, sig string) bool
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	replays replayCache
}

func NewService(store Store) *Service {
	s := &Service{
		Store: store,
		L2:    NewL2Client(),
		L3:    NewL3Client(),
	}
	s.L2.TrustedSigners = s.TrustedL2Signers
	return s
}

// DefaultL2SignerAIDs are the watchers whose signed answers ship trusted. It is
// empty until the default watcher has an identifier of its own; until then an
// agent trusts only what its owner adds under "l2_signer_aids".
var DefaultL2SignerAIDs = []string{}

// TrustedL2Signers is every watcher whose signature on a digest answer is
// accepted: the shipped ones plus any the owner added, as a JSON list in
// watcher_config "l2_signer_aids". A stored row never replaces the shipped list.
func (s *Service) TrustedL2Signers() []string {
	out := append([]string{}, DefaultL2SignerAIDs...)
	if s.Store != nil {
		if raw, _ := s.Store.GetConfig("l2_signer_aids"); raw != "" {
			var extra []string
			if json.Unmarshal([]byte(raw), &extra) == nil {
				out = append(out, extra...)
			}
		}
	}
	return out
}

func (s *Service) DefaultL2URL() string {
	if s.Store == nil {
		return DefaultL2DigestURL
	}
	if v, _ := s.Store.GetConfig("default_l2_url"); v != "" {
		return v
	}
	return DefaultL2DigestURL
}

func (s *Service) WatcherHints() []string {
	if s.Store == nil {
		return nil
	}
	raw, _ := s.Store.GetConfig("watcher_hints")
	if raw == "" {
		return []string{}
	}
	var hints []string
	_ = json.Unmarshal([]byte(raw), &hints)
	return hints
}

func (s *Service) SetWatcherHints(urls []string) error {
	b, err := json.Marshal(urls)
	if err != nil {
		return err
	}
	return s.Store.SetConfig("watcher_hints", string(b))
}

// RecordFirstSeen stores L1 digest at seq (creates or reinforces).
func (s *Service) RecordFirstSeen(aid string, seq int, digest string, source SourceType, sourceURL string) error {
	return s.recordFirstSeen(aid, seq, digest, source, sourceURL, false)
}

// recordFirstSeen is RecordFirstSeen that also says whether the log it comes
// from verified. A sighting once proven stays proven.
func (s *Service) recordFirstSeen(aid string, seq int, digest string, source SourceType, sourceURL string, proven bool) error {
	now := time.Now().UTC()
	existing, err := s.Store.getFirstSeen(aid, seq)
	if err != nil {
		return err
	}
	count := 1
	if existing != nil {
		count = existing.SeenCount + 1
	}
	return s.Store.RecordFirstSeen(FirstSeenRecord{
		AID: aid, SequenceNum: seq, KelDigest: digest,
		FirstSeenAt: firstSeenTime(existing, now), LastConfirmedAt: now,
		SeenCount: count, SourceType: source, SourceURL: sourceURL, Proven: proven,
	})
}

func firstSeenTime(existing *FirstSeenRecord, now time.Time) time.Time {
	if existing != nil {
		return existing.FirstSeenAt
	}
	return now
}

// detectDuplicity compares digest against stored first-seen at same seq.
func (s *Service) detectDuplicity(aid string, seq int, digest string) (bool, *FirstSeenRecord, error) {
	existing, err := s.Store.getFirstSeen(aid, seq)
	if err != nil {
		return false, nil, err
	}
	if existing == nil {
		return false, nil, nil
	}
	if existing.KelDigest == digest {
		_ = s.RecordFirstSeen(aid, seq, digest, existing.SourceType, existing.SourceURL)
		return false, existing, nil
	}
	return true, existing, nil
}

// VerifyKel runs the L1 + L2-standing verification pipeline for a KEL encounter.
func (s *Service) VerifyKel(ctx context.Context, in VerifyKelInput) (*VerifyKelResult, error) {
	seq, err := witnessproto.CurrentSeq(in.KEL)
	if err != nil {
		// Refused rather than passed over. An error here reaches callers as
		// "nothing to say", so a log that could not be placed would skip every
		// check below, and one malformed event is all it would take.
		return &VerifyKelResult{
			OK: false, Blocked: true, AID: in.AID, SequenceNum: -1,
			Reason: "the key log has an unreadable sequence number: " + err.Error(), OverallOutcome: "unreadable",
		}, nil
	}
	if seq < 0 {
		return &VerifyKelResult{OK: false, Reason: "empty KEL"}, nil
	}
	digest, err := witnessproto.KelDigestAtSeq(in.KEL, seq)
	if err != nil {
		return nil, err
	}

	result := &VerifyKelResult{
		AID: in.AID, SequenceNum: seq, Digest: digest,
		sourcesQueried: []SourceOutcome{},
	}

	existing, _ := s.Store.getFirstSeen(in.AID, seq)
	firstContact := existing == nil
	result.firstContact = firstContact

	// A digest is remembered from any log, but only a log that verifies (signed by
	// its own controller) can found a sighting that later refuses a log. Otherwise
	// anybody could plant a digest for an identity they do not control with a
	// made-up log, and the identity's real log would be refused for differing from
	// it. A proven log replaces a planted sighting; an unproven one never
	// contradicts a proven one.
	proven := false
	if len(in.Signed) > 0 {
		if v, err := keri.ValidateSignedKEL(in.Signed); err == nil && v.Identifier == in.AID {
			proven = true
		}
	}

	var l1Outcome string
	switch {
	case existing == nil:
		l1Outcome = "first_seen"
		if err := s.recordFirstSeen(in.AID, seq, digest, in.SourceType, in.SourceURL, proven); err != nil {
			return nil, err
		}
	case existing.KelDigest == digest:
		l1Outcome = "match"
		_ = s.recordFirstSeen(in.AID, seq, digest, in.SourceType, in.SourceURL, proven)
	case proven && !existing.Proven:
		// What was remembered came from a log that proved nothing. The proven one
		// takes its place, and nothing is refused.
		l1Outcome = "first_seen"
		if err := s.recordFirstSeen(in.AID, seq, digest, in.SourceType, in.SourceURL, true); err != nil {
			return nil, err
		}
	case proven && existing.Proven:
		l1Outcome = "mismatch"
	default:
		// Shown, never refused on: this log proves nothing.
		l1Outcome = "unproven_mismatch"
	}
	result.sourcesQueried = append(result.sourcesQueried, SourceOutcome{Type: "L1", Outcome: l1Outcome})

	// Every standing watcher is asked. The first is the default one, whose
	// answer the rest of this pipeline (open alerts, escalation) is built on.
	// A watcher whose digest differs is then asked for its log and judged on
	// it: what it can prove is acted on, what it cannot is shown.
	answers := s.askStanding(ctx, in.AID, seq, digest, result)
	for i := range answers {
		s.judge(ctx, in, &answers[i])
		result.sourcesQueried = append(result.sourcesQueried, SourceOutcome{
			Type: "L2_standing", URL: answers[i].w.URL, Outcome: answers[i].outcome,
		})
	}
	l2URL, l2Outcome, l2Resp := answers[0].w.URL, answers[0].outcome, answers[0].resp
	var fork *standingAnswer
	for i := range answers {
		if answers[i].outcome == "fork" {
			fork = &answers[i]
			break
		}
	}

	// Bootstrap hints — advisory only (never block alone)
	for _, hint := range in.BootstrapL2 {
		if hint == l2URL {
			continue
		}
		resp, _, err := s.L2.QueryDigest(ctx, hint, in.AID, seq)
		outcome := "unknown"
		if err != nil {
			outcome = "unavailable"
		} else if resp.Digest != nil {
			if *resp.Digest == digest {
				outcome = "match"
			} else {
				outcome = "mismatch"
			}
		}
		result.sourcesQueried = append(result.sourcesQueried, SourceOutcome{
			Type: "L2_bootstrap", URL: hint, Outcome: outcome,
		})
	}

	// Blocking: this agent's own record of the contact differs from what it is
	// shown, or a standing watcher proved two histories: two validly signed
	// events at one place, which one watcher's evidence is enough to show.
	shouldBlock := false
	blockReason := ""
	var heldAlert *DuplicityAlert
	var evidence string
	if l1Outcome == "mismatch" {
		shouldBlock = true
		blockReason = "L1 digest mismatch at same sequence"
	} else if fork != nil {
		shouldBlock = true
		blockReason = "proof of duplicity: " + fork.proof.Reason
		l2URL, l2Resp = fork.w.URL, fork.resp
		evidence = fork.proof.Evidence.json()
	} else if held := s.forkedByOpenAlert(ctx, in, answers, seq); held != nil {
		// Not only the first time: the first sighting is recorded before this
		// verdict, so a second try finds this agent's own record agreeing and
		// would pass a log the standing watcher disagrees with. And not only the
		// same log: the same fork one event longer has a new tip and no first
		// sighting, but it still carries the history an open alert is about. So
		// for every open alert, the presented log's digest at the alert's own
		// sequence number is compared with the alert's; where it is the same
		// history, the log stays blocked unless the standing watcher now
		// positively answers match at that sequence. An unreachable watcher
		// cannot be used to wait the block out, and neither can one more event.
		// The owner resolving the alert ends it.
		shouldBlock = true
		heldAlert = held
		blockReason = "a standing watcher disagrees with what this log is known to be, and an alert about it is still open"
	}

	// A watcher that disagrees and cannot show why. That is one watcher against
	// what this log says, not proof of anything, so it blocks nothing; the owner
	// is told rather than left to find out. (One that can show its log is judged
	// above: a fork blocks, and one whose answer does not hold up is flagged below.)
	unproven := false
	for _, an := range answers {
		unproven = unproven || an.outcome == "mismatch"
	}
	escalate := !shouldBlock && (unproven || l1Outcome == "unproven_mismatch")

	// L3 — the contacts the owner chose, when the owner turned peer checks on.
	//
	// Asking tells a contact whom this agent is dealing with, so it is done only
	// where the answer is worth that. The answer is context: it is recorded and
	// never quiets or changes the escalation, because the contact able to answer
	// is the identity's own controller, which is also the party that showed this
	// agent the branch in question.
	if escalate && !firstContact {
		peerOutcomes, _ := s.crossCheckPeers(ctx, in.AID, seq, digest, in.SourceURL)
		result.sourcesQueried = append(result.sourcesQueried, peerOutcomes...)
	}

	if shouldBlock {
		// Blocked by an alert that is already open: that alert is the record,
		// and no second one is added for the same history.
		alert := heldAlert
		if alert == nil {
			var err error
			if _, alert, err = s.recordDuplicity(in.AID, seq, digest, l2URL, existing, l2Resp, evidence); err != nil {
				// The refusal stands: a store fault must not let a proven fork
				// through. Only the record of it is lost, and that is said.
				log.Printf("[watcher] could not keep the duplicity alert for %s at %d: %v", in.AID, seq, err)
				alert = nil
			}
		}
		result.Blocked = true
		result.OK = false
		result.Reason = blockReason
		result.OverallOutcome = "duplicity"
		result.duplicityAlert = alert
		s.emit("kel_duplicity_detected", map[string]interface{}{
			"aid": in.AID, "seq": seq, "reason": blockReason,
		})
		_ = s.AnchorAlertToKEL(alert)
		return result, nil
	}

	if firstContact && l1Outcome == "first_seen" && !escalate && (l2Outcome == "match" || l2Outcome == "unknown") {
		s.emit("kel_first_contact_confirmed", map[string]interface{}{"aid": in.AID, "seq": seq})
	}

	result.OK = true
	result.OverallOutcome = "confirmed"
	// A watcher whose answer did not hold up is raised as an alert about the
	// watcher, not the contact, which goes ahead.
	for _, an := range answers {
		switch an.outcome {
		case "faulty":
			s.flagWatcher(in.AID, seq, digest, an)
			result.FlaggedWatchers = append(result.FlaggedWatchers, an.w.URL)
		case "ahead", "superseded":
			// The watcher holds validly signed later events: the presented log
			// showed a stale key state. Handed back for the caller to adopt before
			// it verifies anything signed.
			if result.Latest == nil || len(an.proof.LatestMessages) > len(result.Latest) {
				result.Latest = an.proof.LatestMessages
				result.LatestKeys = an.proof.Latest.Keys
				result.LatestRecords = an.proof.LatestRecords
				result.LatestSeq = int(an.proof.Latest.State().SN())
			}
			result.Reason = an.proof.Reason
		}
	}
	if escalate {
		// Not a block: no proof. But a watcher holds a different digest, so the
		// owner is told rather than left to find out, whatever a contact says.
		result.OverallOutcome = "escalated"
		s.escalate(in.AID, seq)
	}
	s.emit("kel_verification", map[string]interface{}{
		"aid": in.AID, "sequence_num": seq, "sources": result.sourcesQueried,
		"overall_outcome": result.OverallOutcome,
	})
	s.pruneAID(in.AID, seq)
	return result, nil
}

// openAlertFor says whether an alert about this exact log (aid, seq, digest)
// is still open.
// Only duplicity alerts count: an escalation never blocks.
func (s *Service) openAlertFor(aid string, seq int, digest string) bool {
	return s.openAlert(aid, seq, digest) != nil
}

func (s *Service) openAlert(aid string, seq int, digest string) *DuplicityAlert {
	alerts, err := s.Store.listDuplicityAlerts(aid)
	if err != nil {
		return nil
	}
	for _, a := range alerts {
		if a.SequenceNum == seq && a.OurDigest == digest && !a.Resolved && isDuplicity(a) {
			a := a
			return &a
		}
	}
	return nil
}

func isDuplicity(a DuplicityAlert) bool { return a.Kind == "" || a.Kind == AlertKindDuplicity }

// forkedByOpenAlert returns an open duplicity alert that holds the presented log,
// or nil when there is none or the standing watcher clears the log.
//
// While any duplicity alert is open for the identity, every presented log is
// blocked unless the standing watcher answers match at the log's tip, and also,
// for each open alert, at that alert's own sequence number when the log reaches
// that far. Nothing is inferred from the log alone: a fork that split before the
// tip it was first blocked at, or is cut shorter than it, has no first sighting
// and may not be able to compute the alerted digest, so only a positive answer
// from the standing watcher lets it through. An unreachable watcher cannot be
// used to wait the block out.
func (s *Service) forkedByOpenAlert(ctx context.Context, in VerifyKelInput, answers []standingAnswer, seq int) *DuplicityAlert {
	alerts, err := s.Store.listDuplicityAlerts(in.AID)
	if err != nil {
		return nil
	}
	var open []DuplicityAlert
	for _, a := range alerts {
		if !a.Resolved && isDuplicity(a) {
			open = append(open, a)
		}
	}
	if len(open) == 0 {
		return nil
	}
	// The default watcher must positively match. Any other standing watcher
	// that disagrees also keeps the log blocked, but one that is silent or
	// unreachable does not: it was never required to answer.
	if answers[0].outcome != "match" {
		a := open[0]
		return &a
	}
	for _, an := range answers[1:] {
		if an.outcome == "mismatch" || an.outcome == "fork" {
			a := open[0]
			return &a
		}
	}
	for _, a := range open {
		if a.SequenceNum == seq {
			continue // the tip, already confirmed above
		}
		d, err := witnessproto.KelDigestAtSeq(in.KEL, a.SequenceNum)
		if err != nil {
			continue // the log does not reach that far
		}
		for i, an := range answers {
			resp, _, err := s.L2.QueryDigest(ctx, an.w.URL, in.AID, a.SequenceNum)
			agrees := err == nil && resp != nil && resp.Digest != nil && *resp.Digest == d
			disagrees := err == nil && resp != nil && resp.Digest != nil && *resp.Digest != d
			if (i == 0 && !agrees) || (i > 0 && disagrees) {
				a := a
				return &a
			}
		}
	}
	return nil
}

func (s *Service) recordDuplicity(aid string, seq int, ourDigest, sourceURL string, existing *FirstSeenRecord, l2 *DigestResponse, evidence string) (int64, *DuplicityAlert, error) {
	// A retry of a log already alerted is the same alert, not another one to
	// resolve: the owner closes it once and the log passes.
	if open := s.openAlert(aid, seq, ourDigest); open != nil {
		return open.ID, open, nil
	}
	their := ""
	if existing != nil && existing.KelDigest != ourDigest {
		their = existing.KelDigest
	}
	if l2 != nil && l2.Digest != nil && *l2.Digest != ourDigest {
		their = *l2.Digest
	}
	alert := DuplicityAlert{
		AID: aid, SequenceNum: seq,
		OurDigest: ourDigest, TheirDigest: their,
		SourceURL: sourceURL, DetectedAt: s.now().UTC(), Evidence: evidence,
	}
	id, err := s.Store.InsertDuplicityAlert(alert)
	if err != nil {
		return 0, nil, err
	}
	alert.ID = id
	return id, &alert, nil
}

// Disclosable returns this watcher's first-seen record for aid at seq, or nil
// when there is none OR the identity opted out, so an opted-out identity is
// indistinguishable from one never seen. It and DisclosableAll and
// DisclosableAlerts are the only exported ways to read what the watcher has
// seen or caught: the store's reads are unexported, and
// TestNoExportedReadReturnsAnObservation fails on any other exported method
// that returns one. That keeps a route in another package from skipping the
// opt-out; it does not stop code inside this package from reading the store.
func (s *Service) Disclosable(aid string, seq int) (*FirstSeenRecord, error) {
	return disclose(s, aid, func() (*FirstSeenRecord, error) { return s.Store.getFirstSeen(aid, seq) })
}

// DisclosableAll is Disclosable for every sequence number held for aid.
func (s *Service) DisclosableAll(aid string) ([]FirstSeenRecord, error) {
	return disclose(s, aid, func() ([]FirstSeenRecord, error) { return s.Store.listFirstSeen(aid) })
}

// DisclosableAlerts is Disclosable for the duplicity alerts raised about aid.
func (s *Service) DisclosableAlerts(aid string) ([]DuplicityAlert, error) {
	return disclose(s, aid, func() ([]DuplicityAlert, error) { return s.Store.listDuplicityAlerts(aid) })
}

// disclose is the one opt-out check. The read runs whether or not the identity
// opted out and its result is then dropped, so an opted-out identity costs the
// same queries as one never seen and the time an answer takes does not tell
// them apart.
func disclose[T any](s *Service, aid string, read func() (T, error)) (T, error) {
	var none T
	opted, err := s.Store.IsOptedOut(aid)
	if err != nil {
		return none, err
	}
	found, err := read()
	if err != nil || opted {
		return none, err
	}
	return found, nil
}

// DisclosableAllAlerts is DisclosableAlerts for every identity: every alert this
// watcher holds except those about an identity that opted out.
func (s *Service) DisclosableAllAlerts() ([]DuplicityAlert, error) {
	all, err := s.Store.listAllAlerts()
	if err != nil {
		return nil, err
	}
	out := []DuplicityAlert{}
	opted := map[string]bool{}
	for _, a := range all {
		o, seen := opted[a.AID]
		if !seen {
			if o, err = s.Store.IsOptedOut(a.AID); err != nil {
				return nil, err
			}
			opted[a.AID] = o
		}
		if !o {
			out = append(out, a)
		}
	}
	return out, nil
}

// DisclosableCheck is Disclosable for the newest check of aid: nil when there is
// none or the identity opted out.
func (s *Service) DisclosableCheck(aid string) (*ContactCheck, error) {
	return disclose(s, aid, func() (*ContactCheck, error) { return s.Store.getContactCheck(aid) })
}

// DisclosableChecks is DisclosableCheck for every identity checked.
func (s *Service) DisclosableChecks() ([]ContactCheck, error) {
	all, err := s.Store.listContactChecks()
	if err != nil {
		return nil, err
	}
	out := []ContactCheck{}
	for _, c := range all {
		opted, err := s.Store.IsOptedOut(c.AID)
		if err != nil {
			return nil, err
		}
		if !opted {
			out = append(out, c)
		}
	}
	return out, nil
}

// ErrNoSuchAlert is returned for an alert that does not exist or is about an
// identity that opted out, which an owner cannot tell apart.
var ErrNoSuchAlert = errors.New("no such alert")

// ErrAlertAlreadyResolved is returned when an alert is resolved a second time:
// the alert is an audit record and its first note stands.
var ErrAlertAlreadyResolved = errors.New("alert already resolved")

// AcknowledgeAlert records that the owner has seen alert id.
func (s *Service) AcknowledgeAlert(id int64) error {
	if err := s.alertVisible(id); err != nil {
		return err
	}
	return s.Store.AcknowledgeAlert(id, time.Now())
}

// ResolveAlert closes alert id with the owner's note. The alert is kept, marked
// resolved: it is an audit record and is never deleted.
func (s *Service) ResolveAlert(id int64, note string) error {
	if err := s.alertVisible(id); err != nil {
		return err
	}
	return s.Store.ResolveAlert(id, note, time.Now())
}

func (s *Service) alertVisible(id int64) error {
	a, err := s.Store.getAlert(id)
	if err != nil {
		return err
	}
	if a == nil {
		return ErrNoSuchAlert
	}
	opted, err := s.Store.IsOptedOut(a.AID)
	if err != nil {
		return err
	}
	if opted {
		return ErrNoSuchAlert
	}
	return nil
}

// SetTrustedL2Signers replaces the watchers the owner trusts, on top of the
// shipped list. The shipped list is never replaced.
func (s *Service) SetTrustedL2Signers(aids []string) error {
	b, err := json.Marshal(aids)
	if err != nil {
		return err
	}
	return s.Store.SetConfig("l2_signer_aids", string(b))
}

// OwnerTrustedL2Signers is only the watchers the owner added.
func (s *Service) OwnerTrustedL2Signers() []string {
	out := []string{}
	if raw, _ := s.Store.GetConfig("l2_signer_aids"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	return out
}

// RecordCheck keeps the newest check of the identity a result is about.
func (s *Service) RecordCheck(res *VerifyKelResult) error {
	if res == nil || res.AID == "" {
		return nil
	}
	c := res.Check()
	// A duplicity verdict stands while its alert is open: a later check that
	// found nothing new must not show "confirmed" beside an alert nobody closed.
	if c.Verdict != VerdictDuplicity {
		if prev, err := s.Store.getContactCheck(res.AID); err == nil && prev != nil && prev.Verdict == VerdictDuplicity {
			if alerts, err := s.Store.listDuplicityAlerts(res.AID); err == nil {
				for _, a := range alerts {
					if !a.Resolved && isDuplicity(a) {
						return nil
					}
				}
			}
		}
	}
	return s.Store.SaveContactCheck(c)
}

// GetPublicDigest serves this agent's L1 observation for /public/kel-digest.
//
// Only an Identity Agent whose owner has opted in as a public watcher service
// (PublicWatcherService) answers truthfully: the digest and the time it was first
// seen, for every identity held, would otherwise let anyone list whom this agent
// has dealt with and when. Everyone else gets the signed "never seen" answer,
// which is a valid DigestStatement, so a client cannot tell it from a watcher
// that has not met the identity. The read runs either way, so it costs the same.
func (s *Service) GetPublicDigest(aid string, seq int) (*DigestResponse, error) {
	rec, err := s.Disclosable(aid, seq)
	if err != nil {
		return nil, err
	}
	if !s.PublicWatcherService() {
		rec = nil
	}
	resp := DigestResponse{AID: aid, SequenceNumber: seq}
	if rec == nil {
		s.signDigest(&resp)
		return &resp, nil
	}
	d := rec.KelDigest
	fs := rec.FirstSeenAt.UTC().Format(time.RFC3339)
	os := rec.FirstSeenAt.UTC().Format(time.RFC3339)
	resp.Digest = &d
	resp.FirstSeenAt = &fs
	resp.ObservedSince = &os
	s.signDigest(&resp)
	return &resp, nil
}

// signDigest signs the answer over the one statement witnessproto defines. If it
// cannot, the answer goes out unsigned: that is refused by every client, which
// is the honest outcome for a watcher that cannot prove who it is.
func (s *Service) signDigest(r *DigestResponse) {
	if s.SignDigest == nil {
		return
	}
	stmt, err := witnessproto.DigestStatement(r.AID, r.SequenceNumber, r.Digest, r.FirstSeenAt, r.ObservedSince)
	if err != nil {
		return
	}
	if by, sig, err := s.SignDigest(stmt); err == nil {
		r.SignedBy, r.Signature = by, sig
	}
}

// KelCheck handles POST /public/kel-check (L3 peer cross-check).
//
// It answers only a contact of this agent's, who signed the request, and only
// about an identity whose log this agent serves at its own address (the set
// GET /public/oobi/{aid} answers), comparing the digest with its own copy of
// that log. A contact cannot ask whether the owner has met some third party
// whose log it can fetch. And only with whether the digest it gave is the one
// held. Never the digest, never when it was first seen. Everything else, a request that is unsigned, signed by
// anybody who is not an accepted contact, for another address, outside the
// window, repeated, or about an identity not held, never seen, or opted out, gets
// the same "no match". That is what closes the oracle: anybody who can fetch an
// identity's key log can compute its digest, so a yes/no to a stranger would say
// whether this agent has met that identity.
//
// to is this agent's own public base URL, which the request must name. The
// second result says whether the request was from a contact, so the caller can
// hold only strangers to the shared limit.
// served gives the log this agent serves for an identifier, if it serves it.
func (s *Service) KelCheck(req KelCheckRequest, to string, served func(aid string) ([]map[string]interface{}, bool)) (*KelCheckResponse, bool, error) {
	noMatch := &KelCheckResponse{Match: false}
	if s.VerifyRequester == nil || to == "" || req.Requester == "" || req.Signature == "" || req.At == 0 || req.Digest == "" {
		return noMatch, false, nil
	}
	now := s.now()
	if d := now.Unix() - req.At; d > int64(kelCheckWindow/time.Second) || d < -int64(kelCheckWindow/time.Second) {
		return noMatch, false, nil
	}
	if !s.VerifyRequester(req.Requester, KelCheckRequestStatement(req.AID, req.Seq, req.Digest, strings.TrimRight(to, "/"), req.At), req.Signature) {
		return noMatch, false, nil
	}
	if !s.replays.first(fmt.Sprintf("%s\n%d\n%s\n%d", req.Requester, req.At, req.AID, req.Seq), now) {
		return noMatch, false, nil
	}
	// Both reads run whatever the answer, so an identity that is not served or
	// opted out costs what one served does.
	opted, err := s.Store.IsOptedOut(req.AID)
	if err != nil {
		return nil, true, err
	}
	var kel []map[string]interface{}
	ok := false
	if served != nil {
		kel, ok = served(req.AID)
	}
	ours, derr := witnessproto.KelDigestAtSeq(kel, req.Seq)
	if !ok || opted || derr != nil {
		return noMatch, true, nil
	}
	return &KelCheckResponse{Match: subtle.ConstantTimeCompare([]byte(ours), []byte(req.Digest)) == 1}, true, nil
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// escalate tells the owner that the hosted watcher disagrees with this agent's
// own record on a repeat contact. It is a broadcast event and nothing more:
// no duplicity alert is stored, because every open alert blocks the next check
// of that identity, and a disagreement that is not proof of anything must not.
func (s *Service) escalate(aid string, seq int) {
	s.emit("kel_l3_escalation", map[string]interface{}{
		"aid": aid, "seq": seq, "reason": "the hosted watcher disagrees with this agent's record",
	})
}

// flagWatcher raises an alert about a standing watcher whose answer did not hold
// up: the alert is about the watcher (its URL), not the contact, and holds
// nothing up. One alert is kept per watcher and sequence number however often
// the same answer is met.
func (s *Service) flagWatcher(aid string, seq int, digest string, an standingAnswer) {
	their := ""
	if an.resp != nil && an.resp.Digest != nil {
		their = *an.resp.Digest
	}
	alerts, _ := s.Store.listDuplicityAlerts(aid)
	for _, a := range alerts {
		if a.Kind == AlertKindWatcher && !a.Resolved && a.SourceURL == an.w.URL && a.SequenceNum == seq && a.TheirDigest == their {
			return
		}
	}
	_, _ = s.Store.InsertDuplicityAlert(DuplicityAlert{
		AID: aid, SequenceNum: seq, OurDigest: digest, TheirDigest: their,
		SourceURL: an.w.URL, DetectedAt: s.now().UTC(), Kind: AlertKindWatcher,
		Evidence: Evidence{Kind: "watcher", SequenceNum: seq, Watcher: an.w.URL, Why: an.proof.Reason}.json(),
	})
	s.emit("kel_watcher_flagged", map[string]interface{}{"aid": aid, "seq": seq, "watcher": an.w.URL, "why": an.proof.Reason})
}

// AnchorAlertToKEL anchors a duplicity alert SAID to the verifier KEL (D12 default-on).
// Full ixn creation is deferred to KERI driver integration; we log the intent now.
func (s *Service) AnchorAlertToKEL(alert *DuplicityAlert) error {
	if alert == nil {
		return nil
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"aid": alert.AID, "seq": alert.SequenceNum,
		"our_digest": alert.OurDigest, "their_digest": alert.TheirDigest,
		"detected_at": alert.DetectedAt.UTC().Format(time.RFC3339),
	})
	said := iacrypto.Blake3QB64Must(payload)
	log.Printf("[watcher] AnchorAlertToKEL: alert_id=%d said=%s (ixn deferred)", alert.ID, said)
	return nil
}

// Prune applies retention: keep min+max seq per AID, drop stale AIDs.
func (s *Service) Prune() error {
	// Stale TTL prune is store-wide; per-AID min/max handled on verify.
	cutoff := time.Now().UTC().Add(-defaultStaleTTL)
	n, err := s.Store.PruneStale(cutoff)
	if err != nil {
		return err
	}
	if n > 0 {
		log.Printf("[watcher] pruned %d stale first-seen rows", n)
	}
	return nil
}

func (s *Service) pruneAID(aid string, latestSeq int) error {
	rows, err := s.Store.listFirstSeen(aid)
	if err != nil || len(rows) <= 2 {
		return err
	}
	minSeq, maxSeq := rows[0].SequenceNum, rows[0].SequenceNum
	for _, r := range rows[1:] {
		if r.SequenceNum < minSeq {
			minSeq = r.SequenceNum
		}
		if r.SequenceNum > maxSeq {
			maxSeq = r.SequenceNum
		}
	}
	keep := []int{minSeq, maxSeq}
	if latestSeq != minSeq && latestSeq != maxSeq {
		keep = append(keep, latestSeq)
	}
	return s.Store.PruneIntermediate(aid, keep)
}

func (s *Service) emit(eventType string, payload map[string]interface{}) {
	if s.OnEvent != nil {
		s.OnEvent(eventType, payload)
	}
}
