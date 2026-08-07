package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"identity-agent-core/iacrypto"
)

// Service is the watcher engine (L1 self-watch + L2/L3 clients).
type Service struct {
	Store    Store
	L2       *L2Client
	L3       *L3Client
	OnEvent  func(eventType string, payload map[string]interface{})
}

func NewService(store Store) *Service {
	return &Service{
		Store: store,
		L2:    NewL2Client(),
		L3:    NewL3Client(),
	}
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
	now := time.Now().UTC()
	existing, err := s.Store.GetFirstSeen(aid, seq)
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
		SeenCount: count, SourceType: source, SourceURL: sourceURL,
	})
}

func firstSeenTime(existing *FirstSeenRecord, now time.Time) time.Time {
	if existing != nil {
		return existing.FirstSeenAt
	}
	return now
}

// DetectDuplicity compares digest against stored first-seen at same seq.
func (s *Service) DetectDuplicity(aid string, seq int, digest string) (bool, *FirstSeenRecord, error) {
	existing, err := s.Store.GetFirstSeen(aid, seq)
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
	seq := CurrentSeq(in.KEL)
	if seq < 0 {
		return &VerifyKelResult{OK: false, Reason: "empty KEL"}, nil
	}
	digest, err := KelDigestAtSeq(in.KEL, seq)
	if err != nil {
		return nil, err
	}

	result := &VerifyKelResult{
		AID: in.AID, SequenceNum: seq, Digest: digest,
		SourcesQueried: []SourceOutcome{},
	}

	existing, _ := s.Store.GetFirstSeen(in.AID, seq)
	firstContact := existing == nil
	result.FirstContact = firstContact

	var l1Outcome string
	if existing == nil {
		l1Outcome = "first_seen"
		if err := s.RecordFirstSeen(in.AID, seq, digest, in.SourceType, in.SourceURL); err != nil {
			return nil, err
		}
	} else if existing.KelDigest == digest {
		l1Outcome = "match"
		_ = s.RecordFirstSeen(in.AID, seq, digest, in.SourceType, in.SourceURL)
	} else {
		l1Outcome = "mismatch"
	}
	result.SourcesQueried = append(result.SourcesQueried, SourceOutcome{Type: "L1", Outcome: l1Outcome})

	// L2-standing query (default the commercial witness/watcher service)
	l2URL := s.DefaultL2URL()
	l2Resp, latency, l2Err := s.L2.QueryDigest(ctx, l2URL, in.AID, seq)
	l2Outcome := "unknown"
	if l2Err != nil {
		l2Outcome = "unavailable"
		s.emit("kel_l2_query_latency", map[string]interface{}{
			"url": l2URL, "error": l2Err.Error(), "latency_ms": latency.Milliseconds(),
		})
	} else {
		ms := int(latency.Milliseconds())
		if l2Resp.Digest == nil {
			l2Outcome = "unknown"
		} else if *l2Resp.Digest == digest {
			l2Outcome = "match"
		} else {
			l2Outcome = "mismatch"
		}
		result.SourcesQueried = append(result.SourcesQueried, SourceOutcome{
			Type: "L2_standing", URL: l2URL, Outcome: l2Outcome, LatencyMs: ms,
		})
	}

	// Bootstrap hints — advisory only (never block alone)
	for _, hint := range in.BootstrapL2 {
		if hint == l2URL {
			continue
		}
		resp, _, err := s.L2.QueryDigest(ctx, hint, in.AID, seq)
		outcome := "unknown"
		if err == nil && resp.Digest != nil {
			if *resp.Digest == digest {
				outcome = "match"
			} else {
				outcome = "mismatch"
			}
		}
		result.SourcesQueried = append(result.SourcesQueried, SourceOutcome{
			Type: "L2_bootstrap", URL: hint, Outcome: outcome,
		})
	}

	// Blocking: repeat L1 mismatch, or first-contact L1+L2-standing conflict (≥2 sources).
	shouldBlock := false
	blockReason := ""
	if l1Outcome == "mismatch" {
		shouldBlock = true
		blockReason = "L1 digest mismatch at same sequence"
	} else if firstContact && l2Outcome == "mismatch" {
		shouldBlock = true
		blockReason = "first-contact L1 vs L2-standing digest conflict"
	}

	if shouldBlock {
		alertID, alert, err := s.recordDuplicity(in.AID, seq, digest, l2URL, existing, l2Resp)
		if err != nil {
			return nil, err
		}
		result.Blocked = true
		result.OK = false
		result.Reason = blockReason
		result.OverallOutcome = "duplicity"
		result.DuplicityAlert = alert
		_ = alertID
		s.emit("kel_duplicity_detected", map[string]interface{}{
			"aid": in.AID, "seq": seq, "reason": blockReason,
		})
		_ = s.AnchorAlertToKEL(alert)
		return result, nil
	}

	if firstContact && l1Outcome == "first_seen" && (l2Outcome == "match" || l2Outcome == "unknown") {
		s.emit("kel_first_contact_confirmed", map[string]interface{}{"aid": in.AID, "seq": seq})
	}

	result.OK = true
	result.OverallOutcome = "confirmed"
	s.emit("kel_verification", map[string]interface{}{
		"aid": in.AID, "sequence_num": seq, "sources": result.SourcesQueried,
		"overall_outcome": result.OverallOutcome,
	})
	s.pruneAID(in.AID, seq)
	return result, nil
}

func (s *Service) recordDuplicity(aid string, seq int, ourDigest, sourceURL string, existing *FirstSeenRecord, l2 *DigestResponse) (int64, *DuplicityAlert, error) {
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
		SourceURL: sourceURL, DetectedAt: time.Now().UTC(),
	}
	id, err := s.Store.InsertDuplicityAlert(alert)
	if err != nil {
		return 0, nil, err
	}
	alert.ID = id
	return id, &alert, nil
}

// GetPublicDigest serves this agent's L1 observation for /public/kel-digest.
func (s *Service) GetPublicDigest(aid string, seq int) (*DigestResponse, error) {
	opted, err := s.Store.IsOptedOut(aid)
	if err != nil {
		return nil, err
	}
	if opted {
		return nil, fmt.Errorf("opted_out")
	}
	rec, err := s.Store.GetFirstSeen(aid, seq)
	if err != nil {
		return nil, err
	}
	resp := DigestResponse{AID: aid, SequenceNumber: seq}
	if rec == nil {
		return &resp, nil
	}
	d := rec.KelDigest
	fs := rec.FirstSeenAt.UTC().Format(time.RFC3339)
	os := rec.FirstSeenAt.UTC().Format(time.RFC3339)
	resp.Digest = &d
	resp.FirstSeenAt = &fs
	resp.ObservedSince = &os
	return &resp, nil
}

// KelCheck handles POST /public/kel-check (L3 peer cross-check).
func (s *Service) KelCheck(req KelCheckRequest) (*KelCheckResponse, error) {
	rec, err := s.Store.GetFirstSeen(req.AID, req.Seq)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return &KelCheckResponse{Match: false}, nil
	}
	match := rec.KelDigest == req.Digest
	d := rec.KelDigest
	fs := rec.FirstSeenAt.UTC().Format(time.RFC3339)
	return &KelCheckResponse{Match: match, OurDigest: &d, OurFirstSeen: &fs}, nil
}

// CrossCheck queries a peer's /public/kel-check; L3 mismatch escalates only (never blocks alone).
func (s *Service) CrossCheck(ctx context.Context, peerURL string, aid string, seq int, digest string) error {
	resp, err := s.L3.CrossCheck(ctx, peerURL, KelCheckRequest{AID: aid, Seq: seq, Digest: digest})
	if err != nil {
		return err
	}
	if !resp.Match {
		s.emit("kel_l3_escalation", map[string]interface{}{
			"aid": aid, "seq": seq, "peer": peerURL,
		})
		_, _, _ = s.L2.QueryDigest(ctx, s.DefaultL2URL(), aid, seq)
	}
	return nil
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
	rows, err := s.Store.ListFirstSeen(aid)
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