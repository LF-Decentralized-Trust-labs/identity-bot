package linkverifier

import (
	"context"
	"fmt"
	"strings"
	"time"

	"identity-agent-core/didwebs"
	"identity-agent-core/drivers"
)

// SDK is the SM7 Link Verification engine (M58).
type SDK struct {
	resolver *didwebs.Resolver
	driver   *drivers.KeriDriver
	cache    *cache
	cfg      Config
}

func New(driver *drivers.KeriDriver, cfg Config) *SDK {
	if cfg.EagerCap <= 0 {
		cfg.EagerCap = 20
	}
	return &SDK{
		resolver: didwebs.NewResolver(&didwebs.KeriDriverBackend{Driver: driver}),
		driver:   driver,
		cache:    newCache(),
		cfg:      cfg,
	}
}

// Verify is the single SM7 entry point (SEAM-15 §2.1).
func (s *SDK) Verify(ctx context.Context, req VerifyRequest) (*VerificationResult, error) {
	if req.Flow == "" {
		req.Flow = FlowLink
	}
	if req.Timing == "" {
		req.Timing = TimingLazy
	}
	if req.Tier == "" {
		req.Tier = TierFree
	}
	kind, input := normalizeInput(req.Input, req.InputKind)
	cacheKey := fmt.Sprintf("%s|%s|%s|%s", kind, input, req.Flow, req.Tier)
	if !req.ForceRefresh {
		if cached, ok := s.cache.get(cacheKey); ok {
			return &cached, nil
		}
	}

	now := time.Now().UTC().Format(time.RFC3339)
	result := &VerificationResult{
		Outcome:          OutcomeUnverified,
		VerificationPath: "none",
		LastVerified:     now,
		ContactCorrelation: nil,
		BandStyle:        "generic",
	}

	switch kind {
	case InputOOBI:
		return s.verifyOOBI(ctx, input, req, cacheKey, result)
	default:
		return s.verifyDidWebs(ctx, kind, input, req, cacheKey, result)
	}
}

func (s *SDK) verifyDidWebs(ctx context.Context, kind InputKind, input string, req VerifyRequest, cacheKey string, result *VerificationResult) (*VerificationResult, error) {
	var urls *didwebs.ArtifactURLs
	var err error
	if kind == InputDIDWebs {
		urls, err = didwebs.DeriveFromDID(input)
	} else {
		urls, err = didwebs.DeriveFromURL(input)
	}
	if err != nil {
		result.Band = bandForOutcome(result.Outcome)
		s.cache.set(cacheKey, *result)
		return result, nil
	}

	resolved, status, err := s.resolver.Resolve(ctx, urls)
	if err != nil {
		return nil, err
	}

	switch status {
	case didwebs.FetchNotFound:
		result.Outcome = OutcomeUnverified
		result.VerificationPath = "none"
	case didwebs.FetchPartial:
		result.Outcome = OutcomeUnverified
		result.VerificationPath = "none"
		result.KelReplay = "incomplete"
	case didwebs.FetchSeqMismatch:
		result.Outcome = OutcomeUnverified
		result.VerificationPath = "did_webs"
		result.KelReplay = "incomplete"
	default:
		result.VerificationPath = "did_webs"
		s.classifyResolved(resolved, result)
	}

	if result.AID != nil {
		s.applyFlowAndTier(req, result, resolved)
		s.applyContactCorrelation(result, false)
	}
	result.Band = bandForOutcome(result.Outcome)
	s.cache.set(cacheKey, *result)
	return result, nil
}

func (s *SDK) verifyOOBI(ctx context.Context, oobiURL string, req VerifyRequest, cacheKey string, result *VerificationResult) (*VerificationResult, error) {
	if s.driver == nil {
		result.Outcome = OutcomeIncomplete
		result.VerificationPath = "oobi"
		result.KelReplay = "incomplete"
		result.Band = bandForOutcome(result.Outcome)
		s.cache.set(cacheKey, *result)
		return result, nil
	}
	_ = ctx
	resp, err := s.driver.ResolveOobi(oobiURL)
	if err != nil || resp == nil || !resp.KelVerified {
		result.Outcome = OutcomeUnverified
		result.VerificationPath = "oobi"
		if resp != nil && resp.CID != "" {
			aid := resp.CID
			result.AID = &aid
		}
		result.Band = bandForOutcome(result.Outcome)
		s.cache.set(cacheKey, *result)
		return result, nil
	}
	aid := resp.CID
	result.AID = &aid
	result.Outcome = OutcomeVerified
	result.VerificationPath = "oobi"
	result.KelReplay = "ok"
	s.applyFlowAndTier(req, result, nil)
	s.applyContactCorrelation(result, false)
	result.Band = bandForOutcome(result.Outcome)
	s.cache.set(cacheKey, *result)
	return result, nil
}

func (s *SDK) classifyResolved(res *didwebs.ResolvedDID, result *VerificationResult) {
	if res == nil {
		result.Outcome = OutcomeUnverified
		return
	}
	aid := res.AID
	if aid != "" {
		result.AID = &aid
	}
	if !res.CesrComplete {
		result.Outcome = OutcomeIncomplete
		result.KelReplay = "incomplete"
		return
	}
	if res.ReplayVerified {
		result.Outcome = OutcomeVerified
		result.KelReplay = "ok"
		return
	}
	if len(res.Events) > 0 || res.DidJSON != nil {
		result.Outcome = OutcomeTampered
		result.KelReplay = "failed"
		return
	}
	result.Outcome = OutcomeUnverified
	result.KelReplay = "incomplete"
}

func (s *SDK) applyFlowAndTier(req VerifyRequest, result *VerificationResult, resolved *didwebs.ResolvedDID) {
	var alsoKnown []string
	if resolved != nil {
		alsoKnown = resAlsoKnownAs(resolved.DidJSON)
	}
	if req.Flow == FlowLink && result.VerificationPath == "did_webs" && result.AID != nil && result.Outcome == OutcomeVerified {
		result.Ownership = ownershipForAID(*result.AID, alsoKnown)
	} else if req.Flow == FlowLink && result.VerificationPath == "oobi" {
		result.Ownership = nil
	}
	if req.Tier == TierGated && s.cfg.GrapeScoreProviderActive {
		score := 75 // BLOCKED: wire to AuthProvider GET /api/auth/score (SEAM-11 LV-7)
		asOf := time.Now().UTC().Format(time.RFC3339)
		badge := "grape_branded"
		result.GrapeScore = &score
		result.GrapeScoreAsOf = &asOf
		result.Badge = &badge
	} else {
		result.BandStyle = "generic"
	}
	// LV-6: silent degrade when gated requested but not entitled — omit score fields
}

func (s *SDK) applyContactCorrelation(result *VerificationResult, populate bool) {
	if !populate || s.cfg.ContactLookup == nil || result.AID == nil {
		return
	}
	known, _ := s.cfg.ContactLookup(*result.AID)
	if known {
		v := "known"
		result.ContactCorrelation = &v
	} else {
		v := "stranger"
		result.ContactCorrelation = &v
	}
}

// VerifyWithContacts is the IA loopback path (SEAM-15 §2.6) — populates contact_correlation.
func (s *SDK) VerifyWithContacts(ctx context.Context, req VerifyRequest) (*VerificationResult, error) {
	res, err := s.Verify(ctx, req)
	if err != nil || res == nil {
		return res, err
	}
	s.applyContactCorrelation(res, true)
	return res, nil
}

func normalizeInput(input string, kind InputKind) (InputKind, string) {
	input = strings.TrimSpace(input)
	if kind != "" {
		return kind, input
	}
	if strings.HasPrefix(input, "did:webs:") {
		return InputDIDWebs, input
	}
	if strings.Contains(input, "/oobi/") {
		return InputOOBI, input
	}
	return InputURL, input
}

func ownershipForAID(aid string, alsoKnownAs []string) *Ownership {
	if len(alsoKnownAs) > 0 && alsoKnownAs[0] != "" {
		return &Ownership{RegisteredTo: alsoKnownAs[0], Disclosure: "disclosed"}
	}
	prefix := aid
	if len(prefix) > 15 {
		prefix = prefix[:12] + "…"
	}
	return &Ownership{RegisteredTo: prefix, Disclosure: "undisclosed_verified"}
}

func resAlsoKnownAs(doc map[string]interface{}) []string {
	if doc == nil {
		return nil
	}
	raw, ok := doc["alsoKnownAs"].([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func bandForOutcome(o Outcome) string {
	switch o {
	case OutcomeVerified:
		return "green"
	case OutcomeTampered:
		return "red"
	case OutcomeIncomplete:
		return "amber"
	default:
		return "gray"
	}
}

// BandNeutral returns the display band for unverified (neutral gray — SCR1 uses outcome not band).
func BandNeutral() string { return "gray" }