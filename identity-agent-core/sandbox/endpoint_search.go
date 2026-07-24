package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
)

// The search/describe meta-tools keep a caller's context cost constant as the
// capability catalog grows: search returns ranked summaries (never full schemas),
// describe serves one capability's full record on demand. Both are filtered to the
// caller's entitlements through the same Authorizer that governs execute, so the
// discovery surface never reveals more than the caller could invoke.

// SearchQuery is the search meta-tool's input.
type SearchQuery struct {
	Query        string `json:"query,omitempty"`
	Domain       string `json:"domain,omitempty"`
	ExecutorType string `json:"executor_type,omitempty"`
	Limit        int    `json:"limit,omitempty"`
}

const (
	searchDefaultLimit = 20
	searchMaxLimit     = 50
)

// CapabilitySummary is one context-cheap search result. Full schemas are served
// only by describe.
type CapabilitySummary struct {
	CapabilityID string `json:"capability_id"`
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	Domain       string `json:"domain,omitempty"`
	ExecutorType string `json:"executor_type"`
	Impact       string `json:"impact,omitempty"`
}

// CapabilityDetail is the describe meta-tool's output — the only place a full
// input schema and auth requirements are served.
type CapabilityDetail struct {
	CapabilityID       string          `json:"capability_id"`
	SAID               string          `json:"said,omitempty"`
	Name               string          `json:"name"`
	Description        string          `json:"description,omitempty"`
	Domain             string          `json:"domain,omitempty"`
	ExecutorType       string          `json:"executor_type"`
	Impact             string          `json:"impact,omitempty"`
	InputSchema        json.RawMessage `json:"input_schema,omitempty"`
	RequestContract    string          `json:"request_contract,omitempty"`
	Docs               string          `json:"docs,omitempty"`
	RequiredCredSchema string          `json:"required_cred_schema,omitempty"`
	RequiredCredIssuer string          `json:"required_cred_issuer,omitempty"`
	HostControl        bool            `json:"host_control,omitempty"`
	Provider           string          `json:"provider,omitempty"`
	Invocation         string          `json:"invocation"`
}

// searchCandidate pairs a summary with what the entitlement check and ranking need.
type searchCandidate struct {
	summary CapabilitySummary
	capDef  ProvidedCapability
	score   int
}

// SearchCapabilities is the search meta-tool: deterministic text+filter ranking over
// the full catalog (registry-native records + plug-in capabilities), filtered to what
// the caller is entitled to invoke. The retrieval strategy is hidden behind this
// contract, so a smarter ranking can replace it without a contract change.
func (m *Manager) SearchCapabilities(ctx context.Context, caller CallerContext, q SearchQuery) []CapabilitySummary {
	limit := q.Limit
	if limit <= 0 {
		limit = searchDefaultLimit
	}
	if limit > searchMaxLimit {
		limit = searchMaxLimit
	}

	candidates := m.catalogCandidates()
	auth := m.authz()
	needle := strings.ToLower(strings.TrimSpace(q.Query))

	matched := make([]searchCandidate, 0, len(candidates))
	for _, c := range candidates {
		if q.Domain != "" && c.summary.Domain != q.Domain {
			continue
		}
		if q.ExecutorType != "" && c.summary.ExecutorType != q.ExecutorType {
			continue
		}
		c.score = scoreMatch(needle, c.summary)
		if c.score == 0 {
			continue
		}
		// Entitlement filter: never surface what the caller could not invoke.
		if err := auth.AuthorizeIngress(ctx, caller, c.capDef); err != nil {
			continue
		}
		matched = append(matched, c)
	}

	sort.Slice(matched, func(i, j int) bool {
		if matched[i].score != matched[j].score {
			return matched[i].score > matched[j].score
		}
		return matched[i].summary.CapabilityID < matched[j].summary.CapabilityID
	})
	if len(matched) > limit {
		matched = matched[:limit]
	}
	out := make([]CapabilitySummary, len(matched))
	for i, c := range matched {
		out[i] = c.summary
	}
	return out
}

// DescribeCapability is the describe meta-tool: the full record for one capability,
// gated by the same entitlement check as execute. Not-found and not-entitled are
// deliberately the same answer, so the catalog is not enumerable past a caller's
// entitlements.
func (m *Manager) DescribeCapability(ctx context.Context, caller CallerContext, capabilityID string) (*CapabilityDetail, error) {
	auth := m.authz()

	if provider, capDef, ok := m.findProvider(capabilityID); ok {
		if err := auth.AuthorizeIngress(ctx, caller, capDef); err != nil {
			return nil, ErrCapabilityNotFound
		}
		return &CapabilityDetail{
			CapabilityID:       capDef.ID,
			Name:               capDef.Name,
			Description:        capDef.Description,
			ExecutorType:       "plugin",
			RequestContract:    capDef.RequestContract,
			Docs:               capDef.Docs,
			RequiredCredSchema: capDef.ACDCScope,
			HostControl:        capDef.HostControl,
			Provider:           provider.ID,
			Invocation:         invocationHint(capDef.ID),
		}, nil
	}

	rec := m.registryRecord(capabilityID)
	if rec == nil {
		return nil, ErrCapabilityNotFound
	}
	if err := auth.AuthorizeIngress(ctx, caller, rec.asProvidedCapability()); err != nil {
		return nil, ErrCapabilityNotFound
	}
	return &CapabilityDetail{
		CapabilityID:       rec.ID,
		SAID:               rec.SAID,
		Name:               rec.Name,
		Description:        rec.Description,
		Domain:             rec.Domain,
		ExecutorType:       rec.ExecutorType,
		Impact:             rec.Impact,
		InputSchema:        rec.InputSchema,
		RequiredCredSchema: rec.RequiredCredSchema,
		RequiredCredIssuer: rec.RequiredCredIssuer,
		HostControl:        rec.ExecutorType == "host_control",
		Provider:           rec.Provider,
		Invocation:         invocationHint(rec.ID),
	}, nil
}

func invocationHint(id string) string {
	return fmt.Sprintf("execute {\"capability_id\": %q, \"args\": {...}}", id)
}

// catalogCandidates lists every capability the agent offers, in summary form.
func (m *Manager) catalogCandidates() []searchCandidate {
	var out []searchCandidate

	m.mu.RLock()
	for _, manifest := range m.manifests {
		for _, p := range manifest.Provides {
			out = append(out, searchCandidate{
				summary: CapabilitySummary{
					CapabilityID: p.ID,
					Name:         p.Name,
					Description:  p.Description,
					ExecutorType: "plugin",
				},
				capDef: p,
			})
		}
	}
	m.mu.RUnlock()

	if m.store != nil {
		recs, err := m.store.ListCapabilityRecords()
		if err != nil {
			log.Printf("[registry] list for search: %v", err)
		}
		for _, r := range recs {
			out = append(out, searchCandidate{
				summary: CapabilitySummary{
					CapabilityID: r.ID,
					Name:         r.Name,
					Description:  r.Description,
					Domain:       r.Domain,
					ExecutorType: r.ExecutorType,
					Impact:       r.Impact,
				},
				capDef: r.asProvidedCapability(),
			})
		}
	}
	return out
}

// scoreMatch ranks deterministically: exact id > id/name prefix > id/name substring >
// description substring. An empty query matches everything at the lowest rank (pure
// filter browsing).
func scoreMatch(needle string, s CapabilitySummary) int {
	if needle == "" {
		return 1
	}
	id := strings.ToLower(s.CapabilityID)
	name := strings.ToLower(s.Name)
	switch {
	case id == needle:
		return 5
	case strings.HasPrefix(id, needle) || strings.HasPrefix(name, needle):
		return 4
	case strings.Contains(id, needle) || strings.Contains(name, needle):
		return 3
	case strings.Contains(strings.ToLower(s.Description), needle):
		return 2
	}
	return 0
}
