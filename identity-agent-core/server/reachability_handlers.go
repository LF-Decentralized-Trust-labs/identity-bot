package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

	"identity-agent-core/relay"
)

// The owner's view of the relay, and what the owner may ask of it (ADR-048):
// how this Identity Agent is reached right now, why not if it is not, its
// public name, and its own domains. Every route here is owner-only, which is
// the router's default.

// relayAddress is one address, as the owner sees it. A private address's
// secret never leaves the Identity Agent.
type relayAddress struct {
	URL   string `json:"url"`
	Kind  string `json:"kind"`
	Label string `json:"label"`
}

// relayStatusView is what the settings screen shows.
type relayStatusView struct {
	// Mode is the ingress mode in force: relay (private), public, tunnel or
	// direct.
	Mode string `json:"mode"`
	// State is off when the mode uses no relay or none is configured, and
	// otherwise connecting, active or failed.
	State      string         `json:"state"`
	Operator   string         `json:"operator,omitempty"`
	URL        string         `json:"url,omitempty"`
	Addresses  []relayAddress `json:"addresses"`
	Reason     string         `json:"reason,omitempty"`
	ReasonCode string         `json:"reason_code,omitempty"`
}

func (s *CoreServer) currentRelay() *relay.Manager {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.RelayManager
}

// relayKindFor is the relay the ingress mode calls for, if any.
func relayKindFor(mode IngressMode) (relayKind, bool) {
	switch mode {
	case IngressModeRelay:
		return privateRelay, true
	case IngressModePublic:
		return publicRelay, true
	}
	return relayKind{}, false
}

func (s *CoreServer) relayStatus() relayStatusView {
	mode := s.resolveIngressMode()
	v := relayStatusView{Mode: string(mode), State: "off", Addresses: []relayAddress{}}
	kind, uses := relayKindFor(mode)
	if !uses {
		v.Reason = "This mode does not use a relay."
		return v
	}
	v.Operator = s.relayOperator(kind)
	if v.Operator == "" {
		v.Reason, v.ReasonCode = "No relay is configured for this mode.", "no_relay"
		return v
	}
	s.mu.Lock()
	rm, failed := s.RelayManager, s.relayFailure
	s.mu.Unlock()
	if rm == nil {
		v.State = string(relay.StateConnecting)
		if failed != nil {
			v.State, v.Reason, v.ReasonCode = string(relay.StateFailed), failed.reason, failed.code
		}
		return v
	}
	st := rm.GetStatus()
	v.State, v.URL, v.Reason, v.ReasonCode = string(st.State), rm.URL(), st.Reason, st.ReasonCode
	for _, a := range rm.Allocations() {
		v.Addresses = append(v.Addresses, relayAddress{URL: a.URL, Kind: string(a.Kind), Label: a.Label})
	}
	return v
}

// relayStatusSettled is the relay's status once it has come up or failed, or
// as it stands after a short wait: enough for a screen that has just saved a
// change to say what came of it.
func (s *CoreServer) relayStatusSettled(ctx context.Context) relayStatusView {
	deadline := time.Now().Add(relaySettleWait)
	for {
		v := s.relayStatus()
		if v.State != string(relay.StateConnecting) || time.Now().After(deadline) {
			return v
		}
		select {
		case <-ctx.Done():
			return v
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// relaySettleWait bounds how long saving reachability waits to report what
// came of it.
var relaySettleWait = 10 * time.Second

// applyReachability brings the relay up again under the settings just saved:
// the old one is stopped and a new one started in the mode, at the relay and
// with the name now configured. A development tunnel is restarted only when
// the mode moved to or from tunnel.
func (s *CoreServer) applyReachability(previous IngressMode) {
	s.mu.Lock()
	running := s.running
	s.mu.Unlock()
	ctx, gen := s.nextRelayGeneration()
	if !running {
		return
	}
	now := s.resolveIngressMode()
	if s.TunnelManager != nil && (previous == IngressModeTunnel) != (now == IngressModeTunnel) {
		if err := s.TunnelManager.Restart(s.AppCtx, s.loadTunnelConfig()); err != nil {
			log.Printf("[tunnel] restart after a reachability change: %v", err)
		}
	}
	go s.runRelay(ctx, gen)
}

// handleRelayStatus reports how this Identity Agent is reached through its
// relay right now, and why not when it is not.
func (s *CoreServer) handleRelayStatus(w http.ResponseWriter, r *http.Request) {
	writeJSONStatus(w, http.StatusOK, s.relayStatus())
}

// handleReleaseRelayName gives up the public name. It is forgotten in
// settings too, so it is not claimed again on the next start.
func (s *CoreServer) handleReleaseRelayName(w http.ResponseWriter, r *http.Request) {
	rm := s.currentRelay()
	if rm == nil || rm.Config().Mode != relayproto.ModePublic {
		writeError(w, http.StatusConflict, "No public relay is connected", "")
		return
	}
	var name string
	for _, a := range rm.Allocations() {
		if a.Kind == relay.KindName {
			name = a.Label
		}
	}
	if name == "" {
		writeError(w, http.StatusNotFound, "This Identity Agent holds no public name", "")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := rm.Release(ctx, name); err != nil {
		writeError(w, http.StatusBadGateway, "The relay did not release the name", relayRefusal(err))
		return
	}
	if settings, err := s.DataStore.GetSettings(); err == nil && settings != nil && settings.PublicRelayName == name {
		settings.PublicRelayName = ""
		if err := s.DataStore.SaveSettings(*settings); err != nil {
			log.Printf("[relay] released %s but could not forget it in settings, so it will be claimed again on the next start: %v", name, err)
		}
	}
	writeJSONStatus(w, http.StatusOK, map[string]interface{}{"released": name, "relay": s.relayStatus()})
}

// releasePublicNameHeld releases name at the connected public relay, if this
// Identity Agent holds it there.
func (s *CoreServer) releasePublicNameHeld(ctx context.Context, name string) {
	rm := s.currentRelay()
	if rm == nil || rm.Config().Mode != relayproto.ModePublic || rm.Lookup(name) == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := rm.Release(ctx, name); err != nil {
		log.Printf("[relay] could not release the public name %s, which the relay still holds for this Identity Agent: %v", name, err)
	}
}

// relayDomainView is one custom domain and where it stands.
type relayDomainView struct {
	Domain   string `json:"domain"`
	State    string `json:"state"` // waiting_for_dns or active
	TXTName  string `json:"txt_name,omitempty"`
	TXTValue string `json:"txt_value,omitempty"`
	URL      string `json:"url,omitempty"`
}

func (s *CoreServer) publicRelayRecord() (*storedRelayEnrollment, bool) {
	s.relayRecordMu.Lock()
	defer s.relayRecordMu.Unlock()
	rec, found, err := loadRelayEnrollment(s.DataDir, publicRelay.record)
	return rec, err == nil && found
}

// updateRelayRecord changes kind's enrolment record under the lock every
// change of it takes, so two changes cannot lose each other.
func (s *CoreServer) updateRelayRecord(kind relayKind, change func(*storedRelayEnrollment)) error {
	s.relayRecordMu.Lock()
	defer s.relayRecordMu.Unlock()
	rec, found, err := loadRelayEnrollment(s.DataDir, kind.record)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("this Identity Agent has no enrolment with that relay")
	}
	change(rec)
	return saveRelayEnrollment(s.DataDir, kind.record, *rec)
}

// withoutDomain is pending with domain's entry removed.
func withoutDomain(pending []relay.DomainProof, domain string) []relay.DomainProof {
	out := make([]relay.DomainProof, 0, len(pending))
	for _, p := range pending {
		if p.Domain != domain {
			out = append(out, p)
		}
	}
	return out
}

// handleListRelayDomains lists the custom domains asked for and where each
// stands.
func (s *CoreServer) handleListRelayDomains(w http.ResponseWriter, r *http.Request) {
	out := []relayDomainView{}
	active := map[string]bool{}
	if rm := s.currentRelay(); rm != nil {
		for _, a := range rm.Allocations() {
			if a.Kind == relay.KindDomain {
				active[a.Label] = true
				out = append(out, relayDomainView{Domain: a.Label, State: "active", URL: a.URL})
			}
		}
	}
	if rec, ok := s.publicRelayRecord(); ok {
		for _, p := range rec.PendingDomains {
			if !active[p.Domain] {
				out = append(out, relayDomainView{Domain: p.Domain, State: "waiting_for_dns", TXTName: p.Name, TXTValue: p.Value})
			}
		}
	}
	writeJSONStatus(w, http.StatusOK, map[string]interface{}{"domains": out})
}

func (s *CoreServer) publicRelayForDomains(w http.ResponseWriter, r *http.Request) (*relay.Manager, string, bool) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Domain) == "" {
		writeError(w, http.StatusBadRequest, "Name the domain", "")
		return nil, "", false
	}
	rm := s.currentRelay()
	if rm == nil || rm.Config().Mode != relayproto.ModePublic {
		writeError(w, http.StatusConflict, "A custom domain is served by a connected public relay", "")
		return nil, "", false
	}
	return rm, strings.ToLower(strings.TrimSpace(req.Domain)), true
}

// handleRequestRelayDomain asks the public relay to serve the identity's own
// domain, and returns the exact DNS record that proves it.
func (s *CoreServer) handleRequestRelayDomain(w http.ResponseWriter, r *http.Request) {
	rm, domain, ok := s.publicRelayForDomains(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	proof, err := rm.RequestDomain(ctx, domain)
	if err != nil {
		writeError(w, http.StatusBadGateway, "The relay did not accept the domain", relayRefusal(err))
		return
	}
	if err := s.updateRelayRecord(publicRelay, func(rec *storedRelayEnrollment) {
		rec.PendingDomains = append(withoutDomain(rec.PendingDomains, proof.Domain), *proof)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "The domain was asked for, and could not be remembered", err.Error())
		return
	}
	writeJSONStatus(w, http.StatusOK, relayDomainView{Domain: proof.Domain, State: "waiting_for_dns",
		TXTName: proof.Name, TXTValue: proof.Value})
}

// handleVerifyRelayDomain asks the relay to check the DNS record, and once it
// holds, the domain is one of this Identity Agent's addresses.
func (s *CoreServer) handleVerifyRelayDomain(w http.ResponseWriter, r *http.Request) {
	rm, domain, ok := s.publicRelayForDomains(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	a, err := rm.VerifyDomain(ctx, domain)
	if err != nil {
		writeError(w, http.StatusConflict, "The domain is not proved yet", relayRefusal(err))
		return
	}
	if err := s.updateRelayRecord(publicRelay, func(rec *storedRelayEnrollment) {
		rec.PendingDomains = withoutDomain(rec.PendingDomains, domain)
	}); err != nil {
		log.Printf("[relay] %s is proved and served, and could not be marked so in the record: %v", domain, err)
	}
	writeJSONStatus(w, http.StatusOK, relayDomainView{Domain: a.Label, State: "active", URL: a.URL})
}

// relayRefusal is what the relay said, in its own words where it gave some.
func relayRefusal(err error) string {
	var refused *relay.RefusedError
	if errors.As(err, &refused) && refused.Message != "" {
		return refused.Message
	}
	return err.Error()
}
