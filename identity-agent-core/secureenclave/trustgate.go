package secureenclave

import (
	"fmt"

	"identity-agent-core/update"
)

// TrustGate combines genuineness (hard gate) and freshness (hard gate).
// Currency is warn-only via CurrencyWarning().
type TrustGate struct {
	runner      *Runner
	attestation *update.Attestation
}

func NewTrustGate(runner *Runner, attestation *update.Attestation) *TrustGate {
	return &TrustGate{runner: runner, attestation: attestation}
}

// AllowsTrustOperations reports whether peer-trust operations may proceed.
func (tg *TrustGate) AllowsTrustOperations() bool {
	return tg.TrustBlockedReason() == ""
}

// TrustBlockedReason returns a non-empty reason when trust operations must be blocked.
func (tg *TrustGate) TrustBlockedReason() string {
	if tg.attestation != nil {
		g := tg.attestation.Genuineness()
		if g.Status == "mismatch" {
			if g.Message != "" {
				return fmt.Sprintf("code-plane genuineness mismatch: %s", g.Message)
			}
			return "code-plane genuineness mismatch"
		}
		// Hard-gate only when a signed manifest publishes an expected blake3_256.
		if g.ExpectedBlake3_256 != "" && g.Status != "verified" {
			if g.Message != "" {
				return fmt.Sprintf("code-plane genuineness %s: %s", g.Status, g.Message)
			}
			return fmt.Sprintf("code-plane genuineness %s", g.Status)
		}
	}
	if tg.runner != nil {
		enc := tg.runner.Genuineness()
		if enc.Status == "mismatch" || enc.Status == "failed" {
			if enc.Message != "" {
				return fmt.Sprintf("enclave genuineness %s: %s", enc.Status, enc.Message)
			}
			return fmt.Sprintf("enclave genuineness %s", enc.Status)
		}
		f := tg.runner.Freshness()
		if f.Status == "stale" || f.Status == "failed" {
			if f.Message != "" {
				return fmt.Sprintf("attestation freshness %s: %s", f.Status, f.Message)
			}
			return fmt.Sprintf("attestation freshness %s", f.Status)
		}
	}
	return ""
}

// CurrencyWarning returns a non-empty warning when versions are behind manifest.
func (tg *TrustGate) CurrencyWarning() string {
	if tg.attestation == nil {
		return ""
	}
	c := tg.attestation.Currency()
	if c.Status == "outdated" {
		if c.Message != "" {
			return c.Message
		}
		return fmt.Sprintf("installed %s behind manifest %s", c.InstalledVersion, c.LatestVersion)
	}
	return ""
}

// State exposes the combined trust axes for APIs.
type State struct {
	CodeGenuineness    update.GenuinenessAxis `json:"code_genuineness"`
	EnclaveGenuineness EnclaveGenuinenessAxis `json:"enclave_genuineness"`
	Freshness          FreshnessAxis          `json:"freshness"`
	Currency           update.CurrencyAxis    `json:"currency"`
	TrustAllowed       bool                   `json:"trust_allowed"`
	TrustBlockedReason string                 `json:"trust_blocked_reason,omitempty"`
	CurrencyWarning    string                 `json:"currency_warning,omitempty"`
}

func (tg *TrustGate) State() State {
	st := State{
		TrustAllowed:    tg.AllowsTrustOperations(),
		TrustBlockedReason: tg.TrustBlockedReason(),
		CurrencyWarning: tg.CurrencyWarning(),
	}
	if tg.attestation != nil {
		st.CodeGenuineness = tg.attestation.Genuineness()
		st.Currency = tg.attestation.Currency()
	}
	if tg.runner != nil {
		st.EnclaveGenuineness = tg.runner.Genuineness()
		st.Freshness = tg.runner.Freshness()
	}
	return st
}