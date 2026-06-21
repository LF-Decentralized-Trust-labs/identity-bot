package server

import (
	"encoding/json"
	"net/http"

	"identity-agent-core/secureenclave"
	"identity-agent-core/update"
)

// EnclaveStatusResponse describes the hardware security backing available on this device.
type EnclaveStatusResponse struct {
	HardwareBacked bool    `json:"hardwareBacked"`
	BackingType    string  `json:"backingType"`    // "tpm2", "secure_enclave", "dpapi", "keychain_software", "software"
	BackingLabel   string  `json:"backingLabel"`   // Human-readable, e.g. "Apple Secure Enclave"
	TpmPresent     *bool   `json:"tpmPresent"`     // Windows/Linux only: TPM chip detected
	TpmEnabled     *bool   `json:"tpmEnabled"`     // Windows/Linux only: TPM accessible to OS
	Genuineness    *GenuinenessInfo `json:"genuineness,omitempty"`
	Freshness      *FreshnessInfo   `json:"freshness,omitempty"`
	Currency       *CurrencyInfo    `json:"currency,omitempty"`
	TrustAllowed   *bool            `json:"trustAllowed,omitempty"`
}

// GenuinenessInfo reports running-binary attestation against the signed manifest.
// Trust gates on blake3_256; sha256 fields are interop-only.
type GenuinenessInfo struct {
	Status             string `json:"status"`
	RunningBlake3_256  string `json:"running_blake3_256,omitempty"`
	ExpectedBlake3_256 string `json:"expected_blake3_256,omitempty"`
	RunningSHA256      string `json:"running_sha256,omitempty"`
	ExpectedSHA256     string `json:"expected_sha256,omitempty"`
	InstalledVersion   string `json:"installed_version,omitempty"`
	ChainHash          string `json:"chain_hash,omitempty"`
	SignedChainHash    string `json:"signed_chain_hash,omitempty"`
	Message            string `json:"message,omitempty"`
}

// FreshnessInfo reports secure-enclave self-attestation cadence state.
type FreshnessInfo struct {
	Status         string `json:"status"`
	LastAttestedAt string `json:"last_attested_at,omitempty"`
	NextDueAt      string `json:"next_due_at,omitempty"`
	CadenceHours   int    `json:"cadence_hours,omitempty"`
	Message        string `json:"message,omitempty"`
}

// CurrencyInfo reports version currency (warn-only).
type CurrencyInfo struct {
	Status           string `json:"status"`
	InstalledVersion string `json:"installed_version,omitempty"`
	LatestVersion    string `json:"latest_version,omitempty"`
	Message          string `json:"message,omitempty"`
}

// detectEnclave is implemented per-platform in enclave_windows.go / enclave_linux.go / enclave_darwin.go

func (s *CoreServer) handleSecurityEnclave(w http.ResponseWriter, r *http.Request) {
	result := detectEnclave()
	if s.AttestationRunner != nil {
		if signer := s.AttestationRunner.Signer(); signer != nil {
			result.HardwareBacked = signer.Available() && signer.Platform() != "software"
			result.BackingType = signer.Platform()
			result.BackingLabel = signer.Label()
		}
	}
	if s.TrustGate != nil {
		st := s.TrustGate.State()
		allowed := st.TrustAllowed
		result.TrustAllowed = &allowed
		result.Genuineness = genuinenessFromState(st)
		result.Freshness = freshnessFromState(st.Freshness)
		result.Currency = currencyFromState(st.Currency)
	} else if s.UpdateService != nil {
		g := s.UpdateService.Genuineness()
		result.Genuineness = &GenuinenessInfo{
			Status:             g.Status,
			RunningBlake3_256:  g.RunningBlake3_256,
			ExpectedBlake3_256: g.ExpectedBlake3_256,
			RunningSHA256:      g.RunningSHA256,
			ExpectedSHA256:     g.ExpectedSHA256,
			InstalledVersion:   g.InstalledVersion,
			Message:            g.Message,
		}
		c := s.UpdateService.Currency()
		result.Currency = &CurrencyInfo{
			Status:           c.Status,
			InstalledVersion: c.InstalledVersion,
			LatestVersion:    c.LatestVersion,
			Message:          c.Message,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func genuinenessFromState(st secureenclave.State) *GenuinenessInfo {
	g := st.CodeGenuineness
	info := &GenuinenessInfo{
		Status:             g.Status,
		RunningBlake3_256:  g.RunningBlake3_256,
		ExpectedBlake3_256: g.ExpectedBlake3_256,
		RunningSHA256:      g.RunningSHA256,
		ExpectedSHA256:     g.ExpectedSHA256,
		InstalledVersion:   g.InstalledVersion,
		Message:            g.Message,
	}
	if st.EnclaveGenuineness.Status != "" {
		if info.Message != "" && st.EnclaveGenuineness.Message != "" {
			info.Message = info.Message + "; " + st.EnclaveGenuineness.Message
		} else if st.EnclaveGenuineness.Message != "" {
			info.Message = st.EnclaveGenuineness.Message
		}
		info.ChainHash = st.EnclaveGenuineness.ChainHash
		info.SignedChainHash = st.EnclaveGenuineness.SignedChain
		if st.EnclaveGenuineness.Status != "verified" {
			info.Status = st.EnclaveGenuineness.Status
		}
	}
	return info
}

func freshnessFromState(f secureenclave.FreshnessAxis) *FreshnessInfo {
	return &FreshnessInfo{
		Status:         f.Status,
		LastAttestedAt: f.LastAttestedAt,
		NextDueAt:      f.NextDueAt,
		CadenceHours:   f.CadenceHours,
		Message:        f.Message,
	}
}

func currencyFromState(c update.CurrencyAxis) *CurrencyInfo {
	return &CurrencyInfo{
		Status:           c.Status,
		InstalledVersion: c.InstalledVersion,
		LatestVersion:    c.LatestVersion,
		Message:          c.Message,
	}
}