package server

import (
	"encoding/json"
	"net/http"
)

// EnclaveStatusResponse describes the hardware security backing available on this device.
type EnclaveStatusResponse struct {
	HardwareBacked bool    `json:"hardwareBacked"`
	BackingType    string  `json:"backingType"`    // "tpm2", "secure_enclave", "dpapi", "keychain_software", "software"
	BackingLabel   string  `json:"backingLabel"`   // Human-readable, e.g. "Apple Secure Enclave"
	TpmPresent     *bool   `json:"tpmPresent"`     // Windows/Linux only: TPM chip detected
	TpmEnabled     *bool   `json:"tpmEnabled"`     // Windows/Linux only: TPM accessible to OS
	Genuineness    *GenuinenessInfo `json:"genuineness,omitempty"` // code-plane attestation stub (SEAM-20 §5.3)
}

// GenuinenessInfo reports running-binary attestation against the signed manifest.
type GenuinenessInfo struct {
	Status           string `json:"status"`
	RunningSHA256    string `json:"running_sha256,omitempty"`
	ExpectedSHA256   string `json:"expected_sha256,omitempty"`
	InstalledVersion string `json:"installed_version,omitempty"`
	Message          string `json:"message,omitempty"`
}

// detectEnclave is implemented per-platform in enclave_windows.go / enclave_linux.go / enclave_darwin.go

func (s *CoreServer) handleSecurityEnclave(w http.ResponseWriter, r *http.Request) {
	result := detectEnclave()
	if s.UpdateService != nil {
		g := s.UpdateService.Genuineness()
		result.Genuineness = &GenuinenessInfo{
			Status:           g.Status,
			RunningSHA256:    g.RunningSHA256,
			ExpectedSHA256:   g.ExpectedSHA256,
			InstalledVersion: g.InstalledVersion,
			Message:          g.Message,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
