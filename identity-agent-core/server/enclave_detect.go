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
}

// detectEnclave is implemented per-platform in enclave_windows.go / enclave_linux.go / enclave_darwin.go

func (s *CoreServer) handleSecurityEnclave(w http.ResponseWriter, r *http.Request) {
	result := detectEnclave()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
