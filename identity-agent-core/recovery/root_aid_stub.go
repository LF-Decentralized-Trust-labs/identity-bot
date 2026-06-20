package recovery

import "fmt"

// RootAIDRotationRequest is the break-glass root-AID rotation payload.
type RootAIDRotationRequest struct {
	RecoverySessionID string `json:"recovery_session_id"`
	NewRootPublicKey    string `json:"new_root_public_key"`
	WitnessThreshold    int    `json:"witness_threshold,omitempty"`
}

// RootAIDRotationResult would contain the new root KEL event after rotation.
type RootAIDRotationResult struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// RotateRootAID is a stub for break-glass root-AID rotation after recovery.
//
// TODO: Implement full root-AID rotation once KERI break-glass witness multisig
// semantics are finalized (depends on KERI research for delegated recovery rotation).
// Until then, recovery completes with mandatory signing-key rotation only.
func RotateRootAID(_ RootAIDRotationRequest) (*RootAIDRotationResult, error) {
	return nil, fmt.Errorf("root-AID rotation not implemented: break-glass KERI rotation pending research")
}

// RootAIDRotationAvailable reports whether break-glass root rotation is supported.
func RootAIDRotationAvailable() bool {
	return false
}