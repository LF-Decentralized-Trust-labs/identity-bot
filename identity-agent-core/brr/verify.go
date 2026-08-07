package brr

import "fmt"

// RevocationStatus is one of four verifier outcomes (revocation registry design §2.1).
type RevocationStatus string

const (
	StatusValid       RevocationStatus = "valid"
	StatusRevoked     RevocationStatus = "revoked"
	StatusUnknown     RevocationStatus = "unknown"
	StatusCheckFailed RevocationStatus = "check_failed"
)

// VerifyInput holds credential presentation metadata for a BRR check.
type VerifyInput struct {
	CredentialSAID string
	RegistrySalt   string
	RegistryPrefix string
	BRRBaseURL     string
}

// VerifyLocally finalizes revocation from a bulk proof without contacting the issuer.
func VerifyLocally(input VerifyInput, proof BulkProof) (RevocationStatus, error) {
	if input.RegistryPrefix == "" || input.BRRBaseURL == "" {
		return StatusUnknown, nil
	}
	if proof.RegistryPrefix != "" && proof.RegistryPrefix != input.RegistryPrefix {
		return StatusCheckFailed, fmt.Errorf("registry prefix mismatch")
	}
	// BLOCKED: full sparse-merkle multiproof composition — local membership in signed bulk subtree.
	if proof.MerkleRoot == "" || proof.SubtreeRoot == "" {
		return StatusCheckFailed, fmt.Errorf("incomplete bulk proof")
	}
	blinded := BlindedID(input.CredentialSAID, input.RegistrySalt)
	if isRevoked(blinded, proof.RevokedIDs) {
		return StatusRevoked, nil
	}
	return StatusValid, nil
}

// CheckRevocation runs the full verifier path: bulk proof fetch + local finalize.
func CheckRevocation(client *Client, input VerifyInput) (RevocationStatus, error) {
	if input.BRRBaseURL == "" || input.RegistryPrefix == "" {
		return StatusUnknown, nil
	}
	blinded := BlindedID(input.CredentialSAID, input.RegistrySalt)
	proof, err := client.FetchBulkProof(input.RegistryPrefix, blinded)
	if err != nil {
		return StatusCheckFailed, err
	}
	return VerifyLocally(input, proof)
}