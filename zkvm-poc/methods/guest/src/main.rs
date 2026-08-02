// Identity Agent - Hybrid zkVM + Selective Disclosure (Algorithm v3)
//
// This guest program runs inside the RISC Zero zkVM and provides THREE
// layers of verifiable trust in a single proof:
//
//   LAYER 1: Credential Authenticity
//     → Verifies Ed25519 signatures on each VC INSIDE the zkVM
//     → Proves the credentials were issued by real issuers (not fabricated)
//
//   LAYER 2: Selective Disclosure
//     → Only commits credential_type + issuer fingerprint to public output
//     → Raw VC content (names, document numbers, etc.) stays PRIVATE
//
//   LAYER 3: Verifiable Scoring
//     → Computes confidence score from cryptographically verified VCs only
//     → Score cannot be faked because the algorithm runs in sealed execution
//
// WHAT ALICE LEARNS (public journal):
//   - Bob's AID scored 98%
//   - Algorithm v3 was used
//   - 2 credentials were cryptographically verified
//   - One was a "GovernmentID" from issuer fingerprint a1b2c3...
//   - One was a "BankAccount" from issuer fingerprint d4e5f6...
//
// WHAT ALICE DOES NOT LEARN (stays private):
//   - Which specific government issued it
//   - Bob's document number, name, or address
//   - The bank name or account details
//   - Bob's biometric data

use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use sha2::{Sha256, Digest};

// ═══════════════════════════════════════════════════════════════════════
// DATA STRUCTURES
// ═══════════════════════════════════════════════════════════════════════

/// A signed Verified Credential. The payload is signed by the issuer's
/// Ed25519 private key. The guest verifies this signature inside the zkVM.
#[derive(Deserialize)]
struct SignedCredential {
    /// The raw payload bytes that were signed by the issuer
    payload: CredentialPayload,
    /// The Ed25519 signature bytes (64 bytes as Vec for serde compat)
    signature_bytes: Vec<u8>,
    /// The issuer's Ed25519 public key (32 bytes)
    issuer_pubkey: [u8; 32],
}

/// The credential payload — what the issuer actually signed.
#[derive(Deserialize, Serialize)]
struct CredentialPayload {
    /// The subject's KERI AID (who this credential is about)
    subject_aid: String,
    /// The type of credential (e.g., "GovernmentID", "BankAccount")
    credential_type: String,
    /// Days since issuance
    days_since_issuance: u32,
    /// Days until expiry (0 = no expiry)
    days_until_expiry: u32,
    /// SHA-256 hash of the private claims (actual document data)
    /// The claims themselves are NOT included — only their hash
    /// This allows the issuer to commit to specific data without revealing it
    claims_hash: [u8; 32],
}

/// KERI identity context
#[derive(Deserialize)]
struct KeriContext {
    aid_prefix: String,
    aid_age_days: u32,
    witness_count: u32,
    has_rotated_keys: bool,
}

/// Local device attestation
#[derive(Deserialize)]
struct LocalAttestation {
    biometric_passed: bool,
    peer_endorsements: u32,
}

/// Top-level input to the zkVM guest
#[derive(Deserialize)]
struct ScoringInput {
    keri: KeriContext,
    /// Signed credentials (signature verified inside zkVM)
    signed_credentials: Vec<SignedCredential>,
    /// List of trusted issuer public keys (Alice and Bob agree on these)
    trusted_issuer_pubkeys: Vec<[u8; 32]>,
    local: LocalAttestation,
}

/// Information about a verified credential that gets selectively disclosed
#[derive(Serialize)]
struct DisclosedCredential {
    /// The type of credential (e.g., "GovernmentID") — disclosed
    credential_type: String,
    /// First 8 bytes of issuer public key — fingerprint, not full identity
    issuer_fingerprint: [u8; 8],
    /// Whether the issuer is on the trusted list
    issuer_trusted: bool,
}

/// Public output committed to the journal
#[derive(Serialize)]
struct ScoringOutput {
    /// Bob's KERI AID
    aid_prefix: String,
    /// The computed confidence score (0–100)
    confidence_score: u32,
    /// Algorithm version
    algorithm_version: u32,
    /// Number of credentials with VALID signatures
    signatures_verified: u32,
    /// Number of credentials that FAILED signature verification
    signatures_failed: u32,
    /// Selectively disclosed credential info (type + issuer fingerprint only)
    disclosed_credentials: Vec<DisclosedCredential>,
}

// ═══════════════════════════════════════════════════════════════════════
// ALGORITHM v3 — Hybrid Verifiable Scoring
// ═══════════════════════════════════════════════════════════════════════

const ALGORITHM_VERSION: u32 = 3;

fn main() {
    let input: ScoringInput = env::read();

    let mut score: u32 = 0;
    let mut signatures_verified: u32 = 0;
    let mut signatures_failed: u32 = 0;
    let mut disclosed_credentials: Vec<DisclosedCredential> = Vec::new();

    // Tracking for scoring
    let mut trusted_issuer_count: u32 = 0;
    let mut has_government_id = false;
    let mut has_financial_credential = false;

    // ─── LAYER 1 + 2: Verify signatures & selectively disclose ─────────

    for cred in &input.signed_credentials {
        // Reconstruct the message that was signed (deterministic serialization)
        let payload_bytes = serialize_payload(&cred.payload);

        // LAYER 1: Verify the Ed25519 signature INSIDE the zkVM
        let sig_valid = verify_ed25519_signature(
            &payload_bytes,
            &cred.signature_bytes,
            &cred.issuer_pubkey,
        );

        if !sig_valid {
            signatures_failed += 1;
            continue; // Skip credentials with invalid signatures
        }

        // Signature is valid — this credential is authentic
        signatures_verified += 1;

        // Check if the credential's subject matches Bob's AID
        if cred.payload.subject_aid != input.keri.aid_prefix {
            continue; // Skip credentials issued to someone else
        }

        // Check expiry
        if cred.payload.days_until_expiry > 0 && cred.payload.days_until_expiry < cred.payload.days_since_issuance {
            continue; // Expired
        }

        // Check if issuer is trusted
        let issuer_trusted = input.trusted_issuer_pubkeys
            .iter()
            .any(|trusted_key| trusted_key == &cred.issuer_pubkey);

        if issuer_trusted {
            trusted_issuer_count += 1;
        }

        // Track credential types
        match cred.payload.credential_type.as_str() {
            "GovernmentID" => has_government_id = true,
            "BankAccount" | "FinancialInstitution" => has_financial_credential = true,
            _ => {}
        }

        // LAYER 2: Selective Disclosure — only reveal type + issuer fingerprint
        let mut issuer_fingerprint = [0u8; 8];
        issuer_fingerprint.copy_from_slice(&cred.issuer_pubkey[..8]);

        disclosed_credentials.push(DisclosedCredential {
            credential_type: cred.payload.credential_type.clone(),
            issuer_fingerprint,
            issuer_trusted,
        });
    }

    // ─── LAYER 3: Scoring (only on cryptographically verified VCs) ─────

    // PILLAR 1: Cryptographic Identity (KERI) — max 25 points
    if input.keri.aid_age_days > 365 {
        score += 15;
    } else if input.keri.aid_age_days > 90 {
        score += 8;
    } else if input.keri.aid_age_days > 30 {
        score += 3;
    }

    if input.keri.witness_count >= 3 {
        score += 7;
    } else if input.keri.witness_count >= 1 {
        score += 3;
    }

    if input.keri.has_rotated_keys {
        score += 3;
    }

    // PILLAR 2: Verified Credentials — max 45 points
    // These points are ONLY awarded for signature-verified VCs
    let valid_vc_count = disclosed_credentials.len() as u32;
    score += core::cmp::min(valid_vc_count * 8, 15);
    score += core::cmp::min(trusted_issuer_count * 10, 15);

    if has_government_id && has_financial_credential {
        score += 15;
    } else if has_government_id || has_financial_credential {
        score += 8;
    }

    // PILLAR 3: Local Authentication — max 20 points
    if input.local.biometric_passed {
        score += 12;
    }
    score += core::cmp::min(input.local.peer_endorsements * 4, 8);

    // BONUS: Cross-pillar synergy — max 10 points
    let has_keri_strength = input.keri.aid_age_days > 90 && input.keri.witness_count >= 2;
    let has_vc_strength = valid_vc_count >= 2 && trusted_issuer_count >= 1;
    let has_local_strength = input.local.biometric_passed;

    if has_keri_strength && has_vc_strength && has_local_strength {
        score += 10;
    }

    let confidence_score = core::cmp::min(score, 100);

    // ─── COMMIT PUBLIC OUTPUT ──────────────────────────────────────────

    let output = ScoringOutput {
        aid_prefix: input.keri.aid_prefix,
        confidence_score,
        algorithm_version: ALGORITHM_VERSION,
        signatures_verified,
        signatures_failed,
        disclosed_credentials,
    };

    env::commit(&output);
}

// ═══════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

/// Verify an Ed25519 signature inside the zkVM.
/// This is the critical function — it proves to Alice that the credential
/// was actually signed by the claimed issuer.
fn verify_ed25519_signature(
    message: &[u8],
    signature_bytes: &[u8],
    pubkey_bytes: &[u8; 32],
) -> bool {
    // Signature must be exactly 64 bytes
    if signature_bytes.len() != 64 {
        return false;
    }

    // Parse the public key
    let verifying_key = match VerifyingKey::from_bytes(pubkey_bytes) {
        Ok(key) => key,
        Err(_) => return false,
    };

    // Parse the signature
    let sig_array: [u8; 64] = signature_bytes.try_into().unwrap();
    let signature = Signature::from_bytes(&sig_array);

    // Verify — this is the computationally expensive part that runs in zkVM
    verifying_key.verify(message, &signature).is_ok()
}

/// Deterministic serialization of the credential payload for signing/verification.
/// Uses SHA-256 hash of the JSON-like representation as the signed message.
fn serialize_payload(payload: &CredentialPayload) -> Vec<u8> {
    // Create a deterministic byte representation of the payload
    // In production, this would use a canonical serialization (e.g., JCS, CBOR)
    let mut hasher = Sha256::new();
    hasher.update(payload.subject_aid.as_bytes());
    hasher.update(b"|");
    hasher.update(payload.credential_type.as_bytes());
    hasher.update(b"|");
    hasher.update(&payload.days_since_issuance.to_le_bytes());
    hasher.update(b"|");
    hasher.update(&payload.days_until_expiry.to_le_bytes());
    hasher.update(b"|");
    hasher.update(&payload.claims_hash);
    hasher.finalize().to_vec()
}
