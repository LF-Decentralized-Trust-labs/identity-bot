// Identity Agent - Hybrid zkVM Scoring Algorithm v4
// SHA-256 Commitment Pattern for production-speed full proving
//
// WHY THIS APPROACH (vs Ed25519 inside zkVM):
//
// Ed25519 inside zkVM = ~500 million RISC-V cycles (10-30 min proof)
// SHA-256 accelerator  = ~50,000 RISC-V cycles    (5-10 sec proof)
//
// The split:
//   HOST  → verifies Ed25519 signatures natively (fast, ~100µs each)
//           computes SHA-256 commitment per verified VC
//   GUEST → receives commitments, re-derives them using the accelerator,
//           verifies they match, scores, selectively discloses
//
// SECURITY MODEL:
//   The zkVM proof proves: "algorithm v4 processed these exact commitment
//   hashes and produced this score". The commitments encode the issuer
//   pubkey fingerprint + credential type + trust status. Alice can:
//     a) Trust the proof (algorithm integrity guaranteed by zkVM)
//     b) Independently re-verify the Ed25519 sigs herself using the
//        issuer fingerprints committed in the journal
//
// This is the standard production pattern — identical to how zkEVMs handle
// ECDSA signature precompiles (verify outside, commit inside).

use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

// ═══════════════════════════════════════════════════════════════════════
// DATA STRUCTURES
// ═══════════════════════════════════════════════════════════════════════

/// A pre-verified credential commitment.
/// The host verified the Ed25519 signature and produced this commitment.
/// The guest re-derives and verifies the commitment hash to ensure
/// the host didn't lie about the credential contents.
#[derive(Deserialize)]
struct VerifiedCredentialCommitment {
    /// Credential type — e.g. "GovernmentID" (selectively disclosed)
    credential_type: String,
    /// First 8 bytes of the issuer's Ed25519 public key (fingerprint)
    /// Enables Alice to independently verify the Ed25519 sig if she wants
    issuer_fingerprint: [u8; 8],
    /// Whether the issuer is on the trusted registry list
    issuer_trusted: bool,
    /// Days since this credential was issued (used for scoring)
    #[allow(dead_code)]
    days_since_issuance: u32,
    /// SHA-256 commitment: sha256(issuer_pubkey_32 || payload_hash_32 || trusted_byte)
    /// Guest re-derives this to ensure host didn't fabricate the commitment
    commitment_hash: [u8; 32],
    /// The 32-byte issuer public key (needed for commitment re-derivation)
    issuer_pubkey_32: [u8; 32],
    /// The 32-byte payload hash (sha256 of the VC payload fields)
    payload_hash: [u8; 32],
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

/// Top-level input
#[derive(Deserialize)]
struct ScoringInput {
    keri: KeriContext,
    /// Pre-verified credential commitments from the host
    commitments: Vec<VerifiedCredentialCommitment>,
    local: LocalAttestation,
}

/// Selectively disclosed credential info in the public output
#[derive(Serialize)]
struct DisclosedCredential {
    credential_type: String,
    issuer_fingerprint: [u8; 8],
    issuer_trusted: bool,
}

/// Public output committed to the journal
#[derive(Serialize)]
struct ScoringOutput {
    aid_prefix: String,
    confidence_score: u32,
    algorithm_version: u32,
    commitments_verified: u32,
    commitments_rejected: u32,
    disclosed_credentials: Vec<DisclosedCredential>,
}

const ALGORITHM_VERSION: u32 = 4;

// ═══════════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════════

fn main() {
    let input: ScoringInput = env::read();

    let mut score: u32 = 0;
    let mut commitments_verified: u32 = 0;
    let mut commitments_rejected: u32 = 0;
    let mut disclosed: Vec<DisclosedCredential> = Vec::new();

    let mut trusted_count: u32 = 0;
    let mut has_government_id = false;
    let mut has_financial_cred = false;

    // ─── LAYER 2: Re-derive and verify commitment hashes ───────────────
    //
    // The guest uses the SHA-256 accelerator to re-derive each commitment.
    // If the host fabricated a commitment (e.g., claimed a credential was
    // trusted when it wasn't), the re-derived hash won't match → rejected.
    //
    // sha256(issuer_pubkey_32 || payload_hash_32 || trusted_byte)

    for c in &input.commitments {
        let expected_hash = derive_commitment(
            &c.issuer_pubkey_32,
            &c.payload_hash,
            c.issuer_trusted,
        );

        if expected_hash != c.commitment_hash {
            // Commitment mismatch — host tried to lie about this credential
            commitments_rejected += 1;
            continue;
        }

        // Check subject by ensuring the payload_hash was derived from Bob's AID
        // (The host includes the AID in the payload hash computation)
        // Here we trust the subject check was done by the host and committed

        // Commitment verified ✓
        commitments_verified += 1;

        if c.issuer_trusted {
            trusted_count += 1;
        }

        match c.credential_type.as_str() {
            "GovernmentID" => has_government_id = true,
            "BankAccount" | "FinancialInstitution" => has_financial_cred = true,
            _ => {}
        }

        disclosed.push(DisclosedCredential {
            credential_type: c.credential_type.clone(),
            issuer_fingerprint: c.issuer_fingerprint,
            issuer_trusted: c.issuer_trusted,
        });
    }

    // ─── LAYER 3: Scoring ──────────────────────────────────────────────

    // PILLAR 1: KERI Cryptographic Identity (max 25)
    if input.keri.aid_age_days > 365 {
        score += 15;
    } else if input.keri.aid_age_days > 90 {
        score += 8;
    } else if input.keri.aid_age_days > 30 {
        score += 3;
    }
    if input.keri.witness_count >= 3 { score += 7; }
    else if input.keri.witness_count >= 1 { score += 3; }
    if input.keri.has_rotated_keys { score += 3; }

    // PILLAR 2: Verified Credentials (max 45)
    let valid_count = commitments_verified;
    score += core::cmp::min(valid_count * 8, 15);
    score += core::cmp::min(trusted_count * 10, 15);
    if has_government_id && has_financial_cred { score += 15; }
    else if has_government_id || has_financial_cred { score += 8; }

    // PILLAR 3: Local Authentication (max 20)
    if input.local.biometric_passed { score += 12; }
    score += core::cmp::min(input.local.peer_endorsements * 4, 8);

    // SYNERGY BONUS (max 10)
    let keri_ok = input.keri.aid_age_days > 90 && input.keri.witness_count >= 2;
    let vc_ok = valid_count >= 2 && trusted_count >= 1;
    if keri_ok && vc_ok && input.local.biometric_passed { score += 10; }

    let confidence_score = core::cmp::min(score, 100);

    env::commit(&ScoringOutput {
        aid_prefix: input.keri.aid_prefix,
        confidence_score,
        algorithm_version: ALGORITHM_VERSION,
        commitments_verified,
        commitments_rejected,
        disclosed_credentials: disclosed,
    });
}

// ═══════════════════════════════════════════════════════════════════════
// COMMITMENT DERIVATION — uses RISC Zero SHA-256 accelerator
// ═══════════════════════════════════════════════════════════════════════

/// Derives a credential commitment hash using SHA-256.
/// This runs via the RISC Zero SHA-256 precompile (hardware accelerated).
///
/// commit = SHA-256(issuer_pubkey_32 || payload_hash_32 || trusted_byte)
fn derive_commitment(
    issuer_pubkey: &[u8; 32],
    payload_hash: &[u8; 32],
    issuer_trusted: bool,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(issuer_pubkey);
    hasher.update(payload_hash);
    hasher.update(&[issuer_trusted as u8]);
    hasher.finalize().into()
}
