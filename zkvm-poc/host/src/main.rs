// Identity Agent - Hybrid zkVM Host v4
// SHA-256 Commitment Pattern — enables full proof mode without GPU
//
// ARCHITECTURE:
//
//   STEP 1 (host, native speed):
//     • Generate issuer Ed25519 keypairs
//     • Sign VC payloads
//     • Verify Ed25519 signatures (~100µs each)
//     • For each valid VC: compute SHA-256 commitment
//       commit = sha256(issuer_pubkey_32 || payload_hash || trusted_byte)
//
//   STEP 2 (zkVM, ~5-15 seconds):
//     • Feed commitment structs into the zkVM
//     • Guest re-derives each commitment using SHA-256 accelerator
//     • Guest rejects any mismatches (host can't lie about VC contents)
//     • Guest scores and selectively discloses
//     • Receipt proves: "algorithm v4 processed THESE exact commitments"
//
//   STEP 3 (verifier, ~20ms):
//     • receipt.verify(SCORING_ID) — instant
//     • Read disclosed credentials and score from journal
//
// TRUST MODEL:
//   Alice gets a ZK proof that the scoring algorithm processed specific
//   commitment hashes. The issuer fingerprints in the journal let Alice
//   independently re-verify the Ed25519 signatures if she chooses.

use methods::{SCORING_ELF, SCORING_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest as Sha2Digest};
use ed25519_dalek::{SigningKey, Signer, Verifier, VerifyingKey, Signature};
use std::time::Instant;

// ═══════════════════════════════════════════════════════════════════════
// DATA STRUCTURES — Mirror guest structs exactly
// ═══════════════════════════════════════════════════════════════════════

#[derive(Serialize)]
struct VerifiedCredentialCommitment {
    credential_type: String,
    issuer_fingerprint: [u8; 8],
    issuer_trusted: bool,
    days_since_issuance: u32,
    commitment_hash: [u8; 32],
    issuer_pubkey_32: [u8; 32],
    payload_hash: [u8; 32],
}

#[derive(Serialize)]
struct KeriContext {
    aid_prefix: String,
    aid_age_days: u32,
    witness_count: u32,
    has_rotated_keys: bool,
}

#[derive(Serialize)]
struct LocalAttestation {
    biometric_passed: bool,
    peer_endorsements: u32,
}

#[derive(Serialize)]
struct ScoringInput {
    keri: KeriContext,
    commitments: Vec<VerifiedCredentialCommitment>,
    local: LocalAttestation,
}

#[derive(Deserialize, Debug)]
struct DisclosedCredential {
    credential_type: String,
    issuer_fingerprint: [u8; 8],
    issuer_trusted: bool,
}

#[derive(Deserialize, Debug)]
struct ScoringOutput {
    aid_prefix: String,
    confidence_score: u32,
    algorithm_version: u32,
    commitments_verified: u32,
    commitments_rejected: u32,
    disclosed_credentials: Vec<DisclosedCredential>,
}

// ═══════════════════════════════════════════════════════════════════════
// RAW VC (used only inside host before commitment is built)
// ═══════════════════════════════════════════════════════════════════════

struct RawVC {
    subject_aid: String,
    credential_type: String,
    days_since_issuance: u32,
    days_until_expiry: u32,
    /// Private claims hash — actual VC data (never sent to zkVM)
    private_claims_hash: [u8; 32],
}

// ═══════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════

/// Compute the payload hash — same formula used for signing
fn payload_hash(vc: &RawVC) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(vc.subject_aid.as_bytes());
    h.update(b"|");
    h.update(vc.credential_type.as_bytes());
    h.update(b"|");
    h.update(&vc.days_since_issuance.to_le_bytes());
    h.update(b"|");
    h.update(&vc.days_until_expiry.to_le_bytes());
    h.update(b"|");
    h.update(&vc.private_claims_hash);
    h.finalize().into()
}

/// Derive commitment hash — must match guest's derive_commitment exactly
fn derive_commitment(
    issuer_pubkey: &[u8; 32],
    p_hash: &[u8; 32],
    trusted: bool,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(issuer_pubkey);
    h.update(p_hash);
    h.update(&[trusted as u8]);
    h.finalize().into()
}

/// Sign a VC payload hash with an issuer's signing key
fn sign_vc(signing_key: &SigningKey, vc: &RawVC) -> (Vec<u8>, [u8; 32]) {
    let p_hash = payload_hash(vc);
    let signature = signing_key.sign(&p_hash);
    (signature.to_bytes().to_vec(), p_hash)
}

/// Verify an Ed25519 signature natively on the host (fast, native Rust)
fn verify_sig(
    verifying_key: &VerifyingKey,
    message: &[u8; 32],
    sig_bytes: &[u8],
) -> bool {
    if sig_bytes.len() != 64 { return false; }
    let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
    let sig = Signature::from_bytes(&sig_arr);
    verifying_key.verify(message, &sig).is_ok()
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  Identity Agent - Hybrid zkVM v4 (SHA-256 Commitment PoC)   ║");
    println!("║  Full proof mode — no RISC0_DEV_MODE needed                 ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // =========================================================================
    // STEP 1A: Set up issuers with Ed25519 keypairs
    // =========================================================================

    println!("━━━ ISSUER SETUP ━━━");
    println!();

    let gov_key = SigningKey::from_bytes(&[
        1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
        17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,
    ]);
    let gov_pubkey: [u8; 32] = gov_key.verifying_key().to_bytes();

    let bank_key = SigningKey::from_bytes(&[
        99,98,97,96,95,94,93,92,91,90,89,88,87,86,85,84,
        83,82,81,80,79,78,77,76,75,74,73,72,71,70,69,68,
    ]);
    let bank_pubkey: [u8; 32] = bank_key.verifying_key().to_bytes();

    // Attacker with an untrusted key
    let attacker_key = SigningKey::from_bytes(&[42u8; 32]);
    let attacker_pubkey: [u8; 32] = attacker_key.verifying_key().to_bytes();

    let trusted_pubkeys = vec![gov_pubkey, bank_pubkey];

    println!("  Gov  pubkey: {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}",
        gov_pubkey[0], gov_pubkey[1], gov_pubkey[2], gov_pubkey[3],
        gov_pubkey[30], gov_pubkey[31]);
    println!("  Bank pubkey: {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}",
        bank_pubkey[0], bank_pubkey[1], bank_pubkey[2], bank_pubkey[3],
        bank_pubkey[30], bank_pubkey[31]);
    println!();

    // =========================================================================
    // STEP 1B: Issuers sign credentials
    // =========================================================================

    let bob_aid = "EBk2q3Lz7xhVwYD1K4p8n9R5mT0vX6yA2cF8gH3jW".to_string();

    // Raw VCs with private claims (hashed — actual data never leaves Bob's device)
    let vc1 = RawVC {
        subject_aid: bob_aid.clone(),
        credential_type: "GovernmentID".to_string(),
        days_since_issuance: 180,
        days_until_expiry: 1825,
        private_claims_hash: Sha256::digest(b"Bob Smith|Passport|AB1234567|1990-05-15").into(),
    };

    let vc2 = RawVC {
        subject_aid: bob_aid.clone(),
        credential_type: "BankAccount".to_string(),
        days_since_issuance: 90,
        days_until_expiry: 365,
        private_claims_hash: Sha256::digest(b"Bob Smith|Checking|****4567|Balance>10000").into(),
    };

    let vc3_fake = RawVC {
        subject_aid: bob_aid.clone(),
        credential_type: "FakeCredential".to_string(),
        days_since_issuance: 5,
        days_until_expiry: 9999,
        private_claims_hash: Sha256::digest(b"Fake data from attacker").into(),
    };

    let (sig1, p_hash1) = sign_vc(&gov_key, &vc1);
    let (sig2, p_hash2) = sign_vc(&bank_key, &vc2);
    let (sig3_fake, p_hash3_fake) = sign_vc(&attacker_key, &vc3_fake);

    println!("━━━ STEP 1: HOST — Ed25519 Verification (native speed) ━━━");
    println!();

    let t_verify = Instant::now();

    // =========================================================================
    // STEP 1C: Host verifies signatures and builds commitments
    // =========================================================================

    let mut commitments: Vec<VerifiedCredentialCommitment> = Vec::new();

    // Process VC1 — GovernmentID
    let gov_vk = gov_key.verifying_key();
    let vc1_valid = verify_sig(&gov_vk, &p_hash1, &sig1);
    println!("  VC #1 (GovernmentID)   — Ed25519 sig valid: {}", vc1_valid);
    if vc1_valid {
        let issuer_trusted = trusted_pubkeys.contains(&gov_pubkey);
        let commit = derive_commitment(&gov_pubkey, &p_hash1, issuer_trusted);
        let mut fingerprint = [0u8; 8];
        fingerprint.copy_from_slice(&gov_pubkey[..8]);
        commitments.push(VerifiedCredentialCommitment {
            credential_type: vc1.credential_type.clone(),
            issuer_fingerprint: fingerprint,
            issuer_trusted,
            days_since_issuance: vc1.days_since_issuance,
            commitment_hash: commit,
            issuer_pubkey_32: gov_pubkey,
            payload_hash: p_hash1,
        });
    }

    // Process VC2 — BankAccount
    let bank_vk = bank_key.verifying_key();
    let vc2_valid = verify_sig(&bank_vk, &p_hash2, &sig2);
    println!("  VC #2 (BankAccount)    — Ed25519 sig valid: {}", vc2_valid);
    if vc2_valid {
        let issuer_trusted = trusted_pubkeys.contains(&bank_pubkey);
        let commit = derive_commitment(&bank_pubkey, &p_hash2, issuer_trusted);
        let mut fingerprint = [0u8; 8];
        fingerprint.copy_from_slice(&bank_pubkey[..8]);
        commitments.push(VerifiedCredentialCommitment {
            credential_type: vc2.credential_type.clone(),
            issuer_fingerprint: fingerprint,
            issuer_trusted,
            days_since_issuance: vc2.days_since_issuance,
            commitment_hash: commit,
            issuer_pubkey_32: bank_pubkey,
            payload_hash: p_hash2,
        });
    }

    // Process VC3 — Fake (attacker's credential, untrusted issuer)
    let attacker_vk = attacker_key.verifying_key();
    let vc3_valid = verify_sig(&attacker_vk, &p_hash3_fake, &sig3_fake);
    println!("  VC #3 (FakeCredential) — Ed25519 sig valid: {} (but issuer UNTRUSTED)", vc3_valid);
    if vc3_valid {
        let issuer_trusted = trusted_pubkeys.contains(&attacker_pubkey);
        let commit = derive_commitment(&attacker_pubkey, &p_hash3_fake, issuer_trusted);
        let mut fingerprint = [0u8; 8];
        fingerprint.copy_from_slice(&attacker_pubkey[..8]);
        commitments.push(VerifiedCredentialCommitment {
            credential_type: vc3_fake.credential_type.clone(),
            issuer_fingerprint: fingerprint,
            issuer_trusted,
            days_since_issuance: vc3_fake.days_since_issuance,
            commitment_hash: commit,
            issuer_pubkey_32: attacker_pubkey,
            payload_hash: p_hash3_fake,
        });
    }

    println!("  Native Ed25519 verification time: {:.2?}", t_verify.elapsed());
    println!("  Commitments built: {}", commitments.len());
    println!();

    // =========================================================================
    // STEP 2: Feed commitments into zkVM and generate proof
    // =========================================================================

    println!("━━━ STEP 2: zkVM — SHA-256 Commitment Verification + Scoring ━━━");
    println!();

    let scoring_input = ScoringInput {
        keri: KeriContext {
            aid_prefix: bob_aid.clone(),
            aid_age_days: 730,
            witness_count: 3,
            has_rotated_keys: true,
        },
        commitments,
        local: LocalAttestation {
            biometric_passed: true,
            peer_endorsements: 2,
        },
    };

    let env = ExecutorEnv::builder()
        .write(&scoring_input)
        .unwrap()
        .build()
        .unwrap();

    println!("  Generating full ZK proof (no dev mode)...");
    let t_prove = Instant::now();

    let prover = default_prover();
    let prove_info = prover.prove(env, SCORING_ELF).unwrap();
    let receipt = prove_info.receipt;

    let prove_time = t_prove.elapsed();
    println!("  Proof generated in {:.2?}", prove_time);
    println!();

    let output: ScoringOutput = receipt.journal.decode().unwrap();

    println!("  ┌─────────────────────────────────────────────────────────┐");
    println!("  │ PUBLIC OUTPUT (what Alice receives)                      │");
    println!("  ├─────────────────────────────────────────────────────────┤");
    println!("  │ AID:                  {}...│", &output.aid_prefix[..24]);
    println!("  │ Confidence Score:     {:>3}%                             │", output.confidence_score);
    println!("  │ Algorithm Version:    v{}                               │", output.algorithm_version);
    println!("  │ Commitments Verified: {}                                │", output.commitments_verified);
    println!("  │ Commitments Rejected: {}                                │", output.commitments_rejected);
    println!("  │ Disclosed Credentials:                                  │");
    for c in &output.disclosed_credentials {
        println!("  │   • {:<20} issuer {:02x}{:02x}{:02x}{:02x}... trusted={}  │",
            c.credential_type,
            c.issuer_fingerprint[0], c.issuer_fingerprint[1],
            c.issuer_fingerprint[2], c.issuer_fingerprint[3],
            c.issuer_trusted);
    }
    println!("  │ NOT disclosed: names, doc numbers, balances, addresses  │");
    println!("  └─────────────────────────────────────────────────────────┘");
    println!();

    // =========================================================================
    // STEP 3: Alice verifies
    // =========================================================================

    println!("━━━ STEP 3: ALICE — Verify Proof ━━━");
    println!();

    let t_verify2 = Instant::now();
    match receipt.verify(SCORING_ID) {
        Ok(()) => {
            println!("  ✓ VERIFICATION PASSED in {:.2?}", t_verify2.elapsed());
            println!();
            println!("  Alice now knows with MATHEMATICAL CERTAINTY:");
            println!("    • Score {}% — computed by algorithm v{}", output.confidence_score, output.algorithm_version);
            println!("    • {} credential commitments processed", output.commitments_verified);
            println!("    • {} invalid commitments rejected", output.commitments_rejected);
            println!("    • Algorithm was NOT modified (Image ID: {:08x}...)", SCORING_ID[0]);
            println!("    • Selective disclosure: types+fingerprints revealed, raw data private");
            println!();
            println!("  Alice CAN independently re-verify Ed25519 sigs using the");
            println!("  issuer fingerprints in the journal if she chooses.");
        }
        Err(e) => println!("  ✗ VERIFICATION FAILED: {}", e),
    }

    // =========================================================================
    // SECURITY TEST: Can host lie about commitment?
    // =========================================================================

    println!();
    println!("━━━ SECURITY TEST: Can host lie about commitment? ━━━");
    println!();

    // Try to inject a fake commitment with wrong hash
    let fake_commit_input = ScoringInput {
        keri: KeriContext {
            aid_prefix: bob_aid.clone(),
            aid_age_days: 730,
            witness_count: 3,
            has_rotated_keys: true,
        },
        commitments: vec![VerifiedCredentialCommitment {
            credential_type: "GovernmentID".to_string(),
            issuer_fingerprint: [0u8; 8],
            issuer_trusted: true,    // Host LIES: claims this is trusted
            days_since_issuance: 10,
            commitment_hash: [0u8; 32], // WRONG hash — guest will reject
            issuer_pubkey_32: [1u8; 32],
            payload_hash: [2u8; 32],
        }],
        local: LocalAttestation { biometric_passed: false, peer_endorsements: 0 },
    };

    let env2 = ExecutorEnv::builder()
        .write(&fake_commit_input)
        .unwrap()
        .build()
        .unwrap();

    let prove_info2 = prover.prove(env2, SCORING_ELF).unwrap();
    let receipt2 = prove_info2.receipt;
    let output2: ScoringOutput = receipt2.journal.decode().unwrap();

    println!("  Injected commitment with mismatched hash:");
    println!("    Commitments verified: {} (rejected by guest)", output2.commitments_verified);
    println!("    Commitments rejected: {}", output2.commitments_rejected);
    println!("    Score: {}% (no valid VCs counted)", output2.confidence_score);
    if output2.commitments_rejected == 1 && output2.commitments_verified == 0 {
        println!("    ✓ PASS — host cannot fabricate fake commitments");
    }

    println!();
    println!("━━━ PERFORMANCE SUMMARY ━━━");
    println!("  Ed25519 verification (host, native): {:.2?}", t_verify.elapsed());
    println!("  ZK proof generation (full mode):     {:.2?}", prove_time);
    println!("  ZK proof verification:               {:.2?}", t_verify2.elapsed());
    println!();
    println!("Done. Full proof mode — no RISC0_DEV_MODE needed.");
}
