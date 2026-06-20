//! M63 C4 — Rust mobile PQC fallback spike using pure-Rust RustCrypto crates.

pub mod mldsa65;

use ml_dsa::{Keypair, MlDsa65, Seed as SigSeed, Signature, Signer, SigningKey, Verifier};
use ml_kem::{
    DecapsulationKey, MlKem768, Seed as KemSeed,
    kem::{Decapsulate, Encapsulate},
};

pub const SIG_ALG: &str = "ML-DSA-65";
pub const KEM_ALG: &str = "ML-KEM-768";
pub const CRATE_STACK: &str = "ml-dsa 0.1.1 + ml-kem 0.3.2 (RustCrypto pure Rust)";

fn sig_seed() -> SigSeed {
    (*b"m63-c4-rust-fallback-sig-seed!!!").into()
}

fn kem_seed() -> KemSeed {
    [
        0x6d, 0x36, 0x33, 0x2d, 0x63, 0x34, 0x2d, 0x72, 0x75, 0x73, 0x74, 0x2d, 0x66, 0x61, 0x6c,
        0x6c, 0x62, 0x61, 0x63, 0x6b, 0x2d, 0x6b, 0x65, 0x6d, 0x2d, 0x73, 0x65, 0x65, 0x64, 0x21, 0x21,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21,
    ]
    .into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundTripResult {
    pub crate_stack: &'static str,
    pub sig_alg: &'static str,
    pub kem_alg: &'static str,
    pub sig_verify_ok: bool,
    pub kem_secret_ok: bool,
}

impl RoundTripResult {
    pub fn pass(&self) -> bool {
        self.sig_verify_ok && self.kem_secret_ok
    }

    pub fn summary(&self) -> String {
        format!(
            "crate={} sig={} verify={} kem={} secret_match={}",
            self.crate_stack, self.sig_alg, self.sig_verify_ok, self.kem_alg, self.kem_secret_ok
        )
    }
}

pub fn run_roundtrip() -> Result<RoundTripResult, String> {
    let sig_verify_ok = run_sig_roundtrip()?;
    let kem_secret_ok = run_kem_roundtrip()?;
    Ok(RoundTripResult {
        crate_stack: CRATE_STACK,
        sig_alg: SIG_ALG,
        kem_alg: KEM_ALG,
        sig_verify_ok,
        kem_secret_ok,
    })
}

fn run_sig_roundtrip() -> Result<bool, String> {
    let sk = SigningKey::<MlDsa65>::from_seed(&sig_seed());
    let vk = sk.verifying_key();

    let msg = b"m63-c4-rust-mobile-fallback-signature";
    let sig: Signature<MlDsa65> = sk.sign(msg);
    vk.verify(msg, &sig)
        .map(|_| true)
        .map_err(|e| format!("ML-DSA-65 verify: {e}"))
}

fn run_kem_roundtrip() -> Result<bool, String> {
    let dk = DecapsulationKey::<MlKem768>::from_seed(kem_seed());
    let ek = dk.encapsulation_key();

    let (ct, k_send) = ek.encapsulate();
    let k_recv = dk.decapsulate(&ct);
    Ok(k_send == k_recv)
}

/// C FFI hook for future mobile bridge integration smoke tests.
#[no_mangle]
pub extern "C" fn pqc_rust_roundtrip_pass() -> i32 {
    match run_roundtrip() {
        Ok(r) if r.pass() => 1,
        _ => 0,
    }
}