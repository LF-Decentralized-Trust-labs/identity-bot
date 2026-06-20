//! Deterministic ML-DSA-65 helpers for hybrid PQC C2 cross-engine golden vectors.

use ml_dsa::{
    EncodedVerifyingKey, Keypair, MlDsa65, Seed as SigSeed, Signature, SignatureEncoding, Signer,
    SigningKey, Verifier, VerifyingKey,
};

pub const MLDSA65_SIG_BYTES: usize = 3309;
pub const MLDSA65_VERKEY_BYTES: usize = 1952;

pub fn sign_from_seed(seed: &[u8; 32], msg: &[u8]) -> Result<[u8; MLDSA65_SIG_BYTES], String> {
    let sk = SigningKey::<MlDsa65>::from_seed(&SigSeed::from(*seed));
    let sig: Signature<MlDsa65> = sk.sign(msg);
    let bytes = sig.to_bytes();
    let arr: [u8; MLDSA65_SIG_BYTES] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("unexpected ML-DSA-65 sig len {}", bytes.as_slice().len()))?;
    Ok(arr)
}

pub fn verify(vk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<bool, String> {
    if vk_bytes.len() != MLDSA65_VERKEY_BYTES {
        return Err(format!(
            "vk len {} != {}",
            vk_bytes.len(),
            MLDSA65_VERKEY_BYTES
        ));
    }
    if sig_bytes.len() != MLDSA65_SIG_BYTES {
        return Err(format!(
            "sig len {} != {}",
            sig_bytes.len(),
            MLDSA65_SIG_BYTES
        ));
    }
    let enc_vk = EncodedVerifyingKey::<MlDsa65>::try_from(vk_bytes)
        .map_err(|_| "vk bytes wrong length".to_string())?;
    let vk = VerifyingKey::<MlDsa65>::decode(&enc_vk);
    let sig = Signature::<MlDsa65>::try_from(sig_bytes).map_err(|e| format!("sig decode: {e}"))?;
    Ok(vk.verify(msg, &sig).is_ok())
}

pub fn verkey_from_seed(seed: &[u8; 32]) -> [u8; MLDSA65_VERKEY_BYTES] {
    let sk = SigningKey::<MlDsa65>::from_seed(&SigSeed::from(*seed));
    let vk = sk.verifying_key();
    let encoded = vk.encode();
    *encoded.as_ref()
}