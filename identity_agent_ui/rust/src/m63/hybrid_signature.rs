//! M63 C2 — hybrid composite signature wire format + both-must-verify.

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use pqc_poc_rust::mldsa65;
use serde_json::Value;

use super::cesr::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridSignatureResult {
    pub message_b64: String,
    pub ed25519_siger: String,
    pub mldsa65_sig: String,
    pub composite_wire: String,
    pub composite_wire_len: usize,
}

pub fn is_hybrid_identity(inception: &Value) -> bool {
    let Some(a) = inception.get("a").and_then(|v| v.as_array()) else {
        return false;
    };
    let Some(seal) = a.first().and_then(|v| v.as_object()) else {
        return false;
    };
    seal.get("ia")
        .and_then(|v| v.as_str())
        .map(|s| s == CIPHER_SUITE_IA_HYBRID_1)
        .unwrap_or(false)
}

pub fn signing_key_count(inception: &Value) -> usize {
    inception
        .get("k")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0)
}

pub fn matter_indexed_sig_qb64(code: &str, index: usize, raw: &[u8], fs: usize) -> Result<String, String> {
    let hs = code.len();
    let ss = 1usize;
    let ls = 0usize;
    let cs = hs + ss;
    let ms = ss;
    if fs <= cs {
        return Err(format!("invalid fs {fs} for code {code}"));
    }
    let ps = (3 - (raw.len() % 3)) % 3;
    let both = format!("{}{}", code, int_to_b64(index, ms));
    let mut padded = vec![0u8; ps + raw.len()];
    padded[ps..].copy_from_slice(raw);
    let b64 = base64::encode_config(&padded, base64::URL_SAFE_NO_PAD);
    let skip = ps - ls;
    if skip > b64.len() {
        return Err("invalid indexed sig encoding".into());
    }
    let out = format!("{}{}", both, &b64[skip..]);
    if out.len() != fs {
        return Err(format!("indexed sig len {} != fs {}", out.len(), fs));
    }
    Ok(out)
}

pub fn encode_indexed_mldsa_sig(index: usize, raw: &[u8]) -> Result<String, String> {
    if raw.len() != MLDSA65_SIG_BYTES {
        return Err(format!(
            "ML-DSA-65 sig must be {} bytes, got {}",
            MLDSA65_SIG_BYTES,
            raw.len()
        ));
    }
    if index > 63 {
        return Err(format!("index out of range: {index}"));
    }
    Ok(format!(
        "{}{}{}",
        CESR_MLDSA65_SIG,
        int_to_b64(index, 1),
        base64::encode_config(raw, base64::URL_SAFE_NO_PAD)
    ))
}

pub fn compose_hybrid_signature(ed25519_siger: &str, mldsa_sig: &str) -> String {
    format!(
        "{}{}{}{}",
        CTR_CONTROLLER_IDX_SIGS,
        int_to_b64(2, 2),
        ed25519_siger,
        mldsa_sig
    )
}

pub fn parse_composite_signature(wire: &str) -> Result<(String, String), String> {
    if wire.len() < 4 || !wire.starts_with(CTR_CONTROLLER_IDX_SIGS) {
        return Err(format!(
            "composite signature must start with {CTR_CONTROLLER_IDX_SIGS} counter"
        ));
    }
    let count = b64_to_int(&wire[2..4]);
    if count != 2 {
        return Err(format!("expected 2 indexed sigs, counter={count}"));
    }
    let rest = &wire[4..];
    if rest.len() < 88 {
        return Err("truncated composite signature".into());
    }
    let ed = rest[..88].to_string();
    let mldsa = rest[88..].to_string();
    if !mldsa.starts_with(CESR_MLDSA65_SIG) {
        return Err(format!("ML-DSA half missing {CESR_MLDSA65_SIG} prefix"));
    }
    Ok((ed, mldsa))
}

pub fn decode_indexed_mldsa_sig(wire: &str) -> Result<(usize, Vec<u8>), String> {
    if wire.len() < 5 || !wire.starts_with(CESR_MLDSA65_SIG) {
        return Err(format!("expected {CESR_MLDSA65_SIG} indexed sig"));
    }
    let index = b64_to_int(&wire[4..5]);
    let raw = base64::decode_config(&wire[5..], base64::URL_SAFE_NO_PAD)
        .map_err(|e| format!("b64: {e}"))?;
    if raw.len() != MLDSA65_SIG_BYTES {
        return Err(format!(
            "decoded sig len {} != {}",
            raw.len(),
            MLDSA65_SIG_BYTES
        ));
    }
    Ok((index, raw))
}

pub fn sign_hybrid_message() -> Result<HybridSignatureResult, String> {
    let msg = C2_MESSAGE.as_bytes();
    let ed_seed = c2_ed25519_seed();
    let ed_sk = SigningKey::from_bytes(&ed_seed);
    let ed_sig = ed_sk.sign(msg);
    let ed_wire = matter_indexed_sig_qb64("B", 0, &ed_sig.to_bytes(), 88)?;

    let mldsa_seed = c2_mldsa_seed();
    let mldsa_raw = mldsa65::sign_from_seed(&mldsa_seed, msg)?;
    let mldsa_wire = encode_indexed_mldsa_sig(1, &mldsa_raw)?;
    let composite = compose_hybrid_signature(&ed_wire, &mldsa_wire);
    Ok(HybridSignatureResult {
        message_b64: hex::encode(msg),
        ed25519_siger: ed_wire,
        mldsa65_sig: mldsa_wire,
        composite_wire: composite.clone(),
        composite_wire_len: composite.len(),
    })
}

pub fn c2_signing_verkeys() -> Result<(Vec<u8>, Vec<u8>), String> {
    let ed_seed = c2_ed25519_seed();
    let ed_sk = SigningKey::from_bytes(&ed_seed);
    let ed_vk = VerifyingKey::from(&ed_sk);
    let mldsa_vk = mldsa65::verkey_from_seed(&c2_mldsa_seed());
    Ok((ed_vk.to_bytes().to_vec(), mldsa_vk.to_vec()))
}

pub fn verify_hybrid_signature(
    msg: &[u8],
    composite_wire: &str,
    ed25519_verkey: &[u8],
    mldsa_verkey: &[u8],
    inception: Option<&Value>,
) -> bool {
    if let Some(ev) = inception {
        if !is_hybrid_identity(ev) || signing_key_count(ev) != 2 {
            return false;
        }
    }
    let (ed_wire, mldsa_wire) = match parse_composite_signature(composite_wire) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let ed_raw = match decode_ed25519_siger_raw(&ed_wire) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if ed25519_verkey.len() != ED25519_PUBKEY_BYTES {
        return false;
    }
    let ed_arr: [u8; ED25519_PUBKEY_BYTES] = match ed25519_verkey.try_into() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let ed_vk = match VerifyingKey::from_bytes(&ed_arr) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig_arr: [u8; ED25519_SIG_BYTES] = match ed_raw.try_into() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    if ed_vk.verify_strict(msg, &sig).is_err() {
        return false;
    }
    let (_, mldsa_raw) = match decode_indexed_mldsa_sig(&mldsa_wire) {
        Ok(v) => v,
        Err(_) => return false,
    };
    mldsa65::verify(mldsa_verkey, msg, &mldsa_raw).unwrap_or(false)
}

fn decode_ed25519_siger_raw(siger_qb64: &str) -> Result<Vec<u8>, String> {
    if siger_qb64.len() != 88 || !siger_qb64.starts_with('B') {
        return Err("invalid Ed25519 indexed sig".into());
    }
    let ps = (3 - (ED25519_SIG_BYTES % 3)) % 3;
    let prefix = int_to_b64(0, ps);
    let padded = base64::decode_config(&(prefix + &siger_qb64[2..]), base64::URL_SAFE_NO_PAD)
        .map_err(|e| format!("b64: {e}"))?;
    if padded.len() < ED25519_SIG_BYTES {
        return Err(format!("ed25519 sig len {}", padded.len()));
    }
    Ok(padded[padded.len() - ED25519_SIG_BYTES..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m63::hybrid_inception::{build_hybrid_inception, synthetic_hybrid_key_material};
    use serde_json::Value;

    #[test]
    fn c2_hybrid_signature_golden() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../identity-agent-core/m63/golden_vectors.json"
        );
        let data = std::fs::read_to_string(path).expect("golden_vectors.json");
        let v: Value = serde_json::from_str(&data).expect("json");
        let vec = &v["hybrid_signature"];
        assert!(
            vec["composite_wire"].is_string(),
            "hybrid_signature not pinned — run scripts/pin_m63_c2_golden.py"
        );

        let res = sign_hybrid_message().expect("sign");
        let pinned = vec["composite_wire"].as_str().unwrap();
        assert_eq!(res.composite_wire, pinned, "composite_wire mismatch vs keripy");

        let inc = build_hybrid_inception(&synthetic_hybrid_key_material(0)).expect("icp");
        let inc_val: Value = serde_json::to_value(&inc.inception_event).expect("json");
        let (ed_vk, mldsa_vk) = c2_signing_verkeys().expect("verkeys");
        let msg = b"m63-c2-hybrid-signature-golden-vector";
        assert!(verify_hybrid_signature(
            msg,
            pinned,
            &ed_vk,
            &mldsa_vk,
            Some(&inc_val)
        ));

        let corrupt_classical = vec["negative_vectors"]["hybrid_sig_classical_corrupt"]
            .as_str()
            .unwrap();
        let corrupt_pqc = vec["negative_vectors"]["hybrid_sig_pqc_corrupt"]
            .as_str()
            .unwrap();
        assert!(!verify_hybrid_signature(
            msg, corrupt_classical, &ed_vk, &mldsa_vk, Some(&inc_val)
        ));
        assert!(!verify_hybrid_signature(
            msg, corrupt_pqc, &ed_vk, &mldsa_vk, Some(&inc_val)
        ));
    }
}