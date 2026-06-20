//! Build hybrid PQC KERI-conformant hybrid icp events — Rust bridge (keri 1.1.17).

use serde::Serialize;
use serde_json::{json, Value};

use super::cesr::*;
use super::keri_serialize::{makify_icp_wire, versify, AnchorSeal, IcpWire, SAID_DUMMY_LEN};

#[derive(Debug, Clone)]
pub struct HybridKeyMaterial {
    pub ed25519_signing_raw: Vec<u8>,
    pub mldsa65_signing_raw: Vec<u8>,
    pub x25519_agreement_raw: Vec<u8>,
    pub mlkem768_encap_raw: Vec<u8>,
    pub next_ed25519_signing_raw: Vec<u8>,
    pub next_mldsa65_signing_raw: Vec<u8>,
}

pub fn synthetic_hybrid_key_material(seed: u8) -> HybridKeyMaterial {
    let fill = |n: usize, tag: u8| -> Vec<u8> {
        (0..n)
            .map(|i| seed.wrapping_add(tag).wrapping_add(i as u8))
            .collect()
    };
    HybridKeyMaterial {
        ed25519_signing_raw: fill(ED25519_PUBKEY_BYTES, 0x01),
        mldsa65_signing_raw: fill(MLDSA65_VERKEY_BYTES, 0x02),
        x25519_agreement_raw: fill(X25519_PUBKEY_BYTES, 0x03),
        mlkem768_encap_raw: fill(MLKEM768_ENCAP_BYTES, 0x04),
        next_ed25519_signing_raw: fill(ED25519_PUBKEY_BYTES, 0x11),
        next_mldsa65_signing_raw: fill(MLDSA65_VERKEY_BYTES, 0x12),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CesrKeys {
    pub ed25519_signing: String,
    pub mldsa65_signing: String,
    pub x25519_agreement: String,
    pub mlkem768_encap: String,
    pub next_ed25519_digest: String,
    pub next_mldsa65_digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HybridInceptionResult {
    pub aid: String,
    pub said: String,
    pub inception_event: Value,
    pub raw_bytes_b64: String,
    pub cipher_suite: String,
    pub cesr: CesrKeys,
    pub public_key: String,
    pub next_key_digest: String,
}

fn material_to_cesr(m: &HybridKeyMaterial) -> Result<CesrKeys, String> {
    Ok(CesrKeys {
        ed25519_signing: ed25519_verfer_qb64(&m.ed25519_signing_raw)?,
        mldsa65_signing: encode_large_fixed(
            CESR_MLDSA65_VERKEY,
            &m.mldsa65_signing_raw,
            MLDSA65_VERKEY_BYTES,
        )?,
        x25519_agreement: encode_large_fixed(
            CESR_X25519_PUBKEY,
            &m.x25519_agreement_raw,
            X25519_PUBKEY_BYTES,
        )?,
        mlkem768_encap: encode_large_fixed(
            CESR_MLKEM768_ENCAP,
            &m.mlkem768_encap_raw,
            MLKEM768_ENCAP_BYTES,
        )?,
        next_ed25519_digest: blake3_qb64(&m.next_ed25519_signing_raw)?,
        next_mldsa65_digest: blake3_qb64(&m.next_mldsa65_signing_raw)?,
    })
}

pub fn build_hybrid_inception(m: &HybridKeyMaterial) -> Result<HybridInceptionResult, String> {
    let cesr = material_to_cesr(m)?;
    let k = vec![cesr.ed25519_signing.clone(), cesr.mldsa65_signing.clone()];
    let n = vec![
        cesr.next_ed25519_digest.clone(),
        cesr.next_mldsa65_digest.clone(),
    ];
    let ka = vec![cesr.x25519_agreement.clone(), cesr.mlkem768_encap.clone()];
    let anchor = vec![AnchorSeal {
        ia: CIPHER_SUITE_IA_HYBRID_1,
        ka: &ka,
    }];

    let wire = IcpWire {
        v: String::new(),
        t: "icp",
        d: "",
        i: "",
        s: "0",
        kt: "1",
        k: &k,
        nt: "1",
        n: &n,
        bt: "0",
        b: &[],
        c: &[],
        a: &anchor,
    };

    let dummy = "#".repeat(SAID_DUMMY_LEN);
    let (raw, digest) = makify_icp_wire(&wire, &dummy)?;

    let inception_event = json!({
        "v": versify(raw.len()),
        "t": "icp",
        "d": digest,
        "i": digest,
        "s": "0",
        "kt": "1",
        "k": k,
        "nt": "1",
        "n": n,
        "bt": "0",
        "b": [],
        "c": [],
        "a": [{"ia": CIPHER_SUITE_IA_HYBRID_1, "ka": ka}],
    });

    Ok(HybridInceptionResult {
        aid: digest.clone(),
        said: digest,
        inception_event,
        raw_bytes_b64: base64::encode(&raw),
        cipher_suite: CIPHER_SUITE_IA_HYBRID_1.to_string(),
        cesr: cesr.clone(),
        public_key: cesr.ed25519_signing.clone(),
        next_key_digest: cesr.next_ed25519_digest.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    include!("../../tests/pqc_golden_constants.rs");

    #[test]
    fn cross_engine_byte_identity_seed0() {
        let m = synthetic_hybrid_key_material(0);
        let r = build_hybrid_inception(&m).expect("build");
        assert_eq!(r.aid, EXPECTED_AID);
        assert_eq!(r.said, EXPECTED_SAID);
        assert_eq!(r.aid, r.said);
        assert_eq!(r.raw_bytes_b64.len(), EXPECTED_RAW_B64_LEN);
        if let Some(pinned) = load_pinned_raw_b64() {
            assert_eq!(r.raw_bytes_b64, pinned, "raw_bytes_b64 mismatch vs keripy golden");
        }
    }

    #[test]
    fn synthetic_hybrid_inception_structure() {
        let m = synthetic_hybrid_key_material(0);
        let res = build_hybrid_inception(&m).expect("build");
        assert_eq!(res.cipher_suite, CIPHER_SUITE_IA_HYBRID_1);
        assert!(!res.aid.is_empty());
        assert_eq!(res.aid, res.said);
        assert!(res.cesr.mldsa65_signing.starts_with(CESR_MLDSA65_VERKEY));
        assert!(res.cesr.mlkem768_encap.starts_with(CESR_MLKEM768_ENCAP));
    }
}