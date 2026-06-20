//! Provisional IA-HYBRID-1 CESR codes (C3-pinned wire bytes in golden_vectors.json).

pub const CIPHER_SUITE_IA_HYBRID_1: &str = "IA-HYBRID-1";
pub const CESR_MLDSA65_VERKEY: &str = "1PDA";
pub const CESR_MLDSA65_SIG: &str = "1PDS";
pub const CESR_MLKEM768_ENCAP: &str = "1PKM";
pub const CESR_X25519_PUBKEY: &str = "1PXB";
pub const MLDSA65_VERKEY_BYTES: usize = 1952;
pub const MLDSA65_SIG_BYTES: usize = 3309;
pub const ED25519_SIG_BYTES: usize = 64;
pub const CTR_CONTROLLER_IDX_SIGS: &str = "-A";
pub const C2_MESSAGE: &str = "m63-c2-hybrid-signature-golden-vector";

pub fn c2_ed25519_seed() -> [u8; 32] {
    std::array::from_fn(|i| ((i + 0x21) % 256) as u8)
}

pub fn c2_mldsa_seed() -> [u8; 32] {
    *b"m63-c2-hybrid-signature-golden!!"
}

const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn int_to_b64(i: usize, length: usize) -> String {
    let mut n = i;
    let mut d: Vec<u8> = Vec::new();
    while length > 0 && (d.len() < length || n > 0) {
        d.insert(0, B64_CHARS[n % 64]);
        n /= 64;
    }
    while d.len() < length {
        d.insert(0, b'A');
    }
    String::from_utf8(d).unwrap_or_default()
}

pub fn b64_to_int(s: &str) -> usize {
    s.bytes().fold(0usize, |n, c| {
        let idx = B64_CHARS.iter().position(|&x| x == c).unwrap_or(0);
        n * 64 + idx
    })
}
pub const MLKEM768_ENCAP_BYTES: usize = 1184;
pub const X25519_PUBKEY_BYTES: usize = 32;
pub const ED25519_PUBKEY_BYTES: usize = 32;

/// Fixed-size CESR Matter encoding (keri 1.1.17 Matter._infil).
pub fn matter_fixed_qb64(code: &str, raw: &[u8]) -> Result<String, String> {
    if code.is_empty() {
        return Err("matter code required".into());
    }
    let ps = (3 - (raw.len() % 3)) % 3;
    let cs = code.len();
    let mut padded = vec![0u8; ps + raw.len()];
    padded[ps..].copy_from_slice(raw);
    let b64 = base64::encode_config(&padded, base64::URL_SAFE_NO_PAD);
    if cs % 4 > b64.len() {
        return Err(format!("invalid matter encoding for code {code}"));
    }
    Ok(format!("{}{}", code, &b64[cs % 4..]))
}

pub fn encode_large_fixed(code: &str, raw: &[u8], expected_len: usize) -> Result<String, String> {
    if code.len() != 4 {
        return Err(format!("provisional CESR code must be 4 chars, got {code:?}"));
    }
    if expected_len > 0 && raw.len() != expected_len {
        return Err(format!(
            "expected {expected_len} raw bytes for {code}, got {}",
            raw.len()
        ));
    }
    Ok(format!(
        "{}{}",
        code,
        base64::encode_config(raw, base64::URL_SAFE_NO_PAD)
    ))
}

pub fn ed25519_verfer_qb64(raw32: &[u8]) -> Result<String, String> {
    if raw32.len() != ED25519_PUBKEY_BYTES {
        return Err("Ed25519 public key must be 32 bytes".into());
    }
    matter_fixed_qb64("D", raw32)
}

pub fn blake3_qb64(data: &[u8]) -> Result<String, String> {
    let sum = blake3::hash(data);
    matter_fixed_qb64("E", sum.as_bytes())
}