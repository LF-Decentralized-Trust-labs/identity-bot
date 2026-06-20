// C3 golden-vector prep — synthetic seed=0 (keri 1.1.17 pin).
pub const EXPECTED_AID: &str = "EFdJwgqiFO90lTvDRp-oH2nubRky5N9L9ag8oOvsOL9R";
pub const EXPECTED_SAID: &str = "EFdJwgqiFO90lTvDRp-oH2nubRky5N9L9ag8oOvsOL9R";
pub const EXPECTED_RAW_B64_LEN: usize = 6160;

#[cfg(test)]
pub fn load_pinned_raw_b64() -> Option<String> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../identity-agent-core/iacrypto/golden_vectors.json"
    );
    let data = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&data).ok()?;
    v["hybrid_inception"]["raw_bytes_b64"]
        .as_str()
        .map(str::to_string)
}