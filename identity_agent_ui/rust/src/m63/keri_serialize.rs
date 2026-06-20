//! keri 1.1.17-compatible icp JSON serialization (SerderKERI makify).

use regex::Regex;
use serde::Serialize;

const KERI_VERSION_MAJOR: u8 = 1;
const KERI_VERSION_MINOR: u8 = 0;
pub(crate) const SAID_DUMMY_LEN: usize = 44;

#[derive(Serialize)]
pub(crate) struct AnchorSeal<'a> {
    pub ia: &'a str,
    pub ka: &'a [String],
}

#[derive(Serialize)]
pub(crate) struct IcpWire<'a> {
    pub v: String,
    pub t: &'a str,
    pub d: &'a str,
    pub i: &'a str,
    pub s: &'a str,
    pub kt: &'a str,
    pub k: &'a [String],
    pub nt: &'a str,
    pub n: &'a [String],
    pub bt: &'a str,
    pub b: &'a [serde_json::Value],
    pub c: &'a [serde_json::Value],
    pub a: &'a [AnchorSeal<'a>],
}

pub(crate) fn versify(size: usize) -> String {
    format!(
        "KERI{:x}{:x}JSON{:06x}_",
        KERI_VERSION_MAJOR, KERI_VERSION_MINOR, size
    )
}

fn patch_version_size(raw: &mut Vec<u8>) -> Result<(), String> {
    let re = Regex::new(r"KERI[0-9a-f][0-9a-f]JSON[0-9a-f]{6}_")
        .map_err(|e| format!("regex: {e}"))?;
    let text = std::str::from_utf8(raw).map_err(|e| format!("utf8: {e}"))?;
    let m = re
        .find(text)
        .ok_or_else(|| "keri version string not found".to_string())?;
    let vs = versify(raw.len());
    if vs.len() != m.len() {
        return Err(format!("version length mismatch: {} vs {}", vs.len(), m.len()));
    }
    let (start, end) = (m.start(), m.end());
    raw[start..end].copy_from_slice(vs.as_bytes());
    Ok(())
}

pub(crate) fn serialize_icp_wire(w: &IcpWire<'_>) -> Result<Vec<u8>, String> {
    let wire = IcpWire {
        v: versify(0),
        t: w.t,
        d: w.d,
        i: w.i,
        s: w.s,
        kt: w.kt,
        k: w.k,
        nt: w.nt,
        n: w.n,
        bt: w.bt,
        b: w.b,
        c: w.c,
        a: w.a,
    };
    let mut raw = serde_json::to_vec(&wire).map_err(|e| format!("marshal: {e}"))?;
    patch_version_size(&mut raw)?;
    Ok(raw)
}

/// Returns (raw bytes, said/prefix digest) after keri 1.1.17 SerderKERI makify.
pub(crate) fn makify_icp_wire<'a>(w: &IcpWire<'a>, dummy: &str) -> Result<(Vec<u8>, String), String> {
    let dummied = IcpWire {
        v: versify(0),
        t: w.t,
        d: dummy,
        i: dummy,
        s: w.s,
        kt: w.kt,
        k: w.k,
        nt: w.nt,
        n: w.n,
        bt: w.bt,
        b: w.b,
        c: w.c,
        a: w.a,
    };
    let raw = serialize_icp_wire(&dummied)?;
    let digest = super::cesr::blake3_qb64(&raw)?;

    let final_wire = IcpWire {
        v: versify(0),
        t: w.t,
        d: &digest,
        i: &digest,
        s: w.s,
        kt: w.kt,
        k: w.k,
        nt: w.nt,
        n: w.n,
        bt: w.bt,
        b: w.b,
        c: w.c,
        a: w.a,
    };
    let raw = serialize_icp_wire(&final_wire)?;
    Ok((raw, digest))
}