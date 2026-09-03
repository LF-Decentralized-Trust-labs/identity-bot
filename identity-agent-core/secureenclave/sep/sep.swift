// The Secure Enclave, reached the way it can actually be reached from a helper.
//
// A Secure Enclave key is never stored in the enclave. The enclave wraps it and
// hands back a blob that only that one chip can unwrap — and asking the keychain
// to hold that blob is what needs an entitlement, a provisioning profile, and an
// app-like bundle to embed the profile in. A bare helper has none of those and
// cannot be given them, because the system finds a profile only inside the
// bundle of the binary claiming it.
//
// So this holds the blob itself. Same enclave, same wrapping, same guarantee
// that the private half never exists outside the chip — without the keychain,
// and therefore without any of the apparatus the keychain requires. Measured: a
// bare unsigned executable with no entitlements creates a key, and a separate
// process restores it and signs with it.
//
// CryptoKit rather than Security.framework because only CryptoKit exposes the
// wrapped blob. Security.framework can create the key and then only offer to
// put it in the keychain.
import Foundation
import CryptoKit

@_cdecl("sep_available")
public func sep_available() -> Int32 {
    return SecureEnclave.isAvailable ? 1 : 0
}

// sep_blob_size reports how long a freshly wrapped key is, so the caller can
// refuse a stored blob of any other length before handing it back.
//
// That check is not fastidiousness. CryptoKit's restore TRAPS on a blob of the
// wrong size — a `try!` inside SEP_P256.swift — so a truncated or corrupted file
// takes the whole process down instead of returning an error. The length has to
// be judged before the call, because after it there is nothing to judge.
@_cdecl("sep_blob_size")
public func sep_blob_size() -> Int32 {
    guard let k = try? SecureEnclave.P256.Signing.PrivateKey() else { return -1 }
    return Int32(k.dataRepresentation.count)
}

@_cdecl("sep_create")
public func sep_create(_ out: UnsafeMutablePointer<UInt8>, _ cap: Int, _ n: UnsafeMutablePointer<Int>) -> Int32 {
    guard let key = try? SecureEnclave.P256.Signing.PrivateKey() else { return -1 }
    let d = key.dataRepresentation
    guard d.count <= cap else { return -2 }
    d.copyBytes(to: out, count: d.count)
    n.pointee = d.count
    return 0
}

// restore is deliberately the only place the blob is turned back into a key, so
// the size guard exists once rather than at each call site.
private func restore(_ blob: UnsafePointer<UInt8>, _ len: Int) -> SecureEnclave.P256.Signing.PrivateKey? {
    guard len > 0, len == Int(sep_blob_size()) else { return nil }
    let d = Data(bytes: blob, count: len)
    return try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: d)
}

// sep_public returns the key in X9.63 uncompressed form — 0x04, then X, then Y.
// That is what the Security.framework signer returned, so everything downstream
// keeps working, and CompressP256 turns it into the 33 bytes CESR carries.
@_cdecl("sep_public")
public func sep_public(_ blob: UnsafePointer<UInt8>, _ blen: Int,
                       _ out: UnsafeMutablePointer<UInt8>, _ cap: Int,
                       _ n: UnsafeMutablePointer<Int>) -> Int32 {
    guard let key = restore(blob, blen) else { return -1 }
    let raw = key.publicKey.rawRepresentation          // 64 bytes: X || Y
    guard raw.count + 1 <= cap else { return -2 }
    out[0] = 0x04
    raw.copyBytes(to: out.advanced(by: 1), count: raw.count)
    n.pointee = raw.count + 1
    return 0
}

// sep_sign returns the signature as raw r||s, never DER.
//
// CESR's secp256r1 signature code carries 64 raw bytes, and CryptoKit offers
// exactly that as rawRepresentation. The Security.framework path returns DER and
// would need unwrapping; this does not.
@_cdecl("sep_sign")
public func sep_sign(_ blob: UnsafePointer<UInt8>, _ blen: Int,
                     _ msg: UnsafePointer<UInt8>, _ mlen: Int,
                     _ out: UnsafeMutablePointer<UInt8>, _ cap: Int,
                     _ n: UnsafeMutablePointer<Int>) -> Int32 {
    guard let key = restore(blob, blen) else { return -1 }
    guard let sig = try? key.signature(for: Data(bytes: msg, count: mlen)) else { return -3 }
    let raw = sig.rawRepresentation                    // 64 bytes: r || s
    guard raw.count <= cap else { return -2 }
    raw.copyBytes(to: out, count: raw.count)
    n.pointee = raw.count
    return 0
}
