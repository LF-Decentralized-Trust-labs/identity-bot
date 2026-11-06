// The Secure Enclave, reached the way it can actually be reached from a helper.
//
// A Secure Enclave key is never stored in the enclave. The enclave wraps it and
// hands back a blob that only that one chip can unwrap — and asking the keychain
// to hold that blob is what needs an entitlement, a provisioning profile, and an
// app-like bundle to embed the profile in. A bare helper has none of those and
// cannot be given them, because the system finds a profile only inside the
// bundle of the binary claiming it.
//
// So this holds the blob itself. Same enclave, same wrapping, and the private
// half still never exists outside the chip — without the keychain, and therefore
// without the apparatus the keychain requires. Measured: a bare unsigned
// executable with no entitlements creates a key, and a separate process restores
// it and signs with it.
//
// WHAT IS GIVEN UP, stated because the rest of this reads like nothing is. A
// keychain item carries a per-application access control list, so a different
// binary running as the same person is prompted or refused. A file at 0600 has no
// such gate: anything running as that person can read it and ask the enclave to
// sign. The key cannot be COPIED — it is useless on any other processor — but its
// USE can be borrowed locally. What changed versus the keychain is access
// control, not confidentiality.
//
// Accepted deliberately. The keychain path never worked here at all, so nothing
// real was given up, and the alternative — requiring a person's presence for
// each signature — is not available to a machine that signs every request. What
// governs a borrowed key is the authentication level a controller must reach for
// anything that matters, which is a separate mechanism and the right place for
// it.
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
// Asked once and remembered. This mints a real enclave key to measure one, and
// restore() consults it — so without memoising, a single signing request made
// three throwaway keys in the enclave. Nothing leaked, because CryptoKit does not
// persist them, but it is work the hardware should not be asked to repeat.
private var cachedBlobSize: Int32 = 0

@_cdecl("sep_blob_size")
public func sep_blob_size() -> Int32 {
    if cachedBlobSize > 0 { return cachedBlobSize }
    guard let k = try? SecureEnclave.P256.Signing.PrivateKey() else { return -1 }
    cachedBlobSize = Int32(k.dataRepresentation.count)
    return cachedBlobSize
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

// ---------------------------------------------------------------------------
// Wrapping the root seed.
//
// The signing key above cannot encrypt, so the seed is wrapped with a second kind
// of enclave key, one that does key agreement (ECDH on P-256). The shape is the
// standard hybrid one: a fresh software key agrees a secret with the enclave
// key, HKDF turns it into an AES-256 key, AES-GCM seals the seed.
//
// EVERY WRAP MAKES ITS OWN ENCLAVE KEY and puts that key's wrapped blob inside
// the output. There is no key file to keep beside the seed, nothing to lose
// separately from it, and no state to carry between wrap and unwrap: the seed
// file is self-contained and openable only by the chip that made it. The blob is
// the same kind of thing the signer holds — useless on any other processor.
//
// Layout of the output, all lengths fixed by the key type except the first:
//   [2 bytes big-endian: enclave blob length][enclave key blob]
//   [65 bytes: the ephemeral public key, X9.63][AES-GCM combined: nonce|ct|tag]
//
// NOT YET RUN: written against CryptoKit's documented API on a machine with no
// Swift toolchain. What proves it is `go test -tags sepblob` on a Mac, which
// wraps, restarts the process, and unwraps (see seedwrap_darwin_sep_test.go).
// ---------------------------------------------------------------------------

private let seedWrapInfo = Data("identity-agent seed wrap v1 (se-ecdh-p256-aes256gcm)".utf8)

// Measured once, for the same reason sep_blob_size is: restoring a key from a
// blob of the wrong length TRAPS inside CryptoKit rather than throwing, so the
// length must be judged before the call.
private var cachedAgreementBlobSize: Int32 = 0

@_cdecl("sepw_blob_size")
public func sepw_blob_size() -> Int32 {
    if cachedAgreementBlobSize > 0 { return cachedAgreementBlobSize }
    guard let k = try? SecureEnclave.P256.KeyAgreement.PrivateKey() else { return -1 }
    cachedAgreementBlobSize = Int32(k.dataRepresentation.count)
    return cachedAgreementBlobSize
}

private func wrapKey(secret: SharedSecret, ephemeral: Data, enclave: Data) -> SymmetricKey {
    // Both public keys go into the derivation, so the key is bound to this exact
    // pair and a ciphertext cannot be replayed against another enclave key.
    return secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(),
                                          sharedInfo: seedWrapInfo + ephemeral + enclave,
                                          outputByteCount: 32)
}

@_cdecl("sepw_wrap")
public func sepw_wrap(_ plain: UnsafePointer<UInt8>, _ plen: Int,
                      _ out: UnsafeMutablePointer<UInt8>, _ cap: Int,
                      _ n: UnsafeMutablePointer<Int>) -> Int32 {
    guard plen > 0 else { return -1 }
    guard let enclaveKey = try? SecureEnclave.P256.KeyAgreement.PrivateKey() else { return -1 }
    let blob = enclaveKey.dataRepresentation
    let ephemeral = P256.KeyAgreement.PrivateKey()
    let ephemeralPub = ephemeral.publicKey.x963Representation          // 65 bytes
    let enclavePub = enclaveKey.publicKey.x963Representation
    guard let secret = try? ephemeral.sharedSecretFromKeyAgreement(with: enclaveKey.publicKey) else { return -3 }
    let key = wrapKey(secret: secret, ephemeral: ephemeralPub, enclave: enclavePub)
    guard let box = try? AES.GCM.seal(Data(bytes: plain, count: plen), using: key),
          let combined = box.combined else { return -3 }

    var result = Data()
    result.append(UInt8((blob.count >> 8) & 0xff))
    result.append(UInt8(blob.count & 0xff))
    result.append(blob)
    result.append(ephemeralPub)
    result.append(combined)
    guard result.count <= cap else { return -2 }
    result.copyBytes(to: out, count: result.count)
    n.pointee = result.count
    return 0
}

@_cdecl("sepw_unwrap")
public func sepw_unwrap(_ blob: UnsafePointer<UInt8>, _ blen: Int,
                        _ out: UnsafeMutablePointer<UInt8>, _ cap: Int,
                        _ n: UnsafeMutablePointer<Int>) -> Int32 {
    guard blen > 2 else { return -1 }
    let all = Data(bytes: blob, count: blen)
    let klen = (Int(all[all.startIndex]) << 8) | Int(all[all.startIndex + 1])
    // Judged before restore, because restore traps on a wrong length.
    guard klen > 0, klen == Int(sepw_blob_size()), blen > 2 + klen + 65 else { return -1 }
    let keyBlob = all.subdata(in: (all.startIndex + 2)..<(all.startIndex + 2 + klen))
    let ephemeralPub = all.subdata(in: (all.startIndex + 2 + klen)..<(all.startIndex + 2 + klen + 65))
    let combined = all.subdata(in: (all.startIndex + 2 + klen + 65)..<all.endIndex)

    guard let enclaveKey = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyBlob),
          let peer = try? P256.KeyAgreement.PublicKey(x963Representation: ephemeralPub),
          let secret = try? enclaveKey.sharedSecretFromKeyAgreement(with: peer) else { return -1 }
    let key = wrapKey(secret: secret, ephemeral: ephemeralPub,
                      enclave: enclaveKey.publicKey.x963Representation)
    guard let box = try? AES.GCM.SealedBox(combined: combined),
          let plain = try? AES.GCM.open(box, using: key) else { return -3 }
    guard plain.count <= cap else { return -2 }
    plain.copyBytes(to: out, count: plain.count)
    n.pointee = plain.count
    return 0
}
