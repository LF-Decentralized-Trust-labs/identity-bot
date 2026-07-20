import Foundation
import CryptoKit
import Security
#if os(iOS)
import Flutter
#else
import FlutterMacOS
#endif

/// ADR-027 Layer 1: wraps/unwraps the BIP39 mnemonic using a P-256 key
/// generated inside the real Secure Enclave. The wrapping key itself never
/// leaves the enclave — only ECDH results and AES-GCM ciphertext cross into
/// application memory. Shared verbatim between the iOS and macOS Runner
/// targets (Security.framework/CryptoKit are identical on both).
///
/// Deliberately has NO per-use OS authentication requirement (no
/// `.biometryCurrentSet`, no access-control flags at all beyond the base
/// accessibility class). Per ADR-027: AuthProvider is the sole authorization
/// gate for whether to unwrap at all — an OS-forced biometric prompt on this
/// key would be a second, uncoordinated gate sitting beside AuthProvider
/// rather than inside it.
enum HardwareKeyWrapper {
    private static let keyTag = "org.identityagent.hwwrap.p256".data(using: .utf8)!

    enum WrapError: Error {
        case unavailable
        case keyGenFailed(String)
        case exchangeFailed(String)
        case malformedPayload
    }

    static func isAvailable() -> Bool {
        return SecureEnclave.isAvailable
    }

    private static func getOrCreateWrappingKey() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess, let key = item {
            // swiftlint:disable:next force_cast
            return (key as! SecKey)
        }

        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [],
            nil) else {
            throw WrapError.keyGenFailed("SecAccessControlCreateWithFlags returned nil")
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: keyTag,
                kSecAttrAccessControl as String: access,
            ],
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw WrapError.keyGenFailed(error?.takeRetainedValue().localizedDescription ?? "unknown")
        }
        return privateKey
    }

    /// Returns `ephemeralPublicKey.nonce.ciphertext.tag` (each base64).
    static func wrap(plaintext: String) throws -> String {
        guard isAvailable() else { throw WrapError.unavailable }
        let wrappingKey = try getOrCreateWrappingKey()
        guard let wrappingPublicKey = SecKeyCopyPublicKey(wrappingKey) else {
            throw WrapError.keyGenFailed("no public key for wrapping key")
        }

        let ephemeralAttrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ]
        var genError: Unmanaged<CFError>?
        guard let ephemeralPrivate = SecKeyCreateRandomKey(ephemeralAttrs as CFDictionary, &genError) else {
            throw WrapError.keyGenFailed(genError?.takeRetainedValue().localizedDescription ?? "unknown")
        }
        guard let ephemeralPublic = SecKeyCopyPublicKey(ephemeralPrivate) else {
            throw WrapError.keyGenFailed("no ephemeral public key")
        }
        var exportError: Unmanaged<CFError>?
        guard let ephemeralPublicData = SecKeyCopyExternalRepresentation(ephemeralPublic, &exportError) as Data? else {
            throw WrapError.keyGenFailed(exportError?.takeRetainedValue().localizedDescription ?? "unknown")
        }

        var exchangeError: Unmanaged<CFError>?
        guard let sharedSecretData = SecKeyCopyKeyExchangeResult(
            ephemeralPrivate, .ecdhKeyExchangeStandard, wrappingPublicKey,
            [SecKeyKeyExchangeParameter.requestedSize: 32] as CFDictionary,
            &exchangeError) as Data? else {
            throw WrapError.exchangeFailed(exchangeError?.takeRetainedValue().localizedDescription ?? "unknown")
        }

        let symmetricKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecretData),
            info: "identity-agent.hwwrap.v1".data(using: .utf8)!,
            outputByteCount: 32)

        let sealed = try AES.GCM.seal(plaintext.data(using: .utf8)!, using: symmetricKey)

        let parts = [
            ephemeralPublicData.base64EncodedString(),
            Data(sealed.nonce).base64EncodedString(),
            sealed.ciphertext.base64EncodedString(),
            sealed.tag.base64EncodedString(),
        ]
        return parts.joined(separator: ".")
    }

    static func unwrap(payload: String) throws -> String {
        guard isAvailable() else { throw WrapError.unavailable }
        let parts = payload.split(separator: ".").map(String.init)
        guard parts.count == 4,
              let ephemeralPublicData = Data(base64Encoded: parts[0]),
              let nonceData = Data(base64Encoded: parts[1]),
              let ciphertextData = Data(base64Encoded: parts[2]),
              let tagData = Data(base64Encoded: parts[3]) else {
            throw WrapError.malformedPayload
        }

        let wrappingKey = try getOrCreateWrappingKey()

        let ephemeralKeyAttrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        var importError: Unmanaged<CFError>?
        guard let ephemeralPublicKey = SecKeyCreateWithData(
            ephemeralPublicData as CFData, ephemeralKeyAttrs as CFDictionary, &importError) else {
            throw WrapError.malformedPayload
        }

        var exchangeError: Unmanaged<CFError>?
        guard let sharedSecretData = SecKeyCopyKeyExchangeResult(
            wrappingKey, .ecdhKeyExchangeStandard, ephemeralPublicKey,
            [SecKeyKeyExchangeParameter.requestedSize: 32] as CFDictionary,
            &exchangeError) as Data? else {
            throw WrapError.exchangeFailed(exchangeError?.takeRetainedValue().localizedDescription ?? "unknown")
        }

        let symmetricKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecretData),
            info: "identity-agent.hwwrap.v1".data(using: .utf8)!,
            outputByteCount: 32)

        let nonce = try AES.GCM.Nonce(data: nonceData)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertextData, tag: tagData)
        let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey)
        guard let result = String(data: plaintext, encoding: .utf8) else {
            throw WrapError.malformedPayload
        }
        return result
    }

    /// Registers the `com.identityagent/hwwrap` method channel handler.
    /// Call from AppDelegate (iOS) / MainFlutterWindow (macOS) at launch.
    static func register(messenger: FlutterBinaryMessenger) {
        let channel = FlutterMethodChannel(name: "com.identityagent/hwwrap", binaryMessenger: messenger)
        channel.setMethodCallHandler { call, result in
            switch call.method {
            case "isAvailable":
                result(isAvailable())
            case "wrap":
                guard let args = call.arguments as? [String: Any], let plaintext = args["plaintext"] as? String else {
                    result(FlutterError(code: "BAD_ARGS", message: "missing plaintext", details: nil))
                    return
                }
                do {
                    result(try wrap(plaintext: plaintext))
                } catch {
                    result(FlutterError(code: "WRAP_FAILED", message: "\(error)", details: nil))
                }
            case "unwrap":
                guard let args = call.arguments as? [String: Any], let payload = args["payload"] as? String else {
                    result(FlutterError(code: "BAD_ARGS", message: "missing payload", details: nil))
                    return
                }
                do {
                    result(try unwrap(payload: payload))
                } catch {
                    result(FlutterError(code: "UNWRAP_FAILED", message: "\(error)", details: nil))
                }
            default:
                result(FlutterMethodNotImplemented)
            }
        }
    }
}
