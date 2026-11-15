import CryptoKit
import DeviceCheck
import Foundation
import Security

#if os(iOS)
import Flutter
#else
import FlutterMacOS
#endif

/// The Apple side of the hardware key (ADR-072 section 4, Amendment 3), for iOS and
/// macOS: an App Attest key. The device gives such a key only as an identifier and
/// signs only assertions, so
///
///  - `attestNewKey` makes a new key for the ask and returns the attestation object
///    for `SHA-256(challenge)` (the Dart side reads the public point from it and
///    hands it back through `keepPoint`);
///  - `signStatement` and `signCall` are assertions over the SHA-256 of the sign-in
///    statement and of each call's proof text. A call's proof is therefore an
///    assertion, which the back end tells from a plain 64-byte signature by its length.
///
/// What the Identity Agent checks of the evidence (Apple's pinned root, the nonce, the
/// owner's "<team id>.<bundle id>") is its to decide.
///
/// NOT COMPILED OR RUN: no Mac or device was available when this was written. App
/// Attest does not run in a simulator.
public class LoginFlutterPlugin: NSObject, FlutterPlugin {
    private static let service = "org.identityagent.login_flutter"

    public static func register(with registrar: FlutterPluginRegistrar) {
        #if os(iOS)
        let messenger = registrar.messenger()
        #else
        let messenger = registrar.messenger
        #endif
        let channel = FlutterMethodChannel(name: "org.identityagent.login_flutter/hardware_key", binaryMessenger: messenger)
        registrar.addMethodCallDelegate(LoginFlutterPlugin(), channel: channel)
    }

    // The key identifier and the public point are kept in the keychain under the label.
    private func keep(_ account: String, _ data: Data) {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: Self.service, kSecAttrAccount as String: account]
        SecItemDelete(q as CFDictionary)
        var add = q
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(add as CFDictionary, nil)
    }

    private func read(_ account: String) -> Data? {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: Self.service, kSecAttrAccount as String: account, kSecReturnData as String: true]
        var out: CFTypeRef?
        return SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess ? out as? Data : nil
    }

    private func forget(_ account: String) {
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: Self.service, kSecAttrAccount as String: account] as CFDictionary)
    }

    private func fail(_ result: @escaping FlutterResult, _ e: Error?) {
        result(FlutterError(code: "hardware", message: e?.localizedDescription ?? "App Attest failed", details: nil))
    }

    private func assert(_ label: String, _ hash: Data, _ result: @escaping FlutterResult) {
        guard let id = read(label + ".keyid").flatMap({ String(data: $0, encoding: .utf8) }) else {
            return result(FlutterError(code: "no_key", message: "no key named \(label): sign in again", details: nil))
        }
        DCAppAttestService.shared.generateAssertion(id, clientDataHash: hash) { a, e in
            if let a = a { result(FlutterStandardTypedData(bytes: a)) } else { self.fail(result, e) }
        }
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let args = call.arguments as? [String: Any], let label = args["label"] as? String else {
            return result(FlutterError(code: "bad_args", message: "no label", details: nil))
        }
        func bytes(_ k: String) -> Data? { (args[k] as? FlutterStandardTypedData)?.data }
        switch call.method {
        case "publicPoint":
            result(read(label + ".point").map { FlutterStandardTypedData(bytes: $0) })
        case "keepPoint":
            guard let p = bytes("point") else { return result(FlutterError(code: "bad_args", message: "no point", details: nil)) }
            keep(label + ".point", p)
            result(nil)
        case "attestNewKey":
            guard let challenge = bytes("challenge") else { return result(FlutterError(code: "bad_args", message: "no challenge", details: nil)) }
            let svc = DCAppAttestService.shared
            guard svc.isSupported else {
                return result(FlutterError(code: "unsupported", message: "App Attest is not available on this device (it does not run in a simulator)", details: nil))
            }
            svc.generateKey { id, e in
                guard let id = id else { return self.fail(result, e) }
                svc.attestKey(id, clientDataHash: Data(SHA256.hash(data: challenge))) { obj, e in
                    guard let obj = obj else { return self.fail(result, e) }
                    self.forget(label + ".point")
                    self.keep(label + ".keyid", Data(id.utf8))
                    result(FlutterStandardTypedData(bytes: obj))
                }
            }
        case "signCall":
            guard let m = bytes("message") else { return result(FlutterError(code: "bad_args", message: "no message", details: nil)) }
            assert(label, Data(SHA256.hash(data: m)), result)
        case "signStatement":
            guard let d = bytes("digest"), d.count == 32 else { return result(FlutterError(code: "bad_args", message: "no digest", details: nil)) }
            assert(label, d, result)
        default:
            result(FlutterMethodNotImplemented)
        }
    }
}
