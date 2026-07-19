import 'dart:io' show Platform;
import 'package:flutter/foundation.dart' show kIsWeb, debugPrint;
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import '../src/rust/frb_generated.dart';
import '../src/rust/api/keri_bridge.dart' as rust_api;

class BridgeInteractResult {
  final String aid;
  final String said;
  final int sequenceNumber;
  final String kelEntry;
  final String rawBytesB64;

  BridgeInteractResult({
    required this.aid,
    required this.said,
    required this.sequenceNumber,
    required this.kelEntry,
    required this.rawBytesB64,
  });
}

class BridgeInceptionResult {
  final String aid;
  final String publicKey;
  final String kel;

  BridgeInceptionResult({
    required this.aid,
    required this.publicKey,
    required this.kel,
  });
}

class BridgeRotationResult {
  final String aid;
  final String newPublicKey;
  final String kel;

  BridgeRotationResult({
    required this.aid,
    required this.newPublicKey,
    required this.kel,
  });
}

class BridgeSignatureResult {
  final String signature;
  final String publicKey;

  BridgeSignatureResult({
    required this.signature,
    required this.publicKey,
  });
}

bool get _isMobilePlatform {
  if (kIsWeb) return false;
  return Platform.isAndroid || Platform.isIOS;
}

class KeriBridge {
  static bool _rustInitialized = false;
  static bool _rustAvailable = false;
  static String? _loadError;

  static bool get isAvailable => _rustAvailable;
  static String? get loadError => _loadError;

  static Future<void> ensureInitialized() async {
    if (_rustInitialized) return;
    if (!_isMobilePlatform) return;
    try {
      if (Platform.isIOS) {
        // build-ios.sh links libidentity_agent_keri.a directly into the
        // Runner binary (-lidentity_agent_keri) rather than shipping a
        // separate dynamic framework, so the FFI symbols are already
        // present in this process. flutter_rust_bridge's default iOS
        // loader assumes a dynamic <crate>.framework bundle and can never
        // find one here — a hardened-runtime dlopen of a relative path
        // is also disallowed on-device regardless. ExternalLibrary.process()
        // is FRB's documented mechanism for exactly this (statically
        // linked) case.
        await RustLib.init(
          externalLibrary: ExternalLibrary.process(iKnowHowToUseIt: true),
        );
      } else {
        await RustLib.init();
      }
      _rustAvailable = true;
      _rustInitialized = true;
      debugPrint('[KeriBridge] Rust library loaded successfully');
    } catch (e) {
      _rustInitialized = true;
      _rustAvailable = false;
      _loadError = e.toString();
      debugPrint('[KeriBridge] Rust library NOT available: $e');
    }
  }

  void _ensureBridgeReady(String operation) {
    if (!_isMobilePlatform) {
      throw UnsupportedError(
        'KeriBridge.$operation is only available on mobile (iOS/Android). '
        'Desktop uses the Python KERI driver via the Go backend.',
      );
    }
    if (!_rustAvailable) {
      final reason = _loadError ?? 'unknown error';
      throw StateError(
        'KERI_BRIDGE_NOT_AVAILABLE: The native KERI engine could not be '
        'loaded on this device ($reason). This is required for local '
        'identity creation. The app was built without a working Rust '
        'KERI library — please rebuild with flutter_rust_bridge_codegen.',
      );
    }
  }

  Future<BridgeInceptionResult> inceptAid({
    required String name,
    required String code,
  }) async {
    await ensureInitialized();
    _ensureBridgeReady('inceptAid');
    debugPrint('[KeriBridge] Calling rust_api.inceptAid (sync FFI)...');
    final result = rust_api.inceptAid(name: name, code: code);
    debugPrint('[KeriBridge] rust_api.inceptAid returned, AID: ${result.aid}');
    return BridgeInceptionResult(
      aid: result.aid,
      publicKey: result.publicKey,
      kel: result.kel,
    );
  }

  Future<BridgeRotationResult> rotateAid({
    required String name,
  }) async {
    await ensureInitialized();
    _ensureBridgeReady('rotateAid');
    final result = rust_api.rotateAid(name: name);
    return BridgeRotationResult(
      aid: result.aid,
      newPublicKey: result.newPublicKey,
      kel: result.kel,
    );
  }

  Future<BridgeSignatureResult> signPayload({
    required String name,
    required List<int> data,
  }) async {
    await ensureInitialized();
    _ensureBridgeReady('signPayload');
    final result = rust_api.signPayload(name: name, data: data);
    return BridgeSignatureResult(
      signature: result.signature,
      publicKey: result.publicKey,
    );
  }

  Future<String> getCurrentKel({
    required String name,
  }) async {
    await ensureInitialized();
    _ensureBridgeReady('getCurrentKel');
    return rust_api.getCurrentKel(name: name);
  }

  Future<bool> verifySignature({
    required List<int> data,
    required String signature,
    required String publicKey,
  }) async {
    await ensureInitialized();
    _ensureBridgeReady('verifySignature');
    return rust_api.verifySignature(
      data: data,
      signature: signature,
      publicKey: publicKey,
    );
  }

  Future<BridgeInteractResult> interactAid({
    required String name,
    String sealDataJson = '[]',
  }) async {
    await ensureInitialized();
    _ensureBridgeReady('interactAid');
    final result = rust_api.interactAid(name: name, sealDataJson: sealDataJson);
    return BridgeInteractResult(
      aid: result.aid,
      said: result.said,
      // i64 in Rust; FRB v2 maps i64 → int on native. Cast defensively.
      sequenceNumber: result.sequenceNumber is int
          ? result.sequenceNumber as int
          : (result.sequenceNumber as dynamic).toInt() as int,
      kelEntry: result.kelEntry,
      rawBytesB64: result.rawBytesB64,
    );
  }

  Future<String> cesrEncode({required String rawSigB64}) async {
    await ensureInitialized();
    _ensureBridgeReady('cesrEncode');
    return rust_api.cesrEncode(rawSigB64: rawSigB64);
  }
}
